import { describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

import { wrapAesKw } from '../../../src/algorithms/jwe/aes-kw.ts';
import { GCMKW_IV_BYTES } from '../../../src/algorithms/jwe/aes-gcm-kw.ts';
import { derivePbes2Key, MIN_ITERATIONS } from '../../../src/algorithms/jwe/pbes2.ts';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { encodeBase64url } from '../../../src/internal/encoding/base64url.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { decryptParsed, type TrustedRecipient } from '../../../src/jwe/decrypt.ts';
import { encryptJson } from '../../../src/jwe/encrypt.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
import { parseJsonJwe } from '../../../src/jwe/parse.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function key(
  jwk: Record<string, unknown>,
  algorithm: string,
  operation: 'wrapKey' | 'unwrapKey' | 'deriveKey',
): UsableKey {
  const boundOperation = algorithm.startsWith('ECDH-ES') ? 'deriveKey' : operation;
  const result = importKey(object(jwk), {
    algorithm,
    operation: boundOperation,
    contentAlgorithms: algorithm === 'dir' ? ['A128GCM'] : ['A128GCM', 'A128CBC-HS256'],
  });
  if (!result.ok) {
    throw new Error(`import failed (${algorithm}/${operation}): ${result.reason}`);
  }
  return result.key;
}

/** Records every identity it is asked for, so nonce spaces can be inspected. */
function trackingAllocator(): NonceAllocator & { readonly identities: string[] } {
  const counters = new Map<string, bigint>();
  const writers = new Map<string, number>();
  const identities: string[] = [];
  return {
    identities,
    reserve(id: string): Promise<NonceResult> {
      identities.push(id);
      // Each key identity gets its own writer id, so two spaces at the same
      // counter still yield distinct nonces, as a real deployment's
      // provisioned writers would.
      let writer = writers.get(id);
      if (writer === undefined) {
        writer = writers.size + 1;
        writers.set(id, writer);
      }
      const next = (counters.get(id) ?? 0n) + 1n;
      counters.set(id, next);
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(writer, next)! } });
    },
  };
}

const PLAINTEXT = new TextEncoder().encode('{"sub":"alice"}');

/**
 * A wrapping pair with the provisioned nonce identity the GCM modes require.
 *
 * Deployments allocate this; the default names each generated fixture so two
 * fixtures never share a nonce space.
 */
let fixtureCount = 0;

function gcmKwPair(algorithm: string, bytes: number, keyIdentity = `fixture-${(fixtureCount += 1)}`) {
  const jwk = { kty: 'oct', k: randomBytes(bytes).toString('base64url') };
  return {
    keyIdentity,
    encryption: key(jwk, algorithm, 'wrapKey'),
    decryption: key(jwk, algorithm, 'unwrapKey'),
  };
}

async function decrypt(serialized: string, trusted: readonly TrustedRecipient[], algorithm: string, enc = 'A128GCM') {
  const parsedJson = parseJson(new TextEncoder().encode(serialized), LIMITS_V1);
  if (!parsedJson.ok) {
    throw new Error('bad serialization');
  }
  const parsed = parseJsonJwe(parsedJson.value, LIMITS_V1);
  if (!parsed.ok) {
    throw new Error(`parse failed: ${parsed.reason}`);
  }

  return decryptParsed(parsed.value, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', [algorithm], 'receive'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', [enc], 'receive'),
    recipients: trusted,
    principalId: trusted[0]!.principalId,
    limits: LIMITS_V1,
  });
}

describe('AES-GCM key wrapping end to end', () => {
  for (const [algorithm, bytes] of [
    ['A128GCMKW', 16],
    ['A192GCMKW', 24],
    ['A256GCMKW', 32],
  ] as const) {
    test(`${algorithm} round-trips`, async () => {
      const pair = gcmKwPair(algorithm, bytes);
      const encrypted = await encryptJson(PLAINTEXT, {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', [algorithm], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
        limits: LIMITS_V1,
        random: systemRandom,
        nonceAllocator: trackingAllocator(),
      });

      expect(encrypted.ok).toBe(true);
      if (!encrypted.ok) {
        return;
      }

      const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], algorithm);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.plaintext).toEqual(PLAINTEXT);
      }
    });
  }

  test('publishes the wrapping IV and tag in the header', async () => {
    // A recipient cannot unwrap without them, and they are distinct values from
    // the content IV and tag carried alongside.
    const pair = gcmKwPair('A256GCMKW', 32);
    const encrypted = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: trackingAllocator(),
    });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parsed = JSON.parse(encrypted.value);
    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));

    expect(typeof header.iv).toBe('string');
    expect(typeof header.tag).toBe('string');
    expect(Buffer.from(header.iv, 'base64url')).toHaveLength(GCMKW_IV_BYTES);
    expect(Buffer.from(header.tag, 'base64url')).toHaveLength(16);

    // The header values are the wrapping ones, not the content ones.
    expect(header.iv).not.toBe(parsed.iv);
    expect(header.tag).not.toBe(parsed.tag);
  });

  test('scopes the wrapping nonce to the actual wrapping key', async () => {
    // Only the wrapping key is long-lived here: the CEK is generated fresh for
    // this message, so its content nonce cannot repeat and needs no durable
    // reservation. The one reservation made must name the key rather than the
    // algorithm, or two different keys would share a counter.
    const pair = gcmKwPair('A256GCMKW', 32, 'wrapping-key-a');
    const allocator = trackingAllocator();

    await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator,
    });

    expect(allocator.identities).toEqual(['keywrap:wrapping-key-a']);
  });

  test('gives two keys sharing an algorithm two nonce spaces', async () => {
    // Naming the space by the algorithm would hand both keys one counter, and
    // the allocator could not enforce either key's own creation cap.
    const allocator = trackingAllocator();
    for (const identity of ['wrapping-key-a', 'wrapping-key-b']) {
      const pair = gcmKwPair('A256GCMKW', 32, identity);
      // oxlint-disable-next-line no-await-in-loop
      await encryptJson(PLAINTEXT, {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
        limits: LIMITS_V1,
        random: systemRandom,
        nonceAllocator: allocator,
      });
    }

    expect(allocator.identities).toEqual(['keywrap:wrapping-key-a', 'keywrap:wrapping-key-b']);
  });

  test('gives one key configured twice a single nonce space', async () => {
    // Two configuration entries for one physical key are aliases. Counting them
    // separately would issue the same nonce twice under that key, which is the
    // failure the allocator exists to prevent.
    const jwk = { kty: 'oct', k: randomBytes(32).toString('base64url') };
    const allocator = trackingAllocator();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      // oxlint-disable-next-line no-await-in-loop
      await encryptJson(PLAINTEXT, {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: [{ key: key(jwk, 'A256GCMKW', 'wrapKey'), keyIdentity: 'shared-key' }],
        limits: LIMITS_V1,
        random: systemRandom,
        nonceAllocator: allocator,
      });
    }

    expect(allocator.identities).toEqual(['keywrap:shared-key', 'keywrap:shared-key']);
  });

  test('refuses to wrap under GCM without a provisioned key identity', async () => {
    // The allocator cannot scope a space to a key it cannot name, so creation
    // stops rather than falling back to a label that aliases distinct keys.
    const pair = gcmKwPair('A256GCMKW', 32);
    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: trackingAllocator(),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('key_identity_required');
    }
  });

  test('refuses to create without an allocator for the wrapping nonce', async () => {
    const pair = gcmKwPair('A256GCMKW', 32);
    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      // CBC needs no content nonce, so any allocation demanded here is the
      // wrapping one.
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
      contentAlgorithm: 'A128CBC-HS256',
      recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('nonce_allocator_required');
    }
  });

  test('rejects a modified wrapping tag', async () => {
    const pair = gcmKwPair('A256GCMKW', 32);
    const encrypted = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: trackingAllocator(),
    });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parsed = JSON.parse(encrypted.value);
    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    const tag = Buffer.from(header.tag, 'base64url');
    tag[0] = tag[0]! ^ 0x01;
    header.tag = tag.toString('base64url');
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'a', key: pair.decryption }], 'A256GCMKW');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
    }
  });

  test('refuses a caller-supplied iv or tag header', async () => {
    // These are produced by key protection, so a caller cannot steer them.
    for (const name of ['iv', 'tag']) {
      const pair = gcmKwPair('A256GCMKW', 32);
      const result = await encryptJson(PLAINTEXT, {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
        limits: LIMITS_V1,
        random: systemRandom,
        nonceAllocator: trackingAllocator(),
        protectedHeader: { [name]: 'injected' },
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(`reserved_header_${name}`);
      }
    }
  });
});

describe('PBES2 is receive-only', () => {
  const PASSWORD = new TextEncoder().encode('correct horse battery staple');
  const SALT_INPUT = new Uint8Array(16).fill(3);

  /**
   * Builds a PBES2 object directly, since this library refuses to create one.
   * The CEK is wrapped under a KEK derived exactly as a sender would.
   */
  async function foreignObject(iterations = MIN_ITERATIONS, saltInput = SALT_INPUT) {
    const algorithm = 'PBES2-HS256+A128KW';
    const cek = new Uint8Array(randomBytes(16));

    const kek = await derivePbes2Key(algorithm, PASSWORD, saltInput, iterations);
    if (!kek.ok) {
      throw new Error('derive failed');
    }
    const wrapped = await wrapAesKw('A128KW', kek.value, cek);
    if (!wrapped.ok) {
      throw new Error('wrap failed');
    }

    const header = {
      alg: algorithm,
      enc: 'A128GCM',
      p2s: encodeBase64url(saltInput),
      p2c: iterations,
    };
    const protectedComponent = encodeBase64url(new TextEncoder().encode(JSON.stringify(header)));

    const iv = new Uint8Array(randomBytes(12));
    const handle = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(protectedComponent), tagLength: 128 },
        handle,
        PLAINTEXT,
      ),
    );

    return JSON.stringify({
      protected: protectedComponent,
      encrypted_key: encodeBase64url(wrapped.value),
      iv: encodeBase64url(iv),
      ciphertext: encodeBase64url(sealed.subarray(0, PLAINTEXT.length)),
      tag: encodeBase64url(sealed.subarray(PLAINTEXT.length)),
    });
  }

  function passwordKey() {
    // The password travels with the trusted binding, not in the object.
    const jwk = { kty: 'oct', k: encodeBase64url(new Uint8Array(16)) };
    return {
      principalId: 'alice',
      key: key(jwk, 'PBES2-HS256+A128KW', 'unwrapKey'),
      password: PASSWORD,
    };
  }

  test('refuses creation under a password-derived key', async () => {
    // A policy cannot even be built for creation, so the refusal is visible at
    // configuration rather than at the point of use.
    expect(() => AlgorithmPolicy.create('jwe_alg', ['PBES2-HS256+A128KW'], 'create')).toThrow();
  });

  test('accepts a received object with a configured password', async () => {
    const result = await decrypt(await foreignObject(), [passwordKey()], 'PBES2-HS256+A128KW');

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
      expect(result.principalId).toBe('alice');
    }
  });

  test('refuses when no password is configured', async () => {
    // The password comes from trusted configuration; nothing in the object can
    // supply it.
    const withoutPassword = { principalId: 'alice', key: passwordKey().key };

    const result = await decrypt(await foreignObject(), [withoutPassword], 'PBES2-HS256+A128KW');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
    }
  });

  test('refuses a wrong password with the ordinary authentication failure', async () => {
    const wrong = { principalId: 'alice', key: passwordKey().key, password: new TextEncoder().encode('guess') };

    const result = await decrypt(await foreignObject(), [wrong], 'PBES2-HS256+A128KW');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
      expect(result.reason).toBe('decryption_failed');
    }
  });

  test('rejects an iteration count below policy before deriving', async () => {
    // Built at a valid work factor and rewritten, since the derivation refuses
    // to produce an out-of-policy object in the first place.
    const parsed = JSON.parse(await foreignObject());
    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    header.p2c = 1000;
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [passwordKey()], 'PBES2-HS256+A128KW');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.stage).toBe('header');
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('iterations_below_minimum');
    }
  });

  test('rejects an iteration count above policy before deriving', async () => {
    // The header is rejected without the derivation running, so a hostile count
    // never costs this side the work it names.
    const serialized = await foreignObject();
    const parsed = JSON.parse(serialized);
    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    header.p2c = 100_000_000;
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [passwordKey()], 'PBES2-HS256+A128KW');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('iterations_above_maximum');
    }
  });

  test('rejects a salt input shorter than eight octets', async () => {
    const parsed = JSON.parse(await foreignObject());
    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    header.p2s = encodeBase64url(new Uint8Array(4));
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [passwordKey()], 'PBES2-HS256+A128KW');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('salt_too_short');
    }
  });

  test('rejects a non-integer iteration count', async () => {
    // A count written as `1e9` names a value far outside policy while looking
    // small, so the lexeme itself is checked.
    for (const lexeme of ['1e9', '100000.5', '-100000']) {
      const serialized = await foreignObject();
      const parsed = JSON.parse(serialized);
      const header = Buffer.from(parsed.protected, 'base64url').toString('utf8');
      const rewritten = header.replace(/"p2c":\d+/, `"p2c":${lexeme}`);
      parsed.protected = Buffer.from(rewritten).toString('base64url');

      const result = await decrypt(JSON.stringify(parsed), [passwordKey()], 'PBES2-HS256+A128KW');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('p2c_not_a_positive_integer');
      }
    }
  });

  test('rejects a missing salt or count', async () => {
    for (const member of ['p2s', 'p2c']) {
      const serialized = await foreignObject();
      const parsed = JSON.parse(serialized);
      const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
      delete header[member];
      parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

      const result = await decrypt(JSON.stringify(parsed), [passwordKey()], 'PBES2-HS256+A128KW');
      expect(result.ok).toBe(false);
    }
  });
});

/**
 * Builds an object whose plaintext was compressed before encryption, as a
 * producer with `zip` enabled would emit.
 */
async function compressedObject(zip = 'DEF') {
  const cek = new Uint8Array(randomBytes(16));
  const plaintext = new TextEncoder().encode('{"sub":"alice","padding":"aaaaaaaaaaaaaaaaaaaa"}');
  const compressed = new Uint8Array(deflateRawSync(plaintext));

  const header = { alg: 'dir', enc: 'A128GCM', zip };
  const protectedComponent = encodeBase64url(new TextEncoder().encode(JSON.stringify(header)));
  const iv = new Uint8Array(randomBytes(12));

  const handle = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(protectedComponent), tagLength: 128 },
      handle,
      compressed,
    ),
  );

  return {
    cek,
    serialized: JSON.stringify({
      protected: protectedComponent,
      iv: encodeBase64url(iv),
      ciphertext: encodeBase64url(sealed.subarray(0, compressed.length)),
      tag: encodeBase64url(sealed.subarray(compressed.length)),
    }),
  };
}

describe('compression is disabled', () => {
  test('rejects a received object naming zip rather than returning compressed bytes', async () => {
    // Ignoring the parameter would decrypt successfully and hand back the
    // compressed octets as if they were the plaintext, which a caller cannot
    // distinguish from a genuine payload.
    const { cek, serialized } = await compressedObject();
    const trusted = {
      principalId: 'alice',
      key: key({ kty: 'oct', k: encodeBase64url(cek) }, 'dir', 'decrypt'),
    };

    const result = await decrypt(serialized, [trusted], 'dir');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.stage).toBe('header');
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('compression_not_enabled');
    }
  });

  test('rejects any zip value, not only DEF', async () => {
    // An unrecognised value is refused for the same reason: nothing here knows
    // how to undo whatever transform it names.
    for (const zip of ['GZIP', 'none', '']) {
      const { cek, serialized } = await compressedObject(zip);
      const trusted = {
        principalId: 'alice',
        key: key({ kty: 'oct', k: encodeBase64url(cek) }, 'dir', 'decrypt'),
      };

      const result = await decrypt(serialized, [trusted], 'dir');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('compression_not_enabled');
      }
    }
  });

  test('refuses to create an object naming zip', async () => {
    const pair = gcmKwPair('A256GCMKW', 32);
    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: trackingAllocator(),
      protectedHeader: { zip: 'DEF' },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('reserved_header_zip');
    }
  });
});
