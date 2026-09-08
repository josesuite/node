import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { contentEncryptionShape, sealContent } from '../../../src/algorithms/content-encryption/index.ts';
import { wrapAesKw } from '../../../src/algorithms/jwe/aes-kw.ts';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { decryptJson, decryptParsed, type TrustedRecipient } from '../../../src/jwe/decrypt.ts';
import { encryptJson } from '../../../src/jwe/encrypt.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
import { parseJsonJwe } from '../../../src/jwe/parse.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';

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
  operation: 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey',
  contentAlgorithms: readonly string[] = CONTENT,
): UsableKey {
  const boundOperation = algorithm.startsWith('ECDH-ES') ? 'deriveKey' : operation;
  const result = importKey(object(jwk), { algorithm, operation: boundOperation, contentAlgorithms });
  if (!result.ok) {
    throw new Error(`import failed (${algorithm}/${operation}): ${result.reason}`);
  }
  return result.key;
}

/** A durable-allocator stand-in; production supplies a real one. */
function allocator(): NonceAllocator {
  const counters = new Map<string, bigint>();
  const writers = new Map<string, number>();
  return {
    reserve(keyIdentity: string): Promise<NonceResult> {
      // Each key gets its own writer id, as a real deployment's provisioned
      // writers would. Sharing one across keys would make two distinct spaces
      // yield the same nonce at the same counter.
      let writer = writers.get(keyIdentity);
      if (writer === undefined) {
        writer = writers.size + 1;
        writers.set(keyIdentity, writer);
      }
      const next = (counters.get(keyIdentity) ?? 0n) + 1n;
      counters.set(keyIdentity, next);
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(writer, next)! } });
    },
  };
}

const PLAINTEXT = new TextEncoder().encode('{"sub":"alice"}');

/**
 * Names each generated fixture's nonce space, as a deployment provisions one
 * per physical key. Distinct per fixture so no two share a counter.
 */
let fixtureCount = 0;

function symmetric(algorithm: string, bytes: number, kid?: string, contentAlgorithms: readonly string[] = CONTENT) {
  const secret = randomBytes(bytes);
  const jwk = { kty: 'oct', k: secret.toString('base64url'), ...(kid === undefined ? {} : { kid }) };
  const wrapping = algorithm === 'dir' ? (['encrypt', 'decrypt'] as const) : (['wrapKey', 'unwrapKey'] as const);
  return {
    // Retained so fixtures can build an object this creator refuses to emit.
    secret: new Uint8Array(secret),
    keyIdentity: `fixture-${(fixtureCount += 1)}`,
    encryption: key(jwk, algorithm, wrapping[0], contentAlgorithms),
    decryption: key(jwk, algorithm, wrapping[1], contentAlgorithms),
  };
}

function rsaPair(algorithm = 'RSA-OAEP-256') {
  const generated = generateKeyPairSync('rsa', { modulusLength: 3072 });
  return {
    encryption: key(generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>, algorithm, 'wrapKey'),
    decryption: key(generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>, algorithm, 'unwrapKey'),
  };
}

function ecPair(algorithm: string, curve = 'P-256', contentAlgorithms: readonly string[] = CONTENT) {
  const generated = generateKeyPairSync('ec', { namedCurve: curve });
  const publicJwk = generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  const privateJwk = generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return {
    encryption: key({ ...publicJwk, use: 'enc', key_ops: ['deriveKey'] }, algorithm, 'deriveKey', contentAlgorithms),
    decryption: key({ ...privateJwk, use: 'enc', key_ops: ['deriveKey'] }, algorithm, 'deriveKey', contentAlgorithms),
  };
}

async function encrypt(
  recipients: readonly { encryption: UsableKey; keyIdentity?: string }[],
  keyAlgorithms: readonly string[],
  contentAlgorithm: string,
  extra: Record<string, unknown> = {},
) {
  return encryptJson(PLAINTEXT, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', keyAlgorithms, 'create'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', [contentAlgorithm], 'create'),
    contentAlgorithm,
    recipients: recipients.map((r) => ({ key: r.encryption, keyIdentity: r.keyIdentity })),
    limits: LIMITS_V1,
    random: systemRandom,
    nonceAllocator: allocator(),
    ...extra,
  });
}

async function decrypt(
  serialized: string,
  trusted: readonly TrustedRecipient[],
  keyAlgorithms: readonly string[],
  contentAlgorithm: string,
) {
  return decryptJson(new TextEncoder().encode(serialized), {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', keyAlgorithms, 'receive'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', [contentAlgorithm], 'receive'),
    recipients: trusted,
    principalId: trusted[0]!.principalId,
    limits: LIMITS_V1,
  });
}

const CONTENT = ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const;

describe('round trips', () => {
  for (const enc of CONTENT) {
    test(`dir with ${enc}`, async () => {
      const pair = symmetric('dir', contentEncryptionShape(enc)!.cekBytes, undefined, [enc]);
      const encrypted = await encrypt([pair], ['dir'], enc);
      expect(encrypted.ok).toBe(true);
      if (!encrypted.ok) {
        return;
      }

      const result = await decrypt(encrypted.value, [{ principalId: 'alice', key: pair.decryption }], ['dir'], enc);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.plaintext).toEqual(PLAINTEXT);
        expect(result.principalId).toBe('alice');
      }
    });

    test(`A256KW with ${enc}`, async () => {
      const pair = symmetric('A256KW', 32);
      const encrypted = await encrypt([pair], ['A256KW'], enc);
      expect(encrypted.ok).toBe(true);
      if (!encrypted.ok) {
        return;
      }

      const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['A256KW'], enc);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.plaintext).toEqual(PLAINTEXT);
      }
    });
  }

  test('RSA-OAEP-256 transports the CEK', async () => {
    const pair = rsaPair();
    const encrypted = await encrypt([pair], ['RSA-OAEP-256'], 'A128GCM');
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const result = await decrypt(
      encrypted.value,
      [{ principalId: 'a', key: pair.decryption }],
      ['RSA-OAEP-256'],
      'A128GCM',
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
    }
  });

  test('ECDH-ES derives the CEK directly', async () => {
    const pair = ecPair('ECDH-ES');
    const encrypted = await encrypt([pair], ['ECDH-ES'], 'A128GCM');
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    // Direct agreement carries no encrypted key at all.
    const parsed = JSON.parse(encrypted.value);
    expect(parsed.recipients[0].encrypted_key).toBeUndefined();

    const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['ECDH-ES'], 'A128GCM');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
    }
  });

  test('ECDH-ES+A128KW wraps a fresh CEK', async () => {
    const pair = ecPair('ECDH-ES+A128KW');
    const encrypted = await encrypt([pair], ['ECDH-ES+A128KW'], 'A256GCM');
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const parsed = JSON.parse(encrypted.value);
    expect(typeof parsed.recipients[0].encrypted_key).toBe('string');

    const result = await decrypt(
      encrypted.value,
      [{ principalId: 'a', key: pair.decryption }],
      ['ECDH-ES+A128KW'],
      'A256GCM',
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
    }
  });

  test('refuses content encryption outside the key binding', async () => {
    const pair = ecPair('ECDH-ES', 'P-256', ['A128GCM']);
    const result = await encrypt([pair], ['ECDH-ES'], 'A256GCM');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('content_algorithm_not_bound');
    }
  });

  test('publishes only the public half of the ephemeral key', async () => {
    // A private member in `epk` would let anyone derive the CEK.
    const pair = ecPair('ECDH-ES');
    const encrypted = await encrypt([pair], ['ECDH-ES'], 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const header = JSON.parse(Buffer.from(JSON.parse(encrypted.value).protected, 'base64url').toString('utf8'));
    expect(header.epk).toBeDefined();
    expect(header.epk.d).toBeUndefined();
    expect(header.epk.kty).toBe('EC');
    expect(typeof header.epk.x).toBe('string');
  });

  test('emits the flattened form on request', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM', { flattened: true });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const parsed = JSON.parse(encrypted.value);
    expect(parsed.recipients).toBeUndefined();
    expect(typeof parsed.encrypted_key).toBe('string');

    const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['A256KW'], 'A128GCM');
    expect(result.ok).toBe(true);
  });

  test('round-trips an empty plaintext', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encryptJson(new Uint8Array(0), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
    });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    // GCM produces no ciphertext octets, but the member stays present.
    expect(JSON.parse(encrypted.value).ciphertext).toBe('');

    const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['A256KW'], 'A128GCM');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(new Uint8Array(0));
    }
  });

  test('authenticates external AAD', async () => {
    const pair = symmetric('A256KW', 32);
    const aad = new TextEncoder().encode('context');
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM', { externalAad: aad });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parsed = JSON.parse(encrypted.value);
    expect(parsed.aad).toBe(Buffer.from(aad).toString('base64url'));

    expect(
      (await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['A256KW'], 'A128GCM')).ok,
    ).toBe(true);

    // Changing the AAD changes the authenticated data, so the tag fails.
    const tampered = JSON.stringify({ ...parsed, aad: Buffer.from('other').toString('base64url') });
    const result = await decrypt(tampered, [{ principalId: 'a', key: pair.decryption }], ['A256KW'], 'A128GCM');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
    }
  });

  test('omits the aad member for zero external octets', async () => {
    // An empty member and an absent one produce different authenticated data,
    // so zero octets must emit nothing rather than an empty string.
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM', { externalAad: new Uint8Array(0) });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    expect(JSON.parse(encrypted.value).aad).toBeUndefined();
  });
});

describe('secret lifetime', () => {
  test('clears a generated CEK after content encryption', async () => {
    const pair = symmetric('A256KW', 32);
    const generated: Uint8Array[] = [];
    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption }],
      limits: LIMITS_V1,
      random: {
        randomBytes(length) {
          const value = new Uint8Array(length).fill(0xa5);
          generated.push(value);
          return { ok: true, value };
        },
      },
      nonceAllocator: allocator(),
    });

    expect(result.ok).toBe(true);
    // The CEK and the content IV are both drawn here; only the CEK is a secret
    // that must not survive the operation.
    expect(generated).toHaveLength(2);
    expect(generated[0]).toEqual(new Uint8Array(16));
  });
});

describe('multiple recipients share one content operation', () => {
  test('both recipients recover the same plaintext', async () => {
    // Each recipient publishes its `kid` so a holder of one key can be narrowed
    // to exactly one entry; without it every entry sharing the algorithm is
    // equally eligible and the object is ambiguous.
    const alice = symmetric('A256KW', 32, 'alice');
    const bob = symmetric('A256KW', 32, 'bob');
    const encrypted = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A256GCM'], 'create'),
      contentAlgorithm: 'A256GCM',
      recipients: [
        { key: alice.encryption, unprotectedHeader: { kid: 'alice' } },
        { key: bob.encryption, unprotectedHeader: { kid: 'bob' } },
      ],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
    });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const parsed = JSON.parse(encrypted.value);
    expect(parsed.recipients).toHaveLength(2);
    // One ciphertext and one tag for the whole object, not one per recipient.
    expect(typeof parsed.ciphertext).toBe('string');
    expect(typeof parsed.tag).toBe('string');
    expect(parsed.recipients[0].encrypted_key).not.toBe(parsed.recipients[1].encrypted_key);

    for (const recipient of [alice, bob]) {
      const result = await decrypt(
        encrypted.value,
        [{ principalId: 'p', key: recipient.decryption }],
        ['A256KW'],
        'A256GCM',
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.plaintext).toEqual(PLAINTEXT);
      }
    }
  });

  /**
   * Modes producing a fresh ephemeral key or wrapping IV per recipient.
   *
   * These are the ones where a single shared copy in the protected header
   * describes only one recipient's key management, leaving every other
   * recipient's encrypted key unopenable.
   */
  const PER_RECIPIENT_MODES = [
    { algorithm: 'ECDH-ES+A128KW', parameters: ['epk'] },
    { algorithm: 'A256GCMKW', parameters: ['iv', 'tag'] },
  ] as const;

  for (const { algorithm, parameters } of PER_RECIPIENT_MODES) {
    test(`every recipient of ${algorithm} decrypts independently`, async () => {
      const pairs = ['alice', 'bob'].map((kid) => {
        if (algorithm.startsWith('ECDH-ES')) {
          const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
          const publicJwk = { ...(generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid };
          const privateJwk = { ...(generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>), kid };
          return {
            kid,
            encryption: key(publicJwk, algorithm, 'encrypt'),
            decryption: key(privateJwk, algorithm, 'decrypt'),
          };
        }
        const jwk = { kty: 'oct', k: randomBytes(32).toString('base64url'), kid };
        return { kid, encryption: key(jwk, algorithm, 'wrapKey'), decryption: key(jwk, algorithm, 'unwrapKey') };
      });

      const encrypted = await encryptJson(PLAINTEXT, {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', [algorithm], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: pairs.map((pair) => ({
          key: pair.encryption,
          keyIdentity: pair.kid,
          unprotectedHeader: { kid: pair.kid },
        })),
        limits: LIMITS_V1,
        random: systemRandom,
        nonceAllocator: allocator(),
      });
      expect(encrypted.ok).toBe(true);
      if (!encrypted.ok) {
        return;
      }

      const parsed = JSON.parse(encrypted.value);
      const protectedHeader = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString());

      for (const name of parameters) {
        // A shared copy would describe only the first recipient, so with
        // several recipients the parameter belongs to each entry instead.
        expect(protectedHeader[name]).toBeUndefined();
        expect(parsed.recipients[0].header[name]).toBeDefined();
        expect(parsed.recipients[1].header[name]).toBeDefined();
        expect(parsed.recipients[0].header[name]).not.toEqual(parsed.recipients[1].header[name]);
      }

      for (const pair of pairs) {
        const result = await decrypt(
          encrypted.value,
          [{ principalId: pair.kid, key: pair.decryption }],
          [algorithm],
          'A128GCM',
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.plaintext).toEqual(PLAINTEXT);
        }
      }
    });
  }

  test('refuses several recipients for a direct mode', async () => {
    // Direct modes derive the CEK from one recipient's key, so a second could
    // never recover it.
    const a = symmetric('dir', 16, undefined, ['A128GCM']);
    const b = symmetric('dir', 16, undefined, ['A128GCM']);

    const result = await encrypt([a, b], ['dir'], 'A128GCM');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('algorithm_requires_single_recipient');
    }
  });
});

function flip(value: string): string {
  const bytes = Buffer.from(value, 'base64url');
  bytes[0] = bytes[0]! ^ 0x01;
  return bytes.toString('base64url');
}

describe('tampering is detected', () => {
  async function tamper(member: string, mutate: (value: string) => string) {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parsed = JSON.parse(encrypted.value);
    parsed[member] = mutate(parsed[member]);

    return decrypt(JSON.stringify(parsed), [{ principalId: 'a', key: pair.decryption }], ['A256KW'], 'A128GCM');
  }

  test('a modified ciphertext fails authentication', async () => {
    const result = await tamper('ciphertext', flip);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
    }
  });

  test('a modified tag fails authentication', async () => {
    const result = await tamper('tag', flip);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
    }
  });

  test('a modified IV fails authentication', async () => {
    const result = await tamper('iv', flip);
    expect(result.ok).toBe(false);
  });

  test('a modified protected header fails authentication', async () => {
    // The header is authenticated but not encrypted, so a change must be
    // caught by the content tag rather than silently accepted.
    const result = await tamper('protected', (value) => {
      const header = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
      return Buffer.from(JSON.stringify({ ...header, extra: 'injected' })).toString('base64url');
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('authentication_failure');
    }
  });

  test('preserves duplicate protected-header JSON as malformed input', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }
    const document = JSON.parse(encrypted.value) as { protected: string };
    document.protected = Buffer.from('{"alg":"A256KW","alg":"A256KW","enc":"A128GCM"}').toString('base64url');
    const result = await decrypt(
      JSON.stringify(document),
      [{ principalId: 'a', key: pair.decryption }],
      ['A256KW'],
      'A128GCM',
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('malformed_input');
    }
  });

  test('a wrong key reports the same failure as a bad tag', async () => {
    // A failed key recovery and a failed content tag must not be
    // distinguishable, or the endpoint becomes an oracle.
    const pair = symmetric('A256KW', 32);
    const other = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const wrongKey = await decrypt(
      encrypted.value,
      [{ principalId: 'a', key: other.decryption }],
      ['A256KW'],
      'A128GCM',
    );
    const badTag = await tamper('tag', flip);

    expect(wrongKey.ok).toBe(false);
    expect(badTag.ok).toBe(false);
    if (!wrongKey.ok && !badTag.ok) {
      expect(wrongKey.category).toBe(badTag.category);
      expect(wrongKey.reason).toBe(badTag.reason);
    }
  });

  test('refuses to create a JWE demanding an unimplemented critical extension', async () => {
    // A producer must not emit what its corresponding consumer is required to
    // reject, so this is refused before any cryptography rather than producing
    // an object nobody will accept.
    const pair = symmetric('A256KW', 32);
    const result = await encrypt([pair], ['A256KW'], 'A128GCM', {
      protectedHeader: { b64: false, crit: ['b64'] },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_critical_parameter');
      expect(result.reason).toBe('critical_extension_not_implemented');
    }
  });

  test('rejects a correctly authenticated JWE demanding critical b64', async () => {
    // RFC 7797 defines `b64` for JWS only, so JWE implements no semantics for
    // it. The object authenticates correctly; it must still be refused rather
    // than treating the producer's demand as satisfied. This creator will not
    // emit such an object, so the fixture is built directly, as a
    // non-conforming producer would.
    const pair = symmetric('A256KW', 32);
    const cek = randomBytes(16);
    const iv = randomBytes(12);
    const protectedComponent = Buffer.from(
      JSON.stringify({ alg: 'A256KW', enc: 'A128GCM', b64: false, crit: ['b64'] }),
    ).toString('base64url');

    const wrapped = await wrapAesKw('A256KW', pair.secret, cek);
    const sealed = await sealContent('A128GCM', cek, iv, PLAINTEXT, new TextEncoder().encode(protectedComponent));
    if (!wrapped.ok || !sealed.ok) {
      throw new Error('fixture failed');
    }

    const serialized = JSON.stringify({
      protected: protectedComponent,
      iv: Buffer.from(iv).toString('base64url'),
      ciphertext: Buffer.from(sealed.value.ciphertext).toString('base64url'),
      tag: Buffer.from(sealed.value.tag).toString('base64url'),
      recipients: [{ encrypted_key: Buffer.from(wrapped.value).toString('base64url') }],
    });

    const result = await decrypt(serialized, [{ principalId: 'alice', key: pair.decryption }], ['A256KW'], 'A128GCM');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_critical_parameter');
    }
  });
});

/** A decoded protected header under test, with an `epk` these fixtures mutate. */
interface TestHeader extends Record<string, unknown> {
  epk?: Record<string, string | undefined>;
}

/** Re-encodes a protected header after mutating it; the AAD changes with it. */
function rewriteProtected(serialized: string, mutate: (header: TestHeader) => void): string {
  const document = JSON.parse(serialized) as { protected: string };
  const header = JSON.parse(Buffer.from(document.protected, 'base64url').toString()) as TestHeader;
  mutate(header);
  document.protected = Buffer.from(JSON.stringify(header)).toString('base64url');
  return JSON.stringify(document);
}

describe('ECDH agreement parameters', () => {
  test('binds supplied party information into the derivation', async () => {
    // The recipient derives with the `apu`/`apv` the header publishes, so a
    // producer that emits them without binding them into its own KDF builds an
    // object nobody can decrypt.
    const pair = ecPair('ECDH-ES');
    const encrypted = await encrypt([pair], ['ECDH-ES'], 'A128GCM', {
      protectedHeader: { apu: 'QWxpY2U', apv: 'Qm9i' },
    });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const header = JSON.parse(Buffer.from(JSON.parse(encrypted.value).protected, 'base64url').toString());
    expect(header.apu).toBe('QWxpY2U');
    expect(header.apv).toBe('Qm9i');

    const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['ECDH-ES'], 'A128GCM');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
    }
  });

  test('refuses party information under a non-agreement algorithm', async () => {
    // Nothing would bind them, so accepting them would emit a header member the
    // producer believes is authenticated context and that no derivation reads.
    const pair = symmetric('A256KW', 32);
    const result = await encrypt([pair], ['A256KW'], 'A128GCM', { protectedHeader: { apu: 'QWxpY2U' } });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_header');
      expect(result.reason).toBe('party_info_requires_agreement_algorithm');
    }
  });

  const EPK_DEFECTS: readonly {
    name: string;
    reason: string;
    mutate: (header: TestHeader) => void;
  }[] = [
    { name: 'a missing epk', reason: 'epk_missing', mutate: (h) => delete h.epk },
    { name: 'a wrong kty', reason: 'epk_kty_does_not_match_curve', mutate: (h) => (h.epk!['kty'] = 'oct') },
    { name: 'an absent kty', reason: 'epk_incomplete', mutate: (h) => delete h.epk!['kty'] },
    { name: 'a private member', reason: 'epk_carries_private_key', mutate: (h) => (h.epk!['d'] = h.epk!['x']) },
    {
      name: 'a short coordinate',
      reason: 'epk_x_wrong_length',
      mutate: (h) => {
        h.epk!['x'] = Buffer.from(h.epk!['x']!, 'base64url').subarray(0, 8).toString('base64url');
      },
    },
    { name: 'an absent y on a NIST curve', reason: 'epk_incomplete', mutate: (h) => delete h.epk!['y'] },
    {
      name: 'a signing curve',
      reason: 'epk_curve_not_usable_for_agreement',
      mutate: (h) => (h.epk!['crv'] = 'Ed25519'),
    },
  ];

  for (const { name, reason, mutate } of EPK_DEFECTS) {
    test(`rejects ${name} at the header stage`, async () => {
      // Every one of these is decidable from the header alone, so it must be
      // reported there rather than surfacing later as a failed recovery.
      const pair = ecPair('ECDH-ES');
      const encrypted = await encrypt([pair], ['ECDH-ES'], 'A128GCM');
      if (!encrypted.ok) {
        throw new Error('encrypt failed');
      }

      const result = await decrypt(
        rewriteProtected(encrypted.value, mutate),
        [{ principalId: 'a', key: pair.decryption }],
        ['ECDH-ES'],
        'A128GCM',
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.stage).toBe('header');
        expect(result.category).toBe('invalid_header');
        expect(result.reason).toBe(reason);
      }
    });
  }

  test('ignores an epk under an algorithm that does not agree', async () => {
    // Under RSA-OAEP the member selects nothing, so it stays an ordinary
    // ignorable header member rather than being interpreted out of context.
    // It is injected as an unprotected member because creation refuses to let a
    // caller supply `epk` itself, and unprotected members are outside the AAD.
    const pair = rsaPair();
    const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
      format: 'jwk',
    }) as Record<string, string>;

    const encrypted = await encrypt([pair], ['RSA-OAEP-256'], 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const document = JSON.parse(encrypted.value) as { recipients: Record<string, unknown>[] };
    document.recipients[0]!['header'] = {
      epk: { kty: 'EC', crv: generated['crv']!, x: generated['x']!, y: generated['y']! },
    };

    const result = await decrypt(
      JSON.stringify(document),
      [{ principalId: 'a', key: pair.decryption }],
      ['RSA-OAEP-256'],
      'A128GCM',
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
    }
  });
});

describe('creation validates its own configuration', () => {
  test('normalizes throwing randomness and nonce collaborators', async () => {
    const wrapping = symmetric('A256KW', 32);
    const randomFailure = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: wrapping.encryption }],
      limits: LIMITS_V1,
      random: {
        randomBytes: () => {
          throw new Error('offline');
        },
      },
    });
    expect(randomFailure.ok).toBe(false);
    if (!randomFailure.ok) {
      expect(randomFailure.category).toBe('backend_failure');
    }

    const direct = symmetric('dir', 16, undefined, ['A128GCM']);
    const nonceFailure = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: direct.encryption, keyIdentity: direct.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: { reserve: () => Promise.reject(new Error('offline')) },
    });
    expect(nonceFailure.ok).toBe(false);
    if (!nonceFailure.ok) {
      expect(nonceFailure.category).toBe('backend_failure');
    }
  });
  test('refuses a policy built for acceptance', async () => {
    // A receive allowlist admits identifiers this direction refuses, so passing
    // one here is a configuration defect rather than an outcome to discover per
    // identifier further down.
    const pair = symmetric('A256KW', 32);
    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('policy_not_built_for_creation');
    }
  });

  test('refuses to create under a receive-only algorithm', async () => {
    // Legacy RSA-OAEP may be accepted but never produced. A receive allowlist
    // containing it must not become a licence to emit it.
    const generated = generateKeyPairSync('rsa', { modulusLength: 3072 });
    const encryption = key(
      generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>,
      'RSA-OAEP',
      'unwrapKey',
    );

    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: encryption }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
    });

    expect(result.ok).toBe(false);
  });

  const HEADER_DEFECTS = [
    { name: 'a wrong-type kid', header: { kid: ['not', 'a', 'string'] }, reason: 'header_kid_wrong_type' },
    { name: 'a wrong-type crit', header: { crit: 'b64' }, reason: 'header_crit_wrong_type' },
    { name: 'an empty crit list', header: { crit: [] }, reason: 'crit_empty' },
    {
      name: 'a crit naming a base parameter',
      header: { crit: ['kid'], kid: 'a' },
      reason: 'crit_names_base_parameter',
    },
    {
      name: 'a crit naming an absent parameter',
      header: { crit: ['x-absent'] },
      reason: 'crit_names_absent_parameter',
    },
    {
      name: 'a duplicated crit name',
      header: { crit: ['x-a', 'x-a'], 'x-a': 'v' },
      reason: 'crit_duplicate_name',
    },
  ] as const;

  for (const { name, header, reason } of HEADER_DEFECTS) {
    test(`refuses ${name} before any cryptography`, async () => {
      const pair = symmetric('A256KW', 32);
      const result = await encrypt([pair], ['A256KW'], 'A128GCM', {
        protectedHeader: header as Record<string, unknown>,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.stage).toBe('configuration');
        expect(result.reason).toBe(reason);
      }
    });
  }

  test('refuses a critical extension in an unprotected recipient header', async () => {
    // The list must be protected; an unprotected one could be stripped in
    // transit without any recipient noticing.
    const pair = symmetric('A256KW', 32);
    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption, unprotectedHeader: { crit: 'x-a' } }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('unprotected_crit_not_permitted');
    }
  });

  test('reserves no nonce when the configuration is rejected', async () => {
    // A burned nonce is not recoverable, so a rejected configuration must not
    // consume one on its way to failing.
    const pair = symmetric('A256GCMKW', 32);
    const tracker = allocator();
    const reserved: string[] = [];
    const watching: NonceAllocator = {
      async reserve(identity) {
        reserved.push(identity);
        return tracker.reserve(identity);
      },
    };

    const result = await encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256GCMKW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption, keyIdentity: pair.keyIdentity }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: watching,
      protectedHeader: { kid: ['wrong', 'type'] as unknown as string },
    });

    expect(result.ok).toBe(false);
    expect(reserved).toEqual([]);
  });

  test('treats a header named like an inherited member as ordinary data', async () => {
    // `constructor` and `__proto__` must stay plain header names rather than
    // reaching an inherited member or assigning a prototype.
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM', {
      protectedHeader: { constructor: 'x', __proto__: 'y' },
    });
    expect(encrypted.ok).toBe(true);
    if (!encrypted.ok) {
      return;
    }

    const header = JSON.parse(Buffer.from(JSON.parse(encrypted.value).protected, 'base64url').toString());
    expect(header.constructor).toBe('x');
    expect(Object.getPrototypeOf(header)).toBe(Object.prototype);

    const result = await decrypt(encrypted.value, [{ principalId: 'a', key: pair.decryption }], ['A256KW'], 'A128GCM');
    expect(result.ok).toBe(true);
  });
});

describe('resource limits reach the whole operation', () => {
  test('refuses an authenticated plaintext over the payload limit', async () => {
    // The plaintext length is only known after the tag verifies, so the bound
    // is applied there. Returning over-limit octets because the ciphertext fit
    // would make the limit unenforceable.
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parsed = parseJsonJwe(
      (() => {
        const r = parseJson(new TextEncoder().encode(encrypted.value), LIMITS_V1);
        if (!r.ok) {
          throw new Error('bad serialization');
        }
        return r.value;
      })(),
      LIMITS_V1,
    );
    if (!parsed.ok) {
      throw new Error('parse failed');
    }

    const result = await decryptParsed(parsed.value, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
      recipients: [{ principalId: 'a', key: pair.decryption }],
      principalId: 'a',
      limits: lowerLimits({ payload: PLAINTEXT.length - 1 }),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
      expect(result.reason).toBe('plaintext_too_large');
    }
  });

  test('refuses a non-canonical aad component', async () => {
    // The component enters the authenticated data verbatim, so it is never
    // replaced by its decoded value; it must still be well formed rather than
    // arbitrary octets a producer chose.
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt([pair], ['A256KW'], 'A128GCM', {
      externalAad: new TextEncoder().encode('ctx'),
    });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const document = JSON.parse(encrypted.value) as Record<string, unknown>;
    document['aad'] = '!';

    const json = parseJson(new TextEncoder().encode(JSON.stringify(document)), LIMITS_V1);
    if (!json.ok) {
      throw new Error('bad serialization');
    }
    const parsed = parseJsonJwe(json.value, LIMITS_V1);

    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.category).toBe('invalid_encoding');
      expect(parsed.reason).toBe('aad_invalid_base64url');
    }
  });
});
