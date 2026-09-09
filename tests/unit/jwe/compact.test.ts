import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createCipheriv, generateKeyPairSync, randomBytes } from 'node:crypto';

import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { decryptCompact, encryptCompact } from '../../../src/jwe/compact.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
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
  operation: 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey',
  contentAlgorithms: readonly string[] = CONTENT,
): UsableKey {
  const boundOperation = algorithm.startsWith('ECDH-ES') ? 'deriveKey' : operation;
  const result = importKey(object(jwk), { algorithm, operation: boundOperation, contentAlgorithms });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

function allocator(): NonceAllocator {
  const counters = new Map<string, bigint>();
  return {
    reserve(id: string): Promise<NonceResult> {
      const next = (counters.get(id) ?? 0n) + 1n;
      counters.set(id, next);
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(1, next)! } });
    },
  };
}

const PLAINTEXT = new TextEncoder().encode('{"sub":"alice"}');

function symmetric(algorithm: string, bytes: number, contentAlgorithms: readonly string[] = CONTENT) {
  const jwk = { kty: 'oct', k: randomBytes(bytes).toString('base64url') };
  const ops = algorithm === 'dir' ? (['encrypt', 'decrypt'] as const) : (['wrapKey', 'unwrapKey'] as const);
  return {
    jwk,
    encryption: key(jwk, algorithm, ops[0], contentAlgorithms),
    decryption: key(jwk, algorithm, ops[1], contentAlgorithms),
  };
}

/** Names each call's nonce space, as a deployment provisions one per key. */
let fixtureCount = 0;

async function encrypt(encryptionKey: UsableKey, algorithm: string, enc: string, extra: Record<string, unknown> = {}) {
  return encryptCompact(PLAINTEXT, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', [algorithm], 'create'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', [enc], 'create'),
    contentAlgorithm: enc,
    recipients: [{ key: encryptionKey, keyIdentity: `fixture-${(fixtureCount += 1)}` }],
    limits: LIMITS_V1,
    random: systemRandom,
    nonceAllocator: allocator(),
    ...extra,
  });
}

async function decrypt(token: string, decryptionKey: UsableKey, algorithm: string, enc: string) {
  return decryptCompact(token, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', [algorithm], 'receive'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', [enc], 'receive'),
    recipients: [{ principalId: 'alice', key: decryptionKey }],
    principalId: 'alice',
    limits: LIMITS_V1,
  });
}

const CONTENT = ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const;

describe('round trips', () => {
  for (const enc of CONTENT) {
    test(`A256KW with ${enc}`, async () => {
      const pair = symmetric('A256KW', 32);
      const encrypted = await encrypt(pair.encryption, 'A256KW', enc);
      assert.strictEqual(encrypted.ok, true);
      if (!encrypted.ok) {
        return;
      }

      assert.strictEqual(encrypted.token.split('.').length, 5);

      const result = await decrypt(encrypted.token, pair.decryption, 'A256KW', enc);
      assert.strictEqual(result.ok, true);
      if (result.ok) {
        assert.deepStrictEqual(result.plaintext, PLAINTEXT);
        assert.strictEqual(result.principalId, 'alice');
      }
    });
  }

  test('dir emits an empty encrypted-key component', async () => {
    // Direct modes carry no encrypted key. JSON omits the member; Compact has
    // no way to omit a component, so it is empty.
    const pair = symmetric('dir', 16, ['A128GCM']);
    const encrypted = await encrypt(pair.encryption, 'dir', 'A128GCM');
    assert.strictEqual(encrypted.ok, true);
    if (!encrypted.ok) {
      return;
    }

    assert.strictEqual(encrypted.token.split('.')[1], '');

    const result = await decrypt(encrypted.token, pair.decryption, 'dir', 'A128GCM');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.plaintext, PLAINTEXT);
    }
  });

  test('RSA-OAEP-256 round-trips', async () => {
    const generated = generateKeyPairSync('rsa', { modulusLength: 3072 });
    const encryption = key(
      generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
      'RSA-OAEP-256',
      'wrapKey',
    );
    const decryption = key(
      generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>,
      'RSA-OAEP-256',
      'unwrapKey',
    );

    const encrypted = await encrypt(encryption, 'RSA-OAEP-256', 'A128GCM');
    assert.strictEqual(encrypted.ok, true);
    if (!encrypted.ok) {
      return;
    }

    const result = await decrypt(encrypted.token, decryption, 'RSA-OAEP-256', 'A128GCM');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.plaintext, PLAINTEXT);
    }
  });

  test('ECDH-ES carries epk in the protected header', async () => {
    // Compact has no unprotected header, so agreement parameters must travel in
    // the protected one or the recipient cannot reproduce the agreement.
    const generated = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const encryption = key(
      generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
      'ECDH-ES',
      'encrypt',
    );
    const decryption = key(
      generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>,
      'ECDH-ES',
      'decrypt',
    );

    const encrypted = await encrypt(encryption, 'ECDH-ES', 'A128GCM');
    assert.strictEqual(encrypted.ok, true);
    if (!encrypted.ok) {
      return;
    }

    const header = JSON.parse(Buffer.from(encrypted.token.split('.')[0]!, 'base64url').toString('utf8'));
    assert.notStrictEqual(header.epk, undefined);
    assert.strictEqual(header.epk.d, undefined);

    const result = await decrypt(encrypted.token, decryption, 'ECDH-ES', 'A128GCM');
    assert.strictEqual(result.ok, true);
  });

  test('round-trips an empty plaintext', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encryptCompact(new Uint8Array(0), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: pair.encryption }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
    });
    assert.strictEqual(encrypted.ok, true);
    if (!encrypted.ok) {
      return;
    }

    // GCM produces no ciphertext octets, so that component is empty while the
    // remaining four are present.
    assert.strictEqual(encrypted.token.split('.')[3], '');

    const result = await decrypt(encrypted.token, pair.decryption, 'A256KW', 'A128GCM');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.plaintext, new Uint8Array(0));
    }
  });
});

describe('interoperability with an independently built object', () => {
  test('decrypts a Compact JWE this library did not produce', async () => {
    // Built directly from the provider so the test exercises acceptance of a
    // foreign object rather than agreement with our own serializer.
    const cek = randomBytes(16);
    const kekBytes = randomBytes(32);
    const iv = randomBytes(12);

    const header = Buffer.from(JSON.stringify({ alg: 'A256KW', enc: 'A128GCM' })).toString('base64url');

    // Wrapped through WebCrypto's own `wrapKey`, which is a separate code path
    // from this library's serializer and available on every tested runtime.
    const kekHandle = await crypto.subtle.importKey('raw', new Uint8Array(kekBytes), 'AES-KW', false, ['wrapKey']);
    const cekHandle = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(cek),
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign'],
    );
    const encryptedKey = Buffer.from(await crypto.subtle.wrapKey('raw', cekHandle, kekHandle, 'AES-KW'));

    const cipher = createCipheriv('aes-128-gcm', cek, iv);
    cipher.setAAD(Buffer.from(header, 'ascii'));
    const ciphertext = Buffer.concat([cipher.update(PLAINTEXT), cipher.final()]);
    const tag = cipher.getAuthTag();

    const token = [
      header,
      encryptedKey.toString('base64url'),
      iv.toString('base64url'),
      ciphertext.toString('base64url'),
      tag.toString('base64url'),
    ].join('.');

    const decryption = key({ kty: 'oct', k: kekBytes.toString('base64url') }, 'A256KW', 'unwrapKey');

    const result = await decrypt(token, decryption, 'A256KW', 'A128GCM');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.plaintext, PLAINTEXT);
    }
  });
});

describe('Compact cannot express what it has no room for', () => {
  test('forwards JSON encryption failures', async () => {
    const pair = symmetric('A256KW', 32, ['A128GCM']);
    const result = await encrypt(pair.encryption, 'A256KW', 'A192GCM');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
      assert.strictEqual(result.reason, 'content_algorithm_not_bound');
    }
  });

  test('refuses an unprotected header', async () => {
    // Dropping it would emit an object missing data the caller supplied.
    const pair = symmetric('A256KW', 32);
    const result = await encrypt(pair.encryption, 'A256KW', 'A128GCM', {
      recipients: [{ key: pair.encryption, unprotectedHeader: { kid: 'hint' } }],
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'compact_has_no_unprotected_header');
    }
  });

  test('refuses more than one recipient', async () => {
    const a = symmetric('A256KW', 32);
    const b = symmetric('A256KW', 32);
    const result = await encrypt(a.encryption, 'A256KW', 'A128GCM', {
      recipients: [{ key: a.encryption }, { key: b.encryption }],
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'compact_requires_single_recipient');
    }
  });
});

describe('structural rejection', () => {
  test('rejects a token without exactly five components', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt(pair.encryption, 'A256KW', 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parts = encrypted.token.split('.');
    for (const token of [parts.slice(0, 4).join('.'), `${encrypted.token}.extra`]) {
      const result = await decrypt(token, pair.decryption, 'A256KW', 'A128GCM');
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.stage, 'syntax');
        assert.strictEqual(result.reason, 'compact_component_count');
      }
    }
  });

  test('detects tampering in every authenticated component', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt(pair.encryption, 'A256KW', 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    // The protected header, ciphertext and tag all enter the authenticated
    // input, so a change in any of them must be caught.
    for (const index of [0, 3, 4]) {
      const parts = encrypted.token.split('.');
      const bytes = Buffer.from(parts[index]!, 'base64url');
      bytes[0] = bytes[0]! ^ 0x01;
      parts[index] = bytes.toString('base64url');

      const result = await decrypt(parts.join('.'), pair.decryption, 'A256KW', 'A128GCM');
      assert.strictEqual(result.ok, false);
    }
  });

  test('rejects a modified encrypted key', async () => {
    const pair = symmetric('A256KW', 32);
    const encrypted = await encrypt(pair.encryption, 'A256KW', 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const parts = encrypted.token.split('.');
    const bytes = Buffer.from(parts[1]!, 'base64url');
    bytes[0] = bytes[0]! ^ 0x01;
    parts[1] = bytes.toString('base64url');

    const result = await decrypt(parts.join('.'), pair.decryption, 'A256KW', 'A128GCM');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      // A failed unwrap and a failed content tag report identically.
      assert.strictEqual(result.category, 'authentication_failure');
      assert.strictEqual(result.reason, 'decryption_failed');
    }
  });

  test('rejects a wrong key with the same failure as a bad tag', async () => {
    const pair = symmetric('A256KW', 32);
    const other = symmetric('A256KW', 32);
    const encrypted = await encrypt(pair.encryption, 'A256KW', 'A128GCM');
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const wrongKey = await decrypt(encrypted.token, other.decryption, 'A256KW', 'A128GCM');

    const parts = encrypted.token.split('.');
    const tag = Buffer.from(parts[4]!, 'base64url');
    tag[0] = tag[0]! ^ 0x01;
    parts[4] = tag.toString('base64url');
    const badTag = await decrypt(parts.join('.'), pair.decryption, 'A256KW', 'A128GCM');

    assert.strictEqual(wrongKey.ok, false);
    assert.strictEqual(badTag.ok, false);
    if (!wrongKey.ok && !badTag.ok) {
      assert.strictEqual(wrongKey.category, badTag.category);
      assert.strictEqual(wrongKey.reason, badTag.reason);
    }
  });
});

describe('kid filtering', () => {
  function named(kid: string) {
    const jwk = { kty: 'oct', k: randomBytes(32).toString('base64url'), kid };
    return { encryption: key(jwk, 'A256KW', 'wrapKey'), decryption: key(jwk, 'A256KW', 'unwrapKey') };
  }

  test('a matching kid decrypts', async () => {
    const alice = named('alice');
    const encrypted = await encrypt(alice.encryption, 'A256KW', 'A128GCM', {
      protectedHeader: { kid: 'alice' },
    });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const result = await decrypt(encrypted.token, alice.decryption, 'A256KW', 'A128GCM');
    assert.strictEqual(result.ok, true);
  });

  test('an unmatched kid resolves nothing rather than using the sole trusted key', async () => {
    // The key would unwrap this object. A single trusted candidate is still
    // filtered, or an object naming an unconfigured key would be opened anyway.
    const alice = named('alice');
    const encrypted = await encrypt(alice.encryption, 'A256KW', 'A128GCM', {
      protectedHeader: { kid: 'other' },
    });
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const result = await decrypt(encrypted.token, alice.decryption, 'A256KW', 'A128GCM');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'key_resolution_failure');
      assert.strictEqual(result.reason, 'no_eligible_recipient');
    }
  });
});
