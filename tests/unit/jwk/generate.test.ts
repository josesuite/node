import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { encodeBase64url } from '../../../src/internal/encoding/base64url.ts';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { importKeyBytes } from '../../../src/key/import.ts';
import { decryptCompact, encryptCompact } from '../../../src/jwe/compact.ts';
import { generateKeyPair, generateSecret } from '../../../src/key/generate.ts';
import { signCompact } from '../../../src/jws/sign.ts';
import { verifyCompact } from '../../../src/jws/verify.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';

const PLAINTEXT = new TextEncoder().encode('generated key round trip');

describe('key generation: signature families', () => {
  for (const algorithm of ['ES256', 'ES384', 'ES512', 'ES256K'] as const) {
    test(`generates an ECDSA pair usable for ${algorithm}`, async () => {
      const generated = await generateKeyPair({ algorithm });
      assert.ok(generated.ok);

      const { privateKey, publicKey } = generated.keys;
      assert.strictEqual(privateKey.keyType, 'EC');
      assert.strictEqual(privateKey.algorithm, algorithm);
      assert.strictEqual(privateKey.operation, 'sign');
      assert.strictEqual(publicKey.operation, 'verify');
      assert.strictEqual(privateKey.isPrivate, true);
      assert.strictEqual(publicKey.isPrivate, false);

      const signed = await signCompact(PLAINTEXT, {
        key: privateKey,
        policy: AlgorithmPolicy.create('jws', [algorithm], 'create'),
        limits: LIMITS_V1,
      });
      assert.ok(signed.ok);

      const verified = await verifyCompact(signed.token, {
        key: publicKey,
        policy: AlgorithmPolicy.create('jws', [algorithm], 'receive'),
        limits: LIMITS_V1,
        principalId: 'signer',
      });
      assert.ok(verified.ok);
      assert.deepStrictEqual(verified.payload, PLAINTEXT);
    });
  }

  // One RSA size covers both padding families: generation differs only in the
  // bound identifier, and 3072-bit generation is slow enough that repeating it
  // per identifier would dominate the suite.
  for (const algorithm of ['RS256', 'PS256'] as const) {
    test(`generates an RSA pair usable for ${algorithm}`, async () => {
      const generated = await generateKeyPair({ algorithm });
      assert.ok(generated.ok);

      const { privateKey, publicKey } = generated.keys;
      assert.strictEqual(privateKey.keyType, 'RSA');
      assert.strictEqual(privateKey.isPrivate, true);

      const signed = await signCompact(PLAINTEXT, {
        key: privateKey,
        policy: AlgorithmPolicy.create('jws', [algorithm], 'create'),
        limits: LIMITS_V1,
      });
      assert.ok(signed.ok);

      const verified = await verifyCompact(signed.token, {
        key: publicKey,
        policy: AlgorithmPolicy.create('jws', [algorithm], 'receive'),
        limits: LIMITS_V1,
        principalId: 'signer',
      });
      assert.ok(verified.ok);
    });
  }

  test('generates HMAC secrets at the hash output size', () => {
    for (const [algorithm, bytes] of [
      ['HS256', 32],
      ['HS384', 48],
      ['HS512', 64],
    ] as const) {
      const generated = generateSecret({ algorithm });
      assert.ok(generated.ok);
      assert.strictEqual(generated.key.keyType, 'oct');
      assert.strictEqual(generated.key.operation, 'sign');
      assert.strictEqual((generated.key.material as Uint8Array).length, bytes);
    }
  });

  test('a generated HMAC secret round-trips through sign and verify', async () => {
    const generated = generateSecret({ algorithm: 'HS256' });
    assert.ok(generated.ok);

    const signed = await signCompact(PLAINTEXT, {
      key: generated.key,
      policy: AlgorithmPolicy.create('jws', ['HS256'], 'create'),
      limits: LIMITS_V1,
    });
    assert.ok(signed.ok);

    // The same secret verifies: a MAC key is one key used in both directions,
    // unlike the asymmetric families above.
    const verifyKey = generateSecret({ algorithm: 'HS256' });
    assert.ok(verifyKey.ok);
    const wrong = await verifyCompact(signed.token, {
      key: verifyKey.key,
      policy: AlgorithmPolicy.create('jws', ['HS256'], 'receive'),
      limits: LIMITS_V1,
      principalId: 'signer',
    });
    assert.strictEqual(wrong.ok, false);
  });
});

describe('key generation: encryption families', () => {
  test('generates an RSA pair usable for RSA-OAEP-256 key transport', async () => {
    const generated = await generateKeyPair({
      algorithm: 'RSA-OAEP-256',
      contentAlgorithms: ['A128CBC-HS256'],
    });
    assert.ok(generated.ok);

    const { privateKey, publicKey } = generated.keys;
    assert.strictEqual(publicKey.operation, 'wrapKey');
    assert.strictEqual(privateKey.operation, 'unwrapKey');
    assert.deepStrictEqual([...publicKey.contentAlgorithms], ['A128CBC-HS256']);

    const encrypted = await encryptCompact(PLAINTEXT, {
      recipients: [{ key: publicKey }],
      contentAlgorithm: 'A128CBC-HS256',
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-256'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
      limits: LIMITS_V1,
      random: systemRandom,
    });
    assert.ok(encrypted.ok);

    const decrypted = await decryptCompact(encrypted.token, {
      recipients: [{ principalId: 'recipient', key: privateKey }],
      principalId: 'recipient',
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-256'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'receive'),
      limits: LIMITS_V1,
    });
    assert.ok(decrypted.ok);
    assert.deepStrictEqual(decrypted.plaintext, PLAINTEXT);
  });

  test('generates an agreement pair on the configured curve', async () => {
    for (const algorithm of ['ECDH-ES', 'ECDH-ES+A128KW'] as const) {
      const generated = await generateKeyPair({
        algorithm,
        curve: 'P-384',
        contentAlgorithms: ['A128GCM'],
      });
      assert.ok(generated.ok, algorithm);

      // Both halves derive: agreement has no separate wrap and unwrap roles at
      // the key level.
      assert.strictEqual(generated.keys.privateKey.operation, 'deriveKey');
      assert.strictEqual(generated.keys.publicKey.operation, 'deriveKey');
      assert.strictEqual(generated.keys.privateKey.identity.kty, 'EC');
      assert.strictEqual(
        generated.keys.privateKey.identity.kty === 'EC' ? generated.keys.privateKey.identity.crv : undefined,
        'P-384',
      );
    }
  });

  test('generates AES key-wrapping secrets at the identifier size', () => {
    for (const [algorithm, bytes] of [
      ['A128KW', 16],
      ['A192KW', 24],
      ['A256KW', 32],
      ['A128GCMKW', 16],
      ['A256GCMKW', 32],
    ] as const) {
      const generated = generateSecret({ algorithm, contentAlgorithms: ['A128GCM'] });
      assert.ok(generated.ok, algorithm);
      assert.strictEqual(generated.key.operation, 'wrapKey');
      assert.strictEqual((generated.key.material as Uint8Array).length, bytes);
    }
  });

  test('sizes a `dir` secret from its single content algorithm', () => {
    for (const [contentAlgorithm, bytes] of [
      ['A128GCM', 16],
      ['A256GCM', 32],
      ['A128CBC-HS256', 32],
      ['A256CBC-HS512', 64],
    ] as const) {
      const generated = generateSecret({ algorithm: 'dir', contentAlgorithms: [contentAlgorithm] });
      assert.ok(generated.ok, contentAlgorithm);
      assert.strictEqual(generated.key.operation, 'encrypt');
      assert.strictEqual((generated.key.material as Uint8Array).length, bytes);
    }
  });

  test('a generated `dir` secret round-trips through encrypt and decrypt', async () => {
    const generated = generateSecret({ algorithm: 'dir', contentAlgorithms: ['A128CBC-HS256'] });
    assert.ok(generated.ok);

    const encrypted = await encryptCompact(PLAINTEXT, {
      recipients: [{ key: generated.key }],
      contentAlgorithm: 'A128CBC-HS256',
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
      limits: LIMITS_V1,
      random: systemRandom,
    });
    assert.ok(encrypted.ok);

    // Generation binds one key to one operation, so the receiving side imports
    // the same secret bound to `decrypt` rather than reusing the sending key.
    const decryptionKey = importKeyBytes(
      new TextEncoder().encode(
        JSON.stringify({ kty: 'oct', k: encodeBase64url(generated.key.material as Uint8Array) }),
      ),
      { algorithm: 'dir', operation: 'decrypt', contentAlgorithms: ['A128CBC-HS256'] },
    );
    assert.ok(decryptionKey.ok);

    const decrypted = await decryptCompact(encrypted.token, {
      recipients: [{ principalId: 'recipient', key: decryptionKey.key }],
      principalId: 'recipient',
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'receive'),
      limits: LIMITS_V1,
    });
    assert.ok(decrypted.ok);
    assert.deepStrictEqual(decrypted.plaintext, PLAINTEXT);
  });
});

describe('key generation: RSA-02 parameters', () => {
  test('defaults to the modern modulus floor with exponent 65537', async () => {
    const generated = await generateKeyPair({ algorithm: 'RS256' });
    assert.ok(generated.ok);

    const material = generated.keys.publicKey.material as { modulusBits: number; e: Uint8Array };
    assert.strictEqual(material.modulusBits, 3072);
    // 65,537 is 0x010001.
    assert.deepStrictEqual([...material.e], [0x01, 0x00, 0x01]);
  });

  test('refuses a modulus below the modern floor', async () => {
    for (const modulusBits of [2048, 3071, 1024, 0]) {
      const generated = await generateKeyPair({ algorithm: 'RS256', modulusBits });
      assert.strictEqual(generated.ok, false, String(modulusBits));
      assert.strictEqual(generated.category, 'policy_violation');
      assert.strictEqual(generated.reason, 'modulus_below_modern_floor');
    }
  });

  test('refuses a non-integer modulus size', async () => {
    const generated = await generateKeyPair({ algorithm: 'RS256', modulusBits: 3072.5 });
    assert.strictEqual(generated.ok, false);
    assert.strictEqual(generated.reason, 'modulus_below_modern_floor');
  });

  test('refuses a modulus above the resource limit', async () => {
    const generated = await generateKeyPair({
      algorithm: 'RS256',
      modulusBits: 4096,
      limits: lowerLimits({ rsaModulusBits: 3072 }),
    });
    assert.strictEqual(generated.ok, false);
    assert.strictEqual(generated.category, 'resource_limit');
    assert.strictEqual(generated.reason, 'modulus_too_large');
  });
});
