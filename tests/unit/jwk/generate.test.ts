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

describe('key generation: rejected configurations', () => {
  test('refuses a prohibited algorithm', async () => {
    const pair = await generateKeyPair({ algorithm: 'none' });
    assert.strictEqual(pair.ok, false);
    assert.strictEqual(pair.category, 'prohibited_algorithm');

    const secret = generateSecret({ algorithm: 'A128CBC' });
    assert.strictEqual(secret.ok, false);
    assert.strictEqual(secret.category, 'prohibited_algorithm');
  });

  test('refuses a receive-only legacy algorithm', async () => {
    const oaep = await generateKeyPair({ algorithm: 'RSA-OAEP', contentAlgorithms: ['A128GCM'] });
    assert.strictEqual(oaep.ok, false);
    assert.strictEqual(oaep.category, 'policy_violation');
    assert.strictEqual(oaep.reason, 'algorithm_receive_only');

    const pbes2 = generateSecret({ algorithm: 'PBES2-HS256+A128KW', contentAlgorithms: ['A128GCM'] });
    assert.strictEqual(pbes2.ok, false);
    assert.strictEqual(pbes2.reason, 'algorithm_receive_only');
  });

  test('refuses an unqualified algorithm', async () => {
    for (const algorithm of ['Ed25519', 'Ed448', 'EdDSA', 'ML-DSA-44']) {
      const generated = await generateKeyPair({ algorithm });
      assert.strictEqual(generated.ok, false, algorithm);
      assert.strictEqual(generated.category, 'unsupported_algorithm');
      assert.strictEqual(generated.reason, 'algorithm_not_qualified');
    }
  });

  test('refuses an unspecified or unrecognized algorithm', async () => {
    for (const algorithm of ['RSA-OAEP-384', 'RSA-OAEP-512', 'not-an-algorithm', '']) {
      const generated = await generateKeyPair({ algorithm });
      assert.strictEqual(generated.ok, false, algorithm);
      assert.strictEqual(generated.category, 'unsupported_algorithm');
    }
  });

  test('refuses a symmetric algorithm when a key pair is requested', async () => {
    for (const algorithm of ['HS256', 'HS512', 'A128KW', 'A256GCMKW', 'dir']) {
      const generated = await generateKeyPair({ algorithm, contentAlgorithms: ['A128GCM'] });
      assert.strictEqual(generated.ok, false, algorithm);
      assert.strictEqual(generated.category, 'incompatible_key');
      assert.strictEqual(generated.reason, 'algorithm_requires_a_secret_not_a_key_pair');
    }
  });

  test('refuses an asymmetric algorithm when a secret is requested', () => {
    for (const algorithm of ['ES256', 'RS256', 'PS512', 'RSA-OAEP-256', 'ECDH-ES']) {
      const generated = generateSecret({ algorithm, contentAlgorithms: ['A128GCM'] });
      assert.strictEqual(generated.ok, false, algorithm);
      assert.strictEqual(generated.category, 'incompatible_key');
      assert.strictEqual(generated.reason, 'algorithm_requires_a_key_pair_not_a_secret');
    }
  });

  test('refuses a curve the algorithm does not fix or permit', async () => {
    // An ECDSA identifier names its own curve, so a conflicting one is a
    // contradiction rather than a preference.
    const conflicting = await generateKeyPair({ algorithm: 'ES256', curve: 'P-384' });
    assert.strictEqual(conflicting.ok, false);
    assert.strictEqual(conflicting.category, 'incompatible_key');
    assert.strictEqual(conflicting.reason, 'curve_not_eligible_for_algorithm');

    const missing = await generateKeyPair({ algorithm: 'ECDH-ES', contentAlgorithms: ['A128GCM'] });
    assert.strictEqual(missing.ok, false);
    assert.strictEqual(missing.reason, 'curve_required_for_agreement_algorithm');

    const unsupported = await generateKeyPair({
      algorithm: 'ECDH-ES',
      curve: 'secp256k1',
      contentAlgorithms: ['A128GCM'],
    });
    assert.strictEqual(unsupported.ok, false);
    assert.strictEqual(unsupported.reason, 'curve_not_eligible_for_algorithm');
  });

  test('requires a content binding for every key-management algorithm', async () => {
    const pair = await generateKeyPair({ algorithm: 'RSA-OAEP-256' });
    assert.strictEqual(pair.ok, false);
    assert.strictEqual(pair.category, 'policy_violation');
    assert.strictEqual(pair.reason, 'content_algorithms_required');

    const secret = generateSecret({ algorithm: 'A128KW' });
    assert.strictEqual(secret.ok, false);
    assert.strictEqual(secret.reason, 'content_algorithms_required');
  });

  test('requires exactly one content algorithm for `dir`', () => {
    for (const contentAlgorithms of [undefined, [], ['A128GCM', 'A256GCM']]) {
      const generated = generateSecret({ algorithm: 'dir', ...(contentAlgorithms && { contentAlgorithms }) });
      assert.strictEqual(generated.ok, false, String(contentAlgorithms));
      assert.strictEqual(generated.reason, 'direct_requires_one_content_algorithm');
    }
  });

  test('refuses an unqualified or unsupported content algorithm', () => {
    const unsupported = generateSecret({ algorithm: 'dir', contentAlgorithms: ['A128CBC'] });
    assert.strictEqual(unsupported.ok, false);
    assert.strictEqual(unsupported.category, 'unsupported_algorithm');
    assert.strictEqual(unsupported.reason, 'content_algorithm_unsupported');

    const wrapped = generateSecret({ algorithm: 'A128KW', contentAlgorithms: ['not-an-enc'] });
    assert.strictEqual(wrapped.ok, false);
    assert.strictEqual(wrapped.category, 'unsupported_algorithm');
  });

  test('rejects limits that were never lowered from the baseline', async () => {
    const inflated = { ...LIMITS_V1, rsaModulusBits: LIMITS_V1.rsaModulusBits + 1 };

    const pair = await generateKeyPair({ algorithm: 'ES256', limits: inflated });
    assert.strictEqual(pair.ok, false);
    assert.strictEqual(pair.category, 'policy_violation');
    assert.strictEqual(pair.reason, 'limit_rsaModulusBits_exceeds_baseline');

    const secret = generateSecret({ algorithm: 'HS256', limits: inflated });
    assert.strictEqual(secret.ok, false);
    assert.strictEqual(secret.category, 'policy_violation');
  });
});
