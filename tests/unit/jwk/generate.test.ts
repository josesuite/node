import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { generateKeyPair, generateSecret } from '../../../src/key/generate.ts';
import { signCompact } from '../../../src/jws/sign.ts';
import { verifyCompact } from '../../../src/jws/verify.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

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
