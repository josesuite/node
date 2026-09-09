import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, test } from 'node:test';

import { eddsaParameters, signEddsa, verifyEddsa } from '../../../src/algorithms/jws/eddsa.ts';

const bytes = (value: unknown): Uint8Array => new Uint8Array(Buffer.from(String(value), 'base64url'));
const message = new TextEncoder().encode('eddsa coverage');

describe('EdDSA backend adapters', () => {
  test('resolves curve-specific and legacy identifiers', () => {
    assert.strictEqual(eddsaParameters('unknown'), undefined);
    assert.strictEqual(eddsaParameters('EdDSA'), undefined);
    assert.strictEqual(eddsaParameters('EdDSA', 'unknown'), undefined);
    assert.strictEqual(eddsaParameters('EdDSA', 'Ed25519')?.curve, 'Ed25519');
    assert.strictEqual(eddsaParameters('Ed25519')?.signatureBytes, 64);
    assert.strictEqual(eddsaParameters('Ed448')?.signatureBytes, 114);
  });

  for (const [algorithm, nativeOnly] of [
    ['Ed25519', false],
    ['Ed448', true],
  ] as const) {
    test(`${algorithm} signs and verifies`, async () => {
      const parameters = eddsaParameters(algorithm)!;
      assert.strictEqual(parameters.nativeOnly, nativeOnly);

      const pair = generateKeyPairSync(algorithm.toLowerCase() as 'ed25519');
      const privateJwk = pair.privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const publicJwk = pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const privateKey = { x: bytes(privateJwk['x']), d: bytes(privateJwk['d']) };
      const publicKey = { x: bytes(publicJwk['x']) };

      const signed = await signEddsa(parameters, privateKey, message);
      assert.strictEqual(signed.ok, true);
      if (!signed.ok) {
        return;
      }
      assert.strictEqual(signed.value.length, parameters.signatureBytes);

      const verified = await verifyEddsa(parameters, publicKey, message, signed.value);
      assert.deepStrictEqual(verified, { ok: true, value: true });

      const tampered = new Uint8Array(signed.value);
      tampered[0] = tampered[0]! ^ 1;
      const rejected = await verifyEddsa(parameters, publicKey, message, tampered);
      assert.deepStrictEqual(rejected, { ok: true, value: false });

      const wrongLength = await verifyEddsa(
        parameters,
        publicKey,
        message,
        new Uint8Array(parameters.signatureBytes - 1),
      );
      assert.deepStrictEqual(wrongLength, { ok: true, value: false });
    });
  }

  test('returns backend failures for malformed keys', async () => {
    const webCrypto = eddsaParameters('Ed25519')!;
    const native = eddsaParameters('Ed448')!;

    const webSign = await signEddsa(webCrypto, { x: new Uint8Array(32), d: new Uint8Array(1) }, message);
    assert.deepStrictEqual(webSign, { ok: false, failure: 'operation_failed' });

    const webVerify = await verifyEddsa(webCrypto, { x: new Uint8Array(1) }, message, new Uint8Array(64));
    assert.deepStrictEqual(webVerify, { ok: false, failure: 'operation_failed' });

    const nativeSign = await signEddsa(native, { x: new Uint8Array(57), d: new Uint8Array(1) }, message);
    assert.deepStrictEqual(nativeSign, { ok: false, failure: 'operation_failed' });

    const nativeVerify = await verifyEddsa(native, { x: new Uint8Array(1) }, message, new Uint8Array(114));
    assert.deepStrictEqual(nativeVerify, { ok: true, value: false });
  });
});
