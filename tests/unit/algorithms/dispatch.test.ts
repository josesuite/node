import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { signWithKey, verifyWithKey } from '../../../src/algorithms/index.ts';
import { importKeyBytes, type UsableKey } from '../../../src/key/import.ts';
import { flipBit } from '../../helpers/runtime.ts';

const INPUT = new TextEncoder().encode('signing input');

function imported(jwk: unknown, algorithm: string, operation: 'sign' | 'verify'): UsableKey {
  const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(jwk)), { algorithm, operation });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

describe('signature dispatch', () => {
  test('refuses to sign with a key that carries no private material', async () => {
    // A public key cannot produce a signature; the refusal must come before any
    // provider call rather than surfacing as an opaque backend error.
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const rsa = generateKeyPairSync('rsa', { modulusLength: 3072 }).publicKey.export({ format: 'jwk' });

    for (const [jwk, algorithm] of [
      [ec, 'ES256'],
      [rsa, 'RS256'],
    ] as const) {
      const result = await signWithKey(imported(jwk, algorithm, 'verify'), INPUT);

      assert.deepStrictEqual(result, { ok: false, failure: 'operation_failed' });
    }
  });

  test('refuses a record that key import did not produce', async () => {
    // Dispatch runs on validated material only; a hand-assembled record would
    // otherwise be dispatched on whatever the caller attached.
    const forged = {
      keyType: 'oct',
      algorithm: 'HS256',
      operation: 'sign',
      isPrivate: true,
      material: new Uint8Array(32),
    } as unknown as UsableKey;

    assert.deepStrictEqual(await signWithKey(forged, INPUT), { ok: false, failure: 'operation_failed' });
    assert.deepStrictEqual(await verifyWithKey(forged, INPUT, new Uint8Array(32)), {
      ok: false,
      failure: 'operation_failed',
    });
  });

  test('refuses an identifier outside the signature families', async () => {
    const key = imported({ kty: 'oct', k: Buffer.alloc(32, 1).toString('base64url') }, 'HS256', 'sign');
    const forged = { ...key, algorithm: 'HS999' } as UsableKey;

    // The spread drops the import marker, so this reports as an unusable record
    // rather than reaching family lookup; both are refusals, never a signature.
    assert.strictEqual((await signWithKey(forged, INPUT)).ok, false);
    assert.strictEqual((await verifyWithKey(forged, INPUT, new Uint8Array(32))).ok, false);
  });

  test('round-trips an HMAC signature and rejects a corrupted one', async () => {
    const jwk = { kty: 'oct', k: Buffer.alloc(32, 7).toString('base64url') };
    const signing = imported(jwk, 'HS256', 'sign');
    const verification = imported(jwk, 'HS256', 'verify');

    const signed = await signWithKey(signing, INPUT);
    assert.strictEqual(signed.ok, true);
    if (!signed.ok) {
      return;
    }

    assert.deepStrictEqual(await verifyWithKey(verification, INPUT, signed.value), { ok: true, value: true });

    assert.deepStrictEqual(await verifyWithKey(verification, INPUT, flipBit(signed.value)), {
      ok: true,
      value: false,
    });

    // A signature over different bytes must not verify, which is what binds the
    // signature to its exact input.
    assert.deepStrictEqual(await verifyWithKey(verification, new TextEncoder().encode('other'), signed.value), {
      ok: true,
      value: false,
    });
  });

  test('reports a wrong signature as a rejection rather than a backend failure', async () => {
    // Collapsing the two would let a provider outage read as a forgery, or a
    // forgery read as an outage.
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const signing = imported(pair.privateKey.export({ format: 'jwk' }), 'ES256', 'sign');
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const wrongKey = imported(other.publicKey.export({ format: 'jwk' }), 'ES256', 'verify');

    const signed = await signWithKey(signing, INPUT);
    assert.strictEqual(signed.ok, true);
    if (!signed.ok) {
      return;
    }

    assert.deepStrictEqual(await verifyWithKey(wrongKey, INPUT, signed.value), { ok: true, value: false });
  });

  test('does not admit the deprecated EdDSA identifier at import', async () => {
    // The curves that identifier could name are unqualified, so no key ever
    // reaches dispatch bound to it and no curve can be inferred at verification.
    const okp = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });

    for (const algorithm of ['EdDSA', 'Ed25519']) {
      const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(okp)), { algorithm, operation: 'verify' });

      assert.strictEqual(result.ok, false);
    }
  });
});
