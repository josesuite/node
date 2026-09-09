/**
 * A rejected signature and an unusable provider are different outcomes.
 *
 * Verification adapters import a key before performing the operation. Only the
 * operation has a cryptographic outcome: if an import failure were reported as
 * `false`, an outage or a malformed key would be indistinguishable from a
 * forgery, and an operator would read one as the other.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { verifyEcdsa } from '../../../src/algorithms/jws/ecdsa.ts';
import { verifyRsaPkcs1 } from '../../../src/algorithms/jws/rsassa-pkcs1-v1_5.ts';
import { verifyRsaPss } from '../../../src/algorithms/jws/rsassa-pss.ts';

const SIGNING_INPUT = new TextEncoder().encode('signing input');

function rsaPublicParameters() {
  const jwk = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' }) as {
    n: string;
    e: string;
  };
  return { n: Buffer.from(jwk.n, 'base64url'), e: Buffer.from(jwk.e, 'base64url') };
}

/** Whether this runtime's provider admits a degenerate zero-length RSA modulus at import. */
async function importsZeroLengthRsaModulus(): Promise<boolean> {
  try {
    await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: '', e: 'AQAB' },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return true;
  } catch {
    return false;
  }
}

describe('CRYPTO-08 verification distinguishes rejection from provider failure', () => {
  test('a valid key with a wrong signature is a rejection, not a backend failure', async () => {
    const { n, e } = rsaPublicParameters();
    const result = await verifyRsaPkcs1('RS256', { n, e }, SIGNING_INPUT, new Uint8Array(256));

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value, false);
    }
  });

  test('an unimportable RSA key is a backend failure, not a rejected signature', async (t) => {
    // An empty modulus is refused at import by providers that validate it.
    // Without separating import from verification this returned
    // `ok: true, value: false`, reporting an unusable key as a signature that
    // did not verify. Providers differ on whether they reject this key at all:
    // Node's accepts a zero-length modulus and defers to verification, so the
    // precondition is checked rather than assumed.
    const unusable = { n: new Uint8Array(0), e: new Uint8Array([1, 0, 1]) };

    if (await importsZeroLengthRsaModulus()) {
      t.skip('provider admits a zero-length RSA modulus, so no import failure arises');
      return;
    }

    for (const [algorithm, verify] of [
      ['RS256', verifyRsaPkcs1],
      ['PS256', verifyRsaPss],
    ] as const) {
      const result = await verify(algorithm, unusable, SIGNING_INPUT, new Uint8Array(256));
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.failure, 'operation_failed');
      }
    }
  });

  test('an unimportable EC key is a backend failure, not a rejected signature', async () => {
    // A point off the curve is rejected at import rather than by verification.
    const offCurve = { crv: 'P-256', x: new Uint8Array(32).fill(9), y: new Uint8Array(32).fill(9) };
    const result = await verifyEcdsa('ES256', offCurve, SIGNING_INPUT, new Uint8Array(64).fill(1));

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'operation_failed');
    }
  });
});
