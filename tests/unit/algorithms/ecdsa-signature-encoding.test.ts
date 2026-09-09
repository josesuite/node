/**
 * JOSE fixes one ECDSA signature encoding: fixed-width unsigned `R || S`.
 *
 * ASN.1 DER is what general-purpose signing tools emit, so accepting it would
 * make the accepted signature set depend on the backend rather than on the
 * specification.
 */

import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';

import { ecdsaSignatureBytes, verifyEcdsa } from '../../../src/algorithms/jws/ecdsa.ts';
import { availableCurves } from '../../helpers/runtime.ts';

const SIGNING_INPUT = new TextEncoder().encode('signing input');

const CURVES: Readonly<Record<string, { algorithm: string; hash: string }>> = {
  'P-256': { algorithm: 'ES256', hash: 'sha256' },
  'P-384': { algorithm: 'ES384', hash: 'sha384' },
  'P-521': { algorithm: 'ES512', hash: 'sha512' },
};

function keyPair(curve: string) {
  const generated = generateKeyPairSync('ec', { namedCurve: curve });
  const jwk = generated.publicKey.export({ format: 'jwk' }) as { crv: string; x: string; y: string };
  return {
    privateKey: generated.privateKey,
    publicJwk: {
      crv: jwk.crv,
      x: Buffer.from(jwk.x, 'base64url'),
      y: Buffer.from(jwk.y, 'base64url'),
    },
  };
}

describe('ECDSA accepts only fixed-width R || S', () => {
  for (const curve of availableCurves(Object.keys(CURVES))) {
    const { algorithm, hash } = CURVES[curve]!;

    test(`${algorithm} rejects a DER-encoded signature over the same input`, async () => {
      const { privateKey, publicJwk } = keyPair(curve);
      const der = new Uint8Array(nodeSign(hash, SIGNING_INPUT, { key: privateKey, dsaEncoding: 'der' }));
      expect(der.length).not.toBe(ecdsaSignatureBytes(algorithm));

      const result = await verifyEcdsa(algorithm, publicJwk, SIGNING_INPUT, der);

      // A rejection rather than a backend failure: the key and provider are
      // usable and only the signature is unacceptable.
      expect(result).toEqual({ ok: true, value: false });
    });

    test(`${algorithm} rejects a signature padded or truncated to another width`, async () => {
      const { privateKey, publicJwk } = keyPair(curve);
      const raw = new Uint8Array(nodeSign(hash, SIGNING_INPUT, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
      const width = ecdsaSignatureBytes(algorithm)!;
      expect(raw.length).toBe(width);

      // Leading zeros are significant at a fixed width, so a widened signature
      // denotes different scalars rather than the same ones.
      const padded = new Uint8Array(width + 2);
      padded.set(raw, 2);

      for (const candidate of [padded, raw.subarray(0, width - 1), raw.subarray(1)]) {
        expect(await verifyEcdsa(algorithm, publicJwk, SIGNING_INPUT, candidate)).toEqual({ ok: true, value: false });
      }
    });

    test(`${algorithm} rejects a zero R or S rather than deferring to the provider`, async () => {
      // Both scalars are outside the valid range, and some providers accept them.
      const { privateKey, publicJwk } = keyPair(curve);
      const raw = new Uint8Array(nodeSign(hash, SIGNING_INPUT, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
      const half = raw.length / 2;

      const zeroR = new Uint8Array(raw);
      zeroR.fill(0, 0, half);
      const zeroS = new Uint8Array(raw);
      zeroS.fill(0, half);

      for (const candidate of [zeroR, zeroS, new Uint8Array(raw.length)]) {
        expect(await verifyEcdsa(algorithm, publicJwk, SIGNING_INPUT, candidate)).toEqual({ ok: true, value: false });
      }
    });

    test(`${algorithm} accepts the fixed-width signature under the same conditions`, async () => {
      const { privateKey, publicJwk } = keyPair(curve);
      const raw = new Uint8Array(nodeSign(hash, SIGNING_INPUT, { key: privateKey, dsaEncoding: 'ieee-p1363' }));

      expect(await verifyEcdsa(algorithm, publicJwk, SIGNING_INPUT, raw)).toEqual({ ok: true, value: true });
    });
  }
});
