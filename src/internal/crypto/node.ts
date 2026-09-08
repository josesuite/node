/**
 * Node provider adapter for the key-validation operations the JOSE layer needs
 * but the provider does not perform on its own.
 *
 * Qualification of this provider established the behaviour these functions
 * compensate for:
 *
 * - Importing an EC private JWK and exporting it again echoes back the supplied
 *   `x` and `y` rather than the point derived from `d`, so a round trip cannot
 *   detect a mismatched public component. Public points are therefore computed
 *   from the private scalar by scalar multiplication instead.
 * - Ed25519 public-key import accepts low-order points, the identity, and
 *   non-canonical encodings, so those are checked before a key is admitted.
 * - X25519 accepts a non-canonical public alias and does not check that a
 *   supplied `x` matches `d`.
 *
 * These checks keep provider assumptions executable, so an upgrade that changes
 * one fails closed instead of silently altering which keys this library accepts.
 */

import { createECDH, createPrivateKey, createPublicKey } from 'node:crypto';

import { backendError, backendOk, type BackendResult } from './backend.ts';

/** JOSE curve names mapped to the provider's own curve identifiers. */
const EC_CURVE_NAMES: Readonly<Record<string, string>> = Object.freeze({
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  secp256k1: 'secp256k1',
});

export interface EcPoint {
  readonly x: Uint8Array;
  readonly y: Uint8Array;
}

/**
 * Computes the public point for an EC private scalar.
 *
 * This uses scalar multiplication against the curve's base point and never
 * consults any supplied public coordinates, which is what lets the caller
 * compare the result against them. Deriving from a signature made under an
 * unchecked supplied public key would not establish the same property, because
 * a mismatched key can still produce a signature.
 */
export function deriveEcPublicPoint(curve: string, privateScalar: Uint8Array): BackendResult<EcPoint> {
  const curveName = EC_CURVE_NAMES[curve];
  if (curveName === undefined) {
    return backendError('unsupported');
  }

  try {
    const agreement = createECDH(curveName);
    // Rejects a zero or out-of-range scalar, so `1 <= d < n` is enforced here
    // rather than by re-deriving the group order in protocol code.
    agreement.setPrivateKey(Buffer.from(privateScalar));

    // Uncompressed SEC1 form: a 0x04 prefix followed by equal-width X and Y.
    const encoded = agreement.getPublicKey();
    if (encoded.length < 3 || encoded[0] !== 0x04) {
      return backendError('operation_failed');
    }

    const width = (encoded.length - 1) / 2;
    if (!Number.isInteger(width)) {
      return backendError('operation_failed');
    }

    return backendOk({
      x: new Uint8Array(encoded.subarray(1, 1 + width)),
      y: new Uint8Array(encoded.subarray(1 + width)),
    });
  } catch {
    return backendError('operation_failed');
  }
}
