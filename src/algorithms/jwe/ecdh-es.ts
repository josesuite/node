/**
 * ECDH-ES key agreement.
 *
 * The sender generates a fresh ephemeral key pair for every agreement and
 * publishes only its public half as `epk`. Reusing an ephemeral key across
 * messages would derive the same CEK for each, collapsing them into one key and
 * defeating the point of the ephemeral half.
 *
 * The shared secret is the curve's fixed-width X coordinate, including leading
 * zero bytes. This is the raw agreement output and is never used as a key
 * directly; it goes through the KDF, which is what binds the derived key to the
 * algorithm and the party information.
 *
 * WebCrypto is used for every curve it carries. It rejects a private JWK whose
 * public point does not match the private scalar, which the native module
 * accepts, so importing through it removes a mismatched-pair case rather than
 * relying on a separate check. X448 is absent from at least one supported
 * runtime, so that curve alone falls back to the native module.
 *
 * Ephemeral-static agreement gives no forward secrecy: an attacker who records
 * the object and later obtains the recipient's static private key recovers the
 * plaintext.
 */

import { generateKeyPairSync } from 'node:crypto';

import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, base64url } from '../../internal/crypto/webcrypto.ts';

const EC_CURVES: ReadonlySet<string> = new Set(['P-256', 'P-384', 'P-521']);
const XDH_CURVES: ReadonlySet<string> = new Set(['X25519', 'X448']);

/** Curves absent from at least one supported runtime's WebCrypto. */
const NATIVE_ONLY_CURVES: ReadonlySet<string> = new Set(['X448']);

/** Field width in bytes for each supported agreement curve. */
const FIELD_BYTES: Readonly<Record<string, number>> = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  X25519: 32,
  X448: 56,
});

export function agreementFieldBytes(curve: string): number | undefined {
  return FIELD_BYTES[curve];
}

/** Whether a key's curve can be used for agreement at all. */
export function isAgreementCurve(curve: string): boolean {
  return EC_CURVES.has(curve) || XDH_CURVES.has(curve);
}

export interface EphemeralEcKey {
  readonly curve: string;
  readonly x: Uint8Array;
  readonly y: Uint8Array;
  readonly d: Uint8Array;
}

export interface EphemeralOkpKey {
  readonly curve: string;
  readonly x: Uint8Array;
  readonly d: Uint8Array;
}

export async function generateEphemeralEc(curve: string): Promise<BackendResult<EphemeralEcKey>> {
  if (!EC_CURVES.has(curve)) {
    return backendError('unsupported');
  }

  const result = await attempt(async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits']);
    return crypto.subtle.exportKey('jwk', pair.privateKey);
  });

  if (!result.ok) {
    return result;
  }

  const jwk = result.value;
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || typeof jwk.d !== 'string') {
    return backendError('operation_failed');
  }

  return backendOk({
    curve,
    x: decode(jwk.x),
    y: decode(jwk.y),
    d: decode(jwk.d),
  });
}

export async function generateEphemeralOkp(curve: string): Promise<BackendResult<EphemeralOkpKey>> {
  if (!XDH_CURVES.has(curve)) {
    return backendError('unsupported');
  }

  if (NATIVE_ONLY_CURVES.has(curve)) {
    try {
      const generated = generateKeyPairSync(curve.toLowerCase() as 'x25519');
      const jwk = generated.privateKey.export({ format: 'jwk' });
      if (typeof jwk.x !== 'string' || typeof jwk.d !== 'string') {
        return backendError('operation_failed');
      }
      return backendOk({ curve, x: decode(jwk.x), d: decode(jwk.d) });
    } catch {
      return backendError('operation_failed');
    }
  }

  const result = await attempt(async () => {
    const pair = await crypto.subtle.generateKey(curve, true, ['deriveBits']);
    return crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).privateKey);
  });

  if (!result.ok) {
    return result;
  }

  const jwk = result.value;
  if (typeof jwk.x !== 'string' || typeof jwk.d !== 'string') {
    return backendError('operation_failed');
  }

  return backendOk({ curve, x: decode(jwk.x), d: decode(jwk.d) });
}

function decode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}
