/**
 * Signature dispatch.
 *
 * Dispatch is driven by the algorithm the caller's policy already approved and
 * the key that trusted configuration already bound, never by a value read out
 * of the received header. A failed verification is never retried under another
 * hash, curve, or key interpretation: doing so would let an attacker pick the
 * check their forgery can pass.
 */

import { backendError, type BackendResult } from '../internal/crypto/backend.ts';
import { isImportedKey, type UsableKey } from '../key/import.ts';
import { eddsaParameters, signEddsa } from './jws/eddsa.ts';
import { signEcdsa } from './jws/ecdsa.ts';
import { computeHmac } from './jws/hmac.ts';
import { signRsaPkcs1 } from './jws/rsassa-pkcs1-v1_5.ts';
import { signRsaPss } from './jws/rsassa-pss.ts';

type SignatureFamily = 'hmac' | 'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'eddsa';

const FAMILIES: Readonly<Record<string, SignatureFamily>> = Object.freeze({
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'rsa-pkcs1',
  RS384: 'rsa-pkcs1',
  RS512: 'rsa-pkcs1',
  PS256: 'rsa-pss',
  PS384: 'rsa-pss',
  PS512: 'rsa-pss',
  ES256: 'ecdsa',
  ES384: 'ecdsa',
  ES512: 'ecdsa',
  ES256K: 'ecdsa',
  Ed25519: 'eddsa',
  Ed448: 'eddsa',
  EdDSA: 'eddsa',
});

export interface DispatchOptions {
  /**
   * Curve bound to the deprecated polymorphic identifier by trusted policy.
   * Required for that identifier, since it names no curve itself.
   */
  readonly legacyEddsaCurve?: string | undefined;
}

/**
 * Produces a signature or MAC over the exact signing input.
 *
 * The key's bound algorithm must be the one being used; a key bound to one
 * algorithm is never reused under another, which is what prevents an RSA
 * verification key from being pressed into service as an HMAC secret.
 */
export async function signWithKey(
  key: UsableKey,
  signingInput: Uint8Array,
  options: DispatchOptions = {},
): Promise<BackendResult<Uint8Array>> {
  if (!isImportedKey(key)) {
    return backendError('operation_failed');
  }
  if (!key.isPrivate) {
    return backendError('operation_failed');
  }

  const family = FAMILIES[key.algorithm];
  if (family === undefined) {
    return backendError('unsupported');
  }

  switch (family) {
    case 'hmac': {
      if (key.keyType !== 'oct') {
        return backendError('operation_failed');
      }
      return computeHmac(key.algorithm, key.material, signingInput);
    }
    case 'rsa-pkcs1': {
      if (key.keyType !== 'RSA') {
        return backendError('operation_failed');
      }
      return signRsaPkcs1(key.algorithm, key.material, signingInput);
    }
    case 'rsa-pss': {
      if (key.keyType !== 'RSA') {
        return backendError('operation_failed');
      }
      return signRsaPss(key.algorithm, key.material, signingInput);
    }
    case 'ecdsa': {
      if (key.keyType !== 'EC') {
        return backendError('operation_failed');
      }
      const material = key.material;
      if (material.d === undefined) {
        return backendError('operation_failed');
      }
      return signEcdsa(
        key.algorithm,
        { crv: material.curve, x: material.x, y: material.y, d: material.d },
        signingInput,
      );
    }
    case 'eddsa': {
      if (key.keyType !== 'OKP') {
        return backendError('operation_failed');
      }
      const material = key.material;
      if (material.d === undefined) {
        return backendError('operation_failed');
      }
      const parameters = eddsaParameters(key.algorithm, options.legacyEddsaCurve);
      // The deprecated identifier is receive-only; creation requires a
      // curve-specific one, so no signing path exists without parameters.
      if (parameters === undefined) {
        return backendError('unsupported');
      }
      if (parameters.curve !== material.curve) {
        return backendError('operation_failed');
      }
      return signEddsa(parameters, { x: material.x, d: material.d }, signingInput);
    }
  }
}
