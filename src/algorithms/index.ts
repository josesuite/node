/**
 * Signature dispatch.
 *
 * Dispatch is driven by the algorithm the caller's policy already approved and
 * the key that trusted configuration already bound, never by a value read out
 * of the received header. A failed verification is never retried under another
 * hash, curve, or key interpretation: doing so would let an attacker pick the
 * check their forgery can pass.
 *
 * The key record is also handed to each adapter as the token under which its
 * provider handle is memoized. That is sound precisely because of the binding
 * above: one record names one algorithm and one operation for its whole
 * lifetime, so the handle derived from it cannot be reused under a second
 * interpretation. The polymorphic EdDSA identifier is no exception, because the
 * curve it resolves to is required to equal the record's own curve.
 */

import { backendError, type BackendResult } from '../internal/crypto/backend.ts';
import { isImportedKey, type UsableKey } from '../key/import.ts';
import { eddsaParameters, signEddsa, verifyEddsa } from './jws/eddsa.ts';
import { signEcdsa, verifyEcdsa } from './jws/ecdsa.ts';
import { computeHmac, verifyHmac } from './jws/hmac.ts';
import { signRsaPkcs1, verifyRsaPkcs1 } from './jws/rsassa-pkcs1-v1_5.ts';
import { signRsaPss, verifyRsaPss } from './jws/rsassa-pss.ts';

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
      return computeHmac(key.algorithm, key.material, signingInput, key);
    }
    case 'rsa-pkcs1': {
      if (key.keyType !== 'RSA') {
        return backendError('operation_failed');
      }
      return signRsaPkcs1(key.algorithm, key.material, signingInput, key);
    }
    case 'rsa-pss': {
      if (key.keyType !== 'RSA') {
        return backendError('operation_failed');
      }
      return signRsaPss(key.algorithm, key.material, signingInput, key);
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
        key,
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
      return signEddsa(parameters, { x: material.x, d: material.d }, signingInput, key);
    }
  }
}

/**
 * Verifies a signature or MAC against the exact signing input.
 *
 * A false result means the signature did not verify. A backend failure is
 * reported separately and never collapses into either outcome, so a provider
 * outage cannot be mistaken for a bad signature or for success.
 */
export async function verifyWithKey(
  key: UsableKey,
  signingInput: Uint8Array,
  signature: Uint8Array,
  options: DispatchOptions = {},
): Promise<BackendResult<boolean>> {
  if (!isImportedKey(key)) {
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
      return verifyHmac(key.algorithm, key.material, signingInput, signature, key);
    }
    case 'rsa-pkcs1': {
      if (key.keyType !== 'RSA') {
        return backendError('operation_failed');
      }
      return verifyRsaPkcs1(key.algorithm, key.material, signingInput, signature, key);
    }
    case 'rsa-pss': {
      if (key.keyType !== 'RSA') {
        return backendError('operation_failed');
      }
      return verifyRsaPss(key.algorithm, key.material, signingInput, signature, key);
    }
    case 'ecdsa': {
      if (key.keyType !== 'EC') {
        return backendError('operation_failed');
      }
      const material = key.material;
      return verifyEcdsa(
        key.algorithm,
        { crv: material.curve, x: material.x, y: material.y },
        signingInput,
        signature,
        key,
      );
    }
    case 'eddsa': {
      if (key.keyType !== 'OKP') {
        return backendError('operation_failed');
      }
      const material = key.material;
      const parameters = eddsaParameters(key.algorithm, options.legacyEddsaCurve);
      if (parameters === undefined) {
        return backendError('unsupported');
      }
      // The bound curve must match the key's own curve; the identifier
      // selects which curve policy applies, never a different key.
      if (parameters.curve !== material.curve) {
        return backendError('operation_failed');
      }
      return verifyEddsa(parameters, { x: material.x }, signingInput, signature, key);
    }
  }
}
