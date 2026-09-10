/**
 * Edwards-curve signatures for JWS.
 *
 * These are the pure variants: the message is signed directly, with no prehash
 * and no context string. Signature lengths are exact and checked before any
 * cryptographic work, since both halves are always present and there is no
 * short form.
 *
 * Ed25519 uses WebCrypto. Ed448 is absent from at least one supported runtime's
 * WebCrypto, so it falls back to the native module; the curve is optional and
 * off by default, and the fallback is confined to that branch.
 *
 * Public keys are validated at import rather than here. That placement matters:
 * a low-order key can produce a signature verifying against almost any message,
 * so refusing it at import keeps it away from verification entirely instead of
 * changing which signatures a legitimately imported key accepts. Neither
 * backend rejects such a key on its own.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, attemptVerify, base64url, importCached, importJwk } from '../../internal/crypto/webcrypto.ts';

interface EddsaParameters {
  readonly curve: string;
  readonly signatureBytes: number;
  /** True when this curve must use the native module rather than WebCrypto. */
  readonly nativeOnly: boolean;
}

const EDDSA_CURVES: Readonly<Record<string, EddsaParameters>> = Object.freeze({
  Ed25519: { curve: 'Ed25519', signatureBytes: 64, nativeOnly: false },
  Ed448: { curve: 'Ed448', signatureBytes: 114, nativeOnly: true },
});

/**
 * Resolves the curve an algorithm identifier selects.
 *
 * The deprecated polymorphic identifier names no curve of its own, so trusted
 * key policy must supply it. It is never aliased automatically to a
 * curve-specific identifier, because that would let the token choose which
 * curve policy applies.
 */
export function eddsaParameters(algorithm: string, legacyBoundCurve?: string): EddsaParameters | undefined {
  if (algorithm === 'EdDSA') {
    return legacyBoundCurve === undefined ? undefined : EDDSA_CURVES[legacyBoundCurve];
  }
  return EDDSA_CURVES[algorithm];
}

/**
 * Builds the JWK members for an import.
 *
 * Kept as functions so the Base64url of the key octets is produced only on the
 * call that actually imports, which a cached handle skips entirely.
 */
function okpPrivateJwk(
  parameters: EddsaParameters,
  material: { x: Uint8Array; d: Uint8Array },
): Record<string, string> {
  return { kty: 'OKP', crv: parameters.curve, x: base64url(material.x), d: base64url(material.d) };
}

function okpPublicJwk(parameters: EddsaParameters, material: { x: Uint8Array }): Record<string, string> {
  return { kty: 'OKP', crv: parameters.curve, x: base64url(material.x) };
}

export async function signEddsa(
  parameters: EddsaParameters,
  privateJwk: { x: Uint8Array; d: Uint8Array },
  signingInput: Uint8Array,
  handleToken?: object,
): Promise<BackendResult<Uint8Array>> {
  const signature = parameters.nativeOnly
    ? signNative(okpPrivateJwk(parameters, privateJwk), signingInput)
    : await attempt(async () => {
        const key = await importCached(handleToken, () =>
          importJwk(okpPrivateJwk(parameters, privateJwk), parameters.curve, ['sign']),
        );
        return crypto.subtle.sign(parameters.curve, key, toBufferSource(signingInput));
      });

  if (!signature.ok) {
    return signature;
  }

  const bytes = new Uint8Array(signature.value);
  if (bytes.length !== parameters.signatureBytes) {
    return backendError('operation_failed');
  }

  return backendOk(bytes);
}

export async function verifyEddsa(
  parameters: EddsaParameters,
  publicJwk: { x: Uint8Array },
  signingInput: Uint8Array,
  signature: Uint8Array,
  handleToken?: object,
): Promise<BackendResult<boolean>> {
  // Length is public and fixed, so a wrong-length signature is rejected before
  // the key is even constructed.
  if (signature.length !== parameters.signatureBytes) {
    return backendOk(false);
  }

  if (parameters.nativeOnly) {
    return verifyNative(okpPublicJwk(parameters, publicJwk), signingInput, signature);
  }

  const imported = await attempt(() =>
    importCached(handleToken, () => importJwk(okpPublicJwk(parameters, publicJwk), parameters.curve, ['verify'])),
  );
  return imported.ok
    ? attemptVerify(() =>
        crypto.subtle.verify(parameters.curve, imported.value, toBufferSource(signature), toBufferSource(signingInput)),
      )
    : imported;
}

function signNative(jwk: Record<string, string>, signingInput: Uint8Array): BackendResult<Uint8Array> {
  try {
    const key = createPrivateKey({ key: jwk, format: 'jwk' });
    return backendOk(new Uint8Array(nodeSign(null, signingInput, key)));
  } catch {
    return backendError('operation_failed');
  }
}

function verifyNative(
  jwk: Record<string, string>,
  signingInput: Uint8Array,
  signature: Uint8Array,
): BackendResult<boolean> {
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    return backendOk(nodeVerify(null, signingInput, key, signature));
  } catch {
    return backendOk(false);
  }
}
