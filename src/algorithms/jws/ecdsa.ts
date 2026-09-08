/**
 * ECDSA signatures for JWS.
 *
 * JOSE signatures are fixed-width unsigned `R || S`, never ASN.1 DER. WebCrypto
 * produces and consumes exactly that form, so there is no encoding conversion
 * step in this path at all.
 *
 * secp256k1 is absent from at least one supported runtime's WebCrypto, so that
 * curve alone falls back to the native module, which is asked for the same
 * fixed-width form directly. The curve is optional and off by default.
 *
 * Mathematically valid high-`S` signatures are accepted. Low-`S` enforcement is
 * a separate policy and is deliberately not applied here, because rejecting high-`S` by
 * default would refuse signatures other conforming implementations produce.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, attemptVerify, base64url, importJwk } from '../../internal/crypto/webcrypto.ts';

interface EcdsaParameters {
  readonly hash: string;
  readonly curve: string;
  /** Width of each of R and S; the signature is twice this. */
  readonly componentBytes: number;
  /** True when this curve must use the native module rather than WebCrypto. */
  readonly nativeOnly: boolean;
}

const ECDSA_ALGORITHMS: Readonly<Record<string, EcdsaParameters>> = Object.freeze({
  ES256: { hash: 'SHA-256', curve: 'P-256', componentBytes: 32, nativeOnly: false },
  ES384: { hash: 'SHA-384', curve: 'P-384', componentBytes: 48, nativeOnly: false },
  ES512: { hash: 'SHA-512', curve: 'P-521', componentBytes: 66, nativeOnly: false },
  ES256K: { hash: 'SHA-256', curve: 'secp256k1', componentBytes: 32, nativeOnly: true },
});

/** Native digest names, needed only for the fallback curve. */
const NATIVE_HASHES: Readonly<Record<string, string>> = Object.freeze({
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
});

export function ecdsaSignatureBytes(algorithm: string): number | undefined {
  const parameters = ECDSA_ALGORITHMS[algorithm];
  return parameters === undefined ? undefined : parameters.componentBytes * 2;
}

/** The curve an algorithm fixes. The identifier alone determines it. */
export function ecdsaCurve(algorithm: string): string | undefined {
  return ECDSA_ALGORITHMS[algorithm]?.curve;
}

export async function signEcdsa(
  algorithm: string,
  privateJwk: { crv: string; x: Uint8Array; y: Uint8Array; d: Uint8Array },
  signingInput: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const parameters = ECDSA_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }

  // The algorithm fixes the curve, so a key on a different curve is never
  // silently accepted by inferring the curve from the key instead.
  if (privateJwk.crv !== parameters.curve) {
    return backendError('operation_failed');
  }

  const jwk = {
    kty: 'EC',
    crv: privateJwk.crv,
    x: base64url(privateJwk.x),
    y: base64url(privateJwk.y),
    d: base64url(privateJwk.d),
  };

  const signature = parameters.nativeOnly
    ? signNative(parameters, jwk, signingInput)
    : await attempt(async () => {
        const key = await importJwk(jwk, { name: 'ECDSA', namedCurve: parameters.curve }, ['sign']);
        return crypto.subtle.sign({ name: 'ECDSA', hash: parameters.hash }, key, toBufferSource(signingInput));
      });

  if (!signature.ok) {
    return signature;
  }

  const bytes = new Uint8Array(signature.value);
  // A differently sized result would mean the provider used another encoding.
  if (bytes.length !== parameters.componentBytes * 2) {
    return backendError('operation_failed');
  }

  return backendOk(bytes);
}

export async function verifyEcdsa(
  algorithm: string,
  publicJwk: { crv: string; x: Uint8Array; y: Uint8Array },
  signingInput: Uint8Array,
  signature: Uint8Array,
): Promise<BackendResult<boolean>> {
  const parameters = ECDSA_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }
  if (publicJwk.crv !== parameters.curve) {
    return backendError('operation_failed');
  }

  // Length is public, so checking it before any cryptographic work leaks
  // nothing and rejects malformed input cheaply.
  if (signature.length !== parameters.componentBytes * 2) {
    return backendOk(false);
  }

  // A zero R or S is outside the valid scalar range. Some providers accept
  // such a signature, so the range is checked here rather than assumed.
  const half = parameters.componentBytes;
  if (isAllZero(signature.subarray(0, half)) || isAllZero(signature.subarray(half))) {
    return backendOk(false);
  }

  const jwk = { kty: 'EC', crv: publicJwk.crv, x: base64url(publicJwk.x), y: base64url(publicJwk.y) };

  if (parameters.nativeOnly) {
    return verifyNative(parameters, jwk, signingInput, signature);
  }

  // Importing the key is an operational step, not a cryptographic outcome: a
  // rejection here means the key or the provider is unusable, which must not be
  // reported as a signature that did not verify.
  const key = await attempt(() => importJwk(jwk, { name: 'ECDSA', namedCurve: parameters.curve }, ['verify']));
  if (!key.ok) {
    return key;
  }

  return attemptVerify(() =>
    crypto.subtle.verify(
      { name: 'ECDSA', hash: parameters.hash },
      key.value,
      toBufferSource(signature),
      toBufferSource(signingInput),
    ),
  );
}

/**
 * Signs with the native module for the one curve WebCrypto does not carry.
 *
 * `ieee-p1363` asks for the fixed-width form directly, so the DER encoding the
 * module would otherwise produce never appears.
 */
function signNative(
  parameters: EcdsaParameters,
  jwk: Record<string, string>,
  signingInput: Uint8Array,
): BackendResult<Uint8Array> {
  const hash = NATIVE_HASHES[parameters.hash];
  if (hash === undefined) {
    return backendError('unsupported');
  }

  try {
    const key = createPrivateKey({ key: jwk, format: 'jwk' });
    return backendOk(new Uint8Array(nodeSign(hash, signingInput, { key, dsaEncoding: 'ieee-p1363' })));
  } catch {
    return backendError('operation_failed');
  }
}

function verifyNative(
  parameters: EcdsaParameters,
  jwk: Record<string, string>,
  signingInput: Uint8Array,
  signature: Uint8Array,
): BackendResult<boolean> {
  const hash = NATIVE_HASHES[parameters.hash];
  if (hash === undefined) {
    return backendError('unsupported');
  }

  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    return backendOk(nodeVerify(hash, signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature));
  } catch {
    // A provider rejection here is a failed verification, never an error that
    // could be mistaken for success.
    return backendOk(false);
  }
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}
