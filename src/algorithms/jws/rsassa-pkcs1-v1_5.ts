/**
 * RSASSA-PKCS1-v1_5 signatures for JWS.
 *
 * This is the RSA signature scheme, which is distinct from the prohibited
 * RSA1_5 *encryption* scheme despite the similar name: the padding-oracle
 * weakness that bars the encryption scheme does not apply to signatures.
 *
 * Signatures are exactly the modulus length. The provider enforces the
 * complete encoding, so abbreviated signatures, trailing bytes, and malformed
 * padding are rejected rather than tolerated.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, attemptVerify, importJwk } from '../../internal/crypto/webcrypto.ts';
import { rsaJwk, rsaPublicJwk, type RsaJwkParameters } from './rsa-common.ts';

const RSA_HASHES: Readonly<Record<string, string>> = Object.freeze({
  RS256: 'SHA-256',
  RS384: 'SHA-384',
  RS512: 'SHA-512',
});

export async function signRsaPkcs1(
  algorithm: string,
  privateJwk: RsaJwkParameters,
  signingInput: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const hash = RSA_HASHES[algorithm];
  if (hash === undefined) {
    return backendError('unsupported');
  }

  const result = await attempt(async () => {
    const key = await importJwk(rsaJwk(privateJwk), { name: 'RSASSA-PKCS1-v1_5', hash }, ['sign']);
    return crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, toBufferSource(signingInput));
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}

export async function verifyRsaPkcs1(
  algorithm: string,
  publicJwk: RsaJwkParameters,
  signingInput: Uint8Array,
  signature: Uint8Array,
): Promise<BackendResult<boolean>> {
  const hash = RSA_HASHES[algorithm];
  if (hash === undefined) {
    return backendError('unsupported');
  }

  return attemptVerify(async () => {
    const key = await importJwk(rsaPublicJwk(publicJwk), { name: 'RSASSA-PKCS1-v1_5', hash }, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, toBufferSource(signature), toBufferSource(signingInput));
  });
}
