/**
 * RSASSA-PSS signatures for JWS.
 *
 * The salt length is set explicitly to the digest size on both signing and
 * verification. No automatic salt mode is used: such a mode accepts the correct
 * length but also others, so a signature made with a shorter salt than this
 * policy permits would verify under it. MGF1 uses the same hash as the message
 * digest, which the algorithm identifier fixes and WebCrypto ties together.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, attemptVerify, importJwk } from '../../internal/crypto/webcrypto.ts';
import { rsaJwk, rsaPublicJwk, type RsaJwkParameters } from './rsa-common.ts';

interface PssParameters {
  readonly hash: string;
  /** Salt length equals the digest size, which the identifier fixes. */
  readonly saltBytes: number;
}

const PSS_ALGORITHMS: Readonly<Record<string, PssParameters>> = Object.freeze({
  PS256: { hash: 'SHA-256', saltBytes: 32 },
  PS384: { hash: 'SHA-384', saltBytes: 48 },
  PS512: { hash: 'SHA-512', saltBytes: 64 },
});

export async function signRsaPss(
  algorithm: string,
  privateJwk: RsaJwkParameters,
  signingInput: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const parameters = PSS_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }

  const result = await attempt(async () => {
    const key = await importJwk(rsaJwk(privateJwk), { name: 'RSA-PSS', hash: parameters.hash }, ['sign']);
    return crypto.subtle.sign({ name: 'RSA-PSS', saltLength: parameters.saltBytes }, key, toBufferSource(signingInput));
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}

export async function verifyRsaPss(
  algorithm: string,
  publicJwk: RsaJwkParameters,
  signingInput: Uint8Array,
  signature: Uint8Array,
): Promise<BackendResult<boolean>> {
  const parameters = PSS_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }

  return attemptVerify(async () => {
    const key = await importJwk(rsaPublicJwk(publicJwk), { name: 'RSA-PSS', hash: parameters.hash }, ['verify']);
    // Fixing the length here is what rejects an otherwise valid signature that
    // used a salt this policy does not permit.
    return crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: parameters.saltBytes },
      key,
      toBufferSource(signature),
      toBufferSource(signingInput),
    );
  });
}
