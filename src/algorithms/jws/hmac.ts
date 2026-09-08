/**
 * HMAC signatures for JWS.
 *
 * The MAC is the full hash output; JWS does not truncate it, unlike the
 * deliberately truncated HMAC inside the CBC-HMAC content construction. Keys
 * must be at least the hash output size, though that is a necessary bound and
 * never evidence of entropy: a long but guessable secret passes it, so where
 * the key came from is what actually matters.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importRaw } from '../../internal/crypto/webcrypto.ts';

interface HmacParameters {
  readonly hash: string;
  /** Full output size, which is also the minimum key size. */
  readonly outputBytes: number;
}

const HMAC_ALGORITHMS: Readonly<Record<string, HmacParameters>> = Object.freeze({
  HS256: { hash: 'SHA-256', outputBytes: 32 },
  HS384: { hash: 'SHA-384', outputBytes: 48 },
  HS512: { hash: 'SHA-512', outputBytes: 64 },
});

export function hmacOutputBytes(algorithm: string): number | undefined {
  return HMAC_ALGORITHMS[algorithm]?.outputBytes;
}

export async function computeHmac(
  algorithm: string,
  key: Uint8Array,
  signingInput: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const parameters = HMAC_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }

  // A key shorter than the hash output weakens the MAC below the strength the
  // algorithm name implies, so it is refused rather than padded. The provider
  // accepts short keys, so this bound is enforced here.
  if (key.length < parameters.outputBytes) {
    return backendError('operation_failed');
  }

  const result = await attempt(async () => {
    const handle = await importRaw(key, { name: 'HMAC', hash: parameters.hash }, ['sign']);
    return crypto.subtle.sign('HMAC', handle, toBufferSource(signingInput));
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}
