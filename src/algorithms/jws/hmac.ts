/**
 * HMAC signatures for JWS.
 *
 * The MAC is the full hash output; JWS does not truncate it, unlike the
 * deliberately truncated HMAC inside the CBC-HMAC content construction. Keys
 * must be at least the hash output size, though that is a necessary bound and
 * never evidence of entropy: a long but guessable secret passes it, so where
 * the key came from is what actually matters.
 *
 * The MAC is computed synchronously through `node:crypto`. HMAC over a
 * signing input completes in a few microseconds, well below the fixed cost of
 * an asynchronous provider dispatch, so keeping it on the calling thread is
 * the faster choice on every supported runtime and does not measurably block
 * the event loop.
 */

import { createHmac } from 'node:crypto';

import { ownedBytes } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { constantTime } from '../../internal/crypto/constant-time.ts';
import { secretKeyCached } from '../../internal/crypto/node.ts';

interface HmacParameters {
  /** Native digest name. */
  readonly hash: string;
  /** Full output size, which is also the minimum key size. */
  readonly outputBytes: number;
}

const HMAC_ALGORITHMS: Readonly<Record<string, HmacParameters>> = Object.freeze({
  HS256: { hash: 'sha256', outputBytes: 32 },
  HS384: { hash: 'sha384', outputBytes: 48 },
  HS512: { hash: 'sha512', outputBytes: 64 },
});

export function hmacOutputBytes(algorithm: string): number | undefined {
  return HMAC_ALGORITHMS[algorithm]?.outputBytes;
}

export async function computeHmac(
  algorithm: string,
  key: Uint8Array,
  signingInput: Uint8Array,
  handleToken?: object,
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

  try {
    const handle = secretKeyCached(handleToken, key);
    // Exposed as a plain array over the digest's own backing store. The MAC is
    // consumed by native comparison and encoding routines, which read an
    // external backing store directly.
    return backendOk(ownedBytes(createHmac(parameters.hash, handle).update(signingInput).digest()));
  } catch {
    return backendError('operation_failed');
  }
}

/**
 * Verifies a MAC.
 *
 * The comparison is constant-time and done here rather than through the
 * provider's own verify, so the timing behaviour is the one this library
 * qualified. The public length check happens first: a wrong-length signature is
 * a structural defect that reveals nothing secret, whereas comparing contents
 * byte by byte would let an attacker recover a valid MAC one octet at a time.
 */
export async function verifyHmac(
  algorithm: string,
  key: Uint8Array,
  signingInput: Uint8Array,
  signature: Uint8Array,
  handleToken?: object,
): Promise<BackendResult<boolean>> {
  const parameters = HMAC_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }

  // JWS carries the complete MAC; a truncated one is not a valid signature.
  if (signature.length !== parameters.outputBytes) {
    return backendOk(false);
  }

  const expected = await computeHmac(algorithm, key, signingInput, handleToken);
  if (!expected.ok) {
    return expected;
  }

  try {
    return backendOk(constantTime.equal(expected.value, signature));
  } finally {
    // The expected MAC is derived from the key and is not needed afterwards.
    expected.value.fill(0);
  }
}
