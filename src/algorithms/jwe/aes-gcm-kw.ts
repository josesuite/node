/**
 * AES-GCM key wrapping.
 *
 * The CEK is wrapped under AES-GCM with a 12-octet wrapping IV, a 16-octet
 * wrapping tag, and **empty** wrapping additional data. The empty AAD is part
 * of the construction: substituting the protected header here would produce
 * wrapped keys no other implementation could unwrap.
 *
 * The wrapping IV and tag travel as header parameters and are entirely distinct
 * from the content IV and tag. They are also accounted separately: the wrapping
 * key and the content key are different keys, so a nonce may legitimately
 * repeat across the two while never repeating under either one. Sharing one
 * counter between them would be an accounting error in the safe direction but
 * would still misreport how much of each key's budget remains.
 *
 * GCM nonce reuse under one key is catastrophic. It leaks the plaintext
 * difference and the authentication subkey, so a wrapping nonce comes from the
 * caller's durable allocator, exactly as a content nonce does.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importRaw } from '../../internal/crypto/webcrypto.ts';

export const GCMKW_IV_BYTES = 12;
export const GCMKW_TAG_BYTES = 16;

const KEK_SIZES: Readonly<Record<string, number>> = Object.freeze({
  A128GCMKW: 16,
  A192GCMKW: 24,
  A256GCMKW: 32,
});

/** KEK size the identifier requires, or `undefined` when it names no wrapping. */
export function gcmKwKeySize(algorithm: string): number | undefined {
  return KEK_SIZES[algorithm];
}

export interface GcmKwWrapped {
  readonly encryptedKey: Uint8Array;
  /** Wrapping IV for the header `iv` parameter. */
  readonly iv: Uint8Array;
  /** Wrapping tag for the header `tag` parameter. */
  readonly tag: Uint8Array;
}

/**
 * Wraps a CEK under the key-encryption key.
 *
 * The IV is supplied rather than generated here so that its uniqueness is
 * enforced by durable state the caller owns; generating one locally would put
 * the guarantee out of reach of the allocator that is supposed to provide it.
 */
export async function wrapGcmKw(
  algorithm: string,
  kek: Uint8Array,
  iv: Uint8Array,
  cek: Uint8Array,
): Promise<BackendResult<GcmKwWrapped>> {
  const kekBytes = gcmKwKeySize(algorithm);
  if (kekBytes === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== kekBytes || iv.length !== GCMKW_IV_BYTES) {
    return backendError('operation_failed');
  }

  const result = await attempt(async () => {
    const handle = await importRaw(kek, { name: 'AES-GCM', length: kekBytes * 8 }, ['encrypt']);
    // No additional data: the construction authenticates the CEK alone.
    return crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: GCMKW_TAG_BYTES * 8 },
      handle,
      toBufferSource(cek),
    );
  });

  if (!result.ok) {
    return result;
  }

  // The provider appends the tag; JOSE carries the two separately.
  const combined = new Uint8Array(result.value);
  if (combined.length !== cek.length + GCMKW_TAG_BYTES) {
    return backendError('operation_failed');
  }

  return backendOk({
    encryptedKey: combined.subarray(0, cek.length),
    iv,
    tag: combined.subarray(cek.length),
  });
}
