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
 *
 * Wrapping runs synchronously through `node:crypto`, as the GCM content
 * encryption does: a 16- to 64-octet wrap completes well below the fixed cost
 * of an asynchronous provider dispatch.
 */

import { type CipherGCMTypes, createCipheriv, createSecretKey } from 'node:crypto';

import { ownedBytes, toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { importRaw } from '../../internal/crypto/webcrypto.ts';

export const GCMKW_IV_BYTES = 12;
export const GCMKW_TAG_BYTES = 16;

interface GcmKwParameters {
  readonly kekBytes: number;
  readonly cipher: CipherGCMTypes;
}

const GCMKW_ALGORITHMS: Readonly<Record<string, GcmKwParameters>> = Object.freeze({
  A128GCMKW: { kekBytes: 16, cipher: 'aes-128-gcm' },
  A192GCMKW: { kekBytes: 24, cipher: 'aes-192-gcm' },
  A256GCMKW: { kekBytes: 32, cipher: 'aes-256-gcm' },
});

/** KEK size the identifier requires, or `undefined` when it names no wrapping. */
export function gcmKwKeySize(algorithm: string): number | undefined {
  return GCMKW_ALGORITHMS[algorithm]?.kekBytes;
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
  const parameters = GCMKW_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== parameters.kekBytes || iv.length !== GCMKW_IV_BYTES) {
    return backendError('operation_failed');
  }

  try {
    // No additional data: the construction authenticates the CEK alone.
    const cipher = createCipheriv(parameters.cipher, createSecretKey(kek), iv, { authTagLength: GCMKW_TAG_BYTES });
    const encryptedKey = cipher.update(cek);
    cipher.final();
    const tag = cipher.getAuthTag();

    if (encryptedKey.length !== cek.length || tag.length !== GCMKW_TAG_BYTES) {
      return backendError('operation_failed');
    }

    return backendOk({ encryptedKey: ownedBytes(encryptedKey), iv, tag: ownedBytes(tag) });
  } catch {
    return backendError('operation_failed');
  }
}

/**
 * Unwraps a CEK, returning `undefined` when the wrapping tag does not verify.
 *
 * A failed tag is an authentication outcome rather than a provider fault, and
 * it is reported identically for a wrong KEK, a modified wrapped key, and a
 * modified wrapping tag so none can be told apart.
 */
export async function unwrapGcmKw(
  algorithm: string,
  kek: Uint8Array,
  iv: Uint8Array,
  encryptedKey: Uint8Array,
  tag: Uint8Array,
): Promise<BackendResult<Uint8Array | undefined>> {
  const kekBytes = gcmKwKeySize(algorithm);
  if (kekBytes === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== kekBytes) {
    return backendError('operation_failed');
  }
  // Both widths are public and fixed, so a wrong width is a malformed object
  // rather than a decryption attempt worth making.
  if (iv.length !== GCMKW_IV_BYTES || tag.length !== GCMKW_TAG_BYTES) {
    return backendOk(undefined);
  }

  const combined = new Uint8Array(encryptedKey.length + tag.length);
  combined.set(encryptedKey);
  combined.set(tag, encryptedKey.length);

  try {
    const handle = await importRaw(kek, { name: 'AES-GCM', length: kekBytes * 8 }, ['decrypt']);
    const cek = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: GCMKW_TAG_BYTES * 8 },
      handle,
      toBufferSource(combined),
    );
    return backendOk(new Uint8Array(cek));
  } catch {
    return backendOk(undefined);
  }
}
