/**
 * AES-GCM content encryption.
 *
 * The tag is always the full 16 bytes. Truncation is not offered at any layer:
 * a shorter tag weakens forgery resistance, and because the tag length would
 * have to be read from somewhere, offering it would let the object influence
 * how strictly it is checked.
 *
 * WebCrypto returns the tag appended to the ciphertext and expects the same on
 * decryption, whereas JWE carries them as separate components. Splitting and
 * rejoining happens here so the rest of the library works in the wire layout.
 *
 * Nonces are supplied by the caller's allocator rather than generated here.
 * GCM fails catastrophically on nonce reuse under one key. Two messages sharing
 * a nonce leak their plaintext difference and the authentication subkey, so
 * uniqueness has to be enforced by durable state that outlives this function.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importRaw } from '../../internal/crypto/webcrypto.ts';

export interface GcmParameters {
  readonly keyBytes: number;
}

export const GCM_IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;

const GCM_ALGORITHMS: Readonly<Record<string, GcmParameters>> = Object.freeze({
  A128GCM: { keyBytes: 16 },
  A192GCM: { keyBytes: 24 },
  A256GCM: { keyBytes: 32 },
});

export function gcmParameters(algorithm: string): GcmParameters | undefined {
  return GCM_ALGORITHMS[algorithm];
}

export interface GcmSealed {
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

/**
 * Encrypts and authenticates under an exact-size key and a 12-byte nonce.
 *
 * Sizes are checked here rather than trusted from the caller because a provider
 * that silently accepts an odd-length nonce would apply its own derivation
 * step, producing a value this library never accounted for in its uniqueness
 * argument. One supported runtime does accept a short nonce, so this is enforced
 * rather than delegated.
 */
export async function sealGcm(
  algorithm: string,
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Promise<BackendResult<GcmSealed>> {
  const parameters = gcmParameters(algorithm);
  if (parameters === undefined) {
    return backendError('unsupported');
  }
  if (key.length !== parameters.keyBytes || iv.length !== GCM_IV_BYTES) {
    return backendError('operation_failed');
  }

  const result = await attempt(async () => {
    const handle = await importRaw(key, { name: 'AES-GCM', length: parameters.keyBytes * 8 }, ['encrypt']);
    return crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(iv),
        additionalData: toBufferSource(additionalData),
        tagLength: GCM_TAG_BYTES * 8,
      },
      handle,
      toBufferSource(plaintext),
    );
  });

  if (!result.ok) {
    return result;
  }

  const combined = new Uint8Array(result.value);
  if (combined.length !== plaintext.length + GCM_TAG_BYTES) {
    return backendError('operation_failed');
  }

  return backendOk({
    ciphertext: combined.subarray(0, plaintext.length),
    tag: combined.subarray(plaintext.length),
  });
}

/**
 * Authenticates and decrypts, returning plaintext only when the tag verifies.
 *
 * A failed tag is reported as `undefined` rather than as a backend failure: it
 * is an authentication outcome, and collapsing it into a provider error would
 * let a real outage be read as a forgery, or the reverse. No plaintext is
 * produced on that path, so nothing provisional can escape to a caller.
 */
export async function openGcm(
  algorithm: string,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  additionalData: Uint8Array,
): Promise<BackendResult<Uint8Array | undefined>> {
  const parameters = gcmParameters(algorithm);
  if (parameters === undefined) {
    return backendError('unsupported');
  }
  if (key.length !== parameters.keyBytes) {
    return backendError('operation_failed');
  }
  // Nonce and tag widths are public and fixed; a wrong width is a malformed
  // object, not a decryption attempt worth making.
  if (iv.length !== GCM_IV_BYTES || tag.length !== GCM_TAG_BYTES) {
    return backendOk(undefined);
  }

  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const imported = await attempt(() =>
    importRaw(key, { name: 'AES-GCM', length: parameters.keyBytes * 8 }, ['decrypt']),
  );
  if (!imported.ok) {
    return imported;
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(iv),
        additionalData: toBufferSource(additionalData),
        tagLength: GCM_TAG_BYTES * 8,
      },
      imported.value,
      toBufferSource(combined),
    );

    return backendOk(new Uint8Array(plaintext));
  } catch {
    // The provider rejects the whole operation when the tag does not verify, so
    // no partial plaintext is ever produced here.
    return backendOk(undefined);
  }
}
