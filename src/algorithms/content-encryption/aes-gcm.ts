/**
 * AES-GCM content encryption.
 *
 * The tag is always the full 16 bytes. Truncation is not offered at any layer:
 * a shorter tag weakens forgery resistance, and because the tag length would
 * have to be read from somewhere, offering it would let the object influence
 * how strictly it is checked.
 *
 * Nonces are supplied by the caller's allocator rather than generated here.
 * GCM fails catastrophically on nonce reuse under one key. Two messages sharing
 * a nonce leak their plaintext difference and the authentication subkey, so
 * uniqueness has to be enforced by durable state that outlives this function.
 *
 * Encryption runs synchronously through `node:crypto`. For JWE-sized inputs
 * the cipher work is a few microseconds, below the fixed cost of an
 * asynchronous provider dispatch, and the cipher exposes the tag as its own
 * value, which is the JWE wire layout.
 */

import { type CipherGCMTypes, createCipheriv, createSecretKey } from 'node:crypto';

import { ownedBytes, toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importRaw } from '../../internal/crypto/webcrypto.ts';

export interface GcmParameters {
  readonly keyBytes: number;
  /** Native cipher name. */
  readonly cipher: CipherGCMTypes;
}

export const GCM_IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;

const GCM_ALGORITHMS: Readonly<Record<string, GcmParameters>> = Object.freeze({
  A128GCM: { keyBytes: 16, cipher: 'aes-128-gcm' },
  A192GCM: { keyBytes: 24, cipher: 'aes-192-gcm' },
  A256GCM: { keyBytes: 32, cipher: 'aes-256-gcm' },
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

  try {
    // Key material is supplied as a `KeyObject`; passing raw octets triggers a
    // per-call provider fetch on some supported releases.
    const cipher = createCipheriv(parameters.cipher, createSecretKey(key), iv, { authTagLength: GCM_TAG_BYTES });
    cipher.setAAD(additionalData);
    // GCM is a stream mode, so `update` yields every ciphertext octet and
    // `final` only completes the tag.
    const ciphertext = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();

    if (ciphertext.length !== plaintext.length || tag.length !== GCM_TAG_BYTES) {
      return backendError('operation_failed');
    }

    return backendOk({ ciphertext: ownedBytes(ciphertext), tag: ownedBytes(tag) });
  } catch {
    return backendError('operation_failed');
  }
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
