/**
 * Direct content encryption.
 *
 * The configured symmetric key is the CEK itself. Nothing is wrapped, so the
 * encrypted-key component carries no bytes at all.
 *
 * The key must already be the exact size the content algorithm requires.
 * Truncating or padding to fit would let one configured key serve several `enc`
 * values, silently reusing key material across constructions and, for the
 * truncating case, discarding the entropy the operator provisioned.
 */

import { contentEncryptionShape } from '../content-encryption/index.ts';

export type DirectKeyResult =
  | { readonly ok: true; readonly cek: Uint8Array }
  | { readonly ok: false; readonly reason: 'unsupported_enc' | 'key_size_mismatch' };

/**
 * Accepts a configured key as the CEK for one exact content algorithm.
 *
 * Only one recipient can use this, since every recipient sharing the object
 * would have to hold the same key; that constraint is enforced where recipients
 * are assembled, not here.
 */
export function directCek(contentAlgorithm: string, configuredKey: Uint8Array): DirectKeyResult {
  const shape = contentEncryptionShape(contentAlgorithm);
  if (shape === undefined) {
    return { ok: false, reason: 'unsupported_enc' };
  }
  if (configuredKey.length !== shape.cekBytes) {
    return { ok: false, reason: 'key_size_mismatch' };
  }

  return { ok: true, cek: configuredKey };
}
