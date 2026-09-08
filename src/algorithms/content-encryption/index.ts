/**
 * Content-encryption dispatch.
 *
 * The two supported constructions differ in CEK size, IV size, and tag size,
 * and every one of those is fixed by the `enc` identifier alone. Exposing them
 * through one description lets the JWE layer size a CEK and validate received
 * components without branching on the family, and stops a mismatched size from
 * being discovered only once the provider is already handling key material.
 */

import { backendError, type BackendResult } from '../../internal/crypto/backend.ts';
import { CBC_IV_BYTES, cbcHmacParameters, openCbcHmac, sealCbcHmac } from './aes-cbc-hmac.ts';
import { GCM_IV_BYTES, GCM_TAG_BYTES, gcmParameters, openGcm, sealGcm } from './aes-gcm.ts';

export interface ContentEncryptionShape {
  readonly cekBytes: number;
  readonly ivBytes: number;
  readonly tagBytes: number;
  /**
   * True when the construction uses a nonce that must never repeat under one
   * key, as opposed to an IV that must only be unpredictable. The distinction
   * decides whether creation requires durable allocation state.
   */
  readonly requiresUniqueNonce: boolean;
}

export function contentEncryptionShape(algorithm: string): ContentEncryptionShape | undefined {
  const gcm = gcmParameters(algorithm);
  if (gcm !== undefined) {
    return { cekBytes: gcm.keyBytes, ivBytes: GCM_IV_BYTES, tagBytes: GCM_TAG_BYTES, requiresUniqueNonce: true };
  }

  const cbc = cbcHmacParameters(algorithm);
  if (cbc !== undefined) {
    // CBC needs an unpredictable IV rather than a unique one: repetition
    // reveals equality of plaintext prefixes but does not collapse the
    // construction the way GCM nonce reuse does.
    return { cekBytes: cbc.keyBytes, ivBytes: CBC_IV_BYTES, tagBytes: cbc.tagBytes, requiresUniqueNonce: false };
  }

  return undefined;
}

export interface SealedContent {
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

export async function sealContent(
  algorithm: string,
  cek: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Promise<BackendResult<SealedContent>> {
  if (gcmParameters(algorithm) !== undefined) {
    return sealGcm(algorithm, cek, iv, plaintext, additionalData);
  }
  if (cbcHmacParameters(algorithm) !== undefined) {
    return sealCbcHmac(algorithm, cek, iv, plaintext, additionalData);
  }
  return backendError('unsupported');
}

/**
 * Authenticates and decrypts. A successful result holding `undefined` means the
 * object did not authenticate, which is distinct from a backend failure and
 * must stay distinct: one is an attacker-reachable outcome, the other is an
 * operational fault.
 */
export async function openContent(
  algorithm: string,
  cek: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  additionalData: Uint8Array,
): Promise<BackendResult<Uint8Array | undefined>> {
  if (gcmParameters(algorithm) !== undefined) {
    return openGcm(algorithm, cek, iv, ciphertext, tag, additionalData);
  }
  if (cbcHmacParameters(algorithm) !== undefined) {
    return openCbcHmac(algorithm, cek, iv, ciphertext, tag, additionalData);
  }
  return backendError('unsupported');
}
