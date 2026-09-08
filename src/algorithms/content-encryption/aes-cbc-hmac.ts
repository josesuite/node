/**
 * AES-CBC with HMAC-SHA-2 content encryption.
 *
 * This is an encrypt-then-MAC construction: the tag covers the ciphertext, and
 * decryption verifies it in full before the CBC layer is touched. That ordering
 * is what prevents a padding oracle. CBC padding errors are only observable if
 * an attacker can get the implementation to decrypt data it has not
 * authenticated, and here it never does. The provider offers no unpadded CBC
 * mode, so this ordering is the control, not a provider option.
 *
 * The CEK is split in half, MAC key first and AES key second. Both halves come
 * from one key so the two operations cannot be given independently chosen keys.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importRaw } from '../../internal/crypto/webcrypto.ts';

export interface CbcHmacParameters {
  readonly hash: string;
  readonly keyBytes: number;
  readonly tagBytes: number;
}

export const CBC_IV_BYTES = 16;

const CBC_HMAC_ALGORITHMS: Readonly<Record<string, CbcHmacParameters>> = Object.freeze({
  'A128CBC-HS256': { hash: 'SHA-256', keyBytes: 32, tagBytes: 16 },
  'A192CBC-HS384': { hash: 'SHA-384', keyBytes: 48, tagBytes: 24 },
  'A256CBC-HS512': { hash: 'SHA-512', keyBytes: 64, tagBytes: 32 },
});

export function cbcHmacParameters(algorithm: string): CbcHmacParameters | undefined {
  return CBC_HMAC_ALGORITHMS[algorithm];
}

/**
 * Encodes the additional-data length as an unsigned 64-bit big-endian bit
 * count, which is the final block the MAC covers.
 *
 * Binding this length is what stops an attacker from shifting the boundary
 * between the authenticated header and the ciphertext while keeping the
 * concatenation identical.
 */
function additionalDataLength(additionalData: Uint8Array): Uint8Array {
  const encoded = new Uint8Array(8);
  new DataView(encoded.buffer).setBigUint64(0, BigInt(additionalData.length) * 8n);
  return encoded;
}

async function computeTag(
  parameters: CbcHmacParameters,
  macKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  additionalData: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const message = new Uint8Array(additionalData.length + iv.length + ciphertext.length + 8);
  let offset = 0;
  for (const part of [additionalData, iv, ciphertext, additionalDataLength(additionalData)]) {
    message.set(part, offset);
    offset += part.length;
  }

  const result = await attempt(async () => {
    const handle = await importRaw(macKey, { name: 'HMAC', hash: parameters.hash }, ['sign']);
    return crypto.subtle.sign('HMAC', handle, toBufferSource(message));
  });

  if (!result.ok) {
    return result;
  }

  // The leftmost half of the digest is the tag. This truncation is part of the
  // construction and fixed by the algorithm identifier, not a caller choice.
  return backendOk(new Uint8Array(result.value).subarray(0, parameters.tagBytes));
}

export interface CbcHmacSealed {
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

export async function sealCbcHmac(
  algorithm: string,
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Promise<BackendResult<CbcHmacSealed>> {
  const parameters = cbcHmacParameters(algorithm);
  if (parameters === undefined) {
    return backendError('unsupported');
  }
  if (key.length !== parameters.keyBytes || iv.length !== CBC_IV_BYTES) {
    return backendError('operation_failed');
  }

  const half = parameters.keyBytes / 2;
  const macKey = key.subarray(0, half);
  const encryptionKey = key.subarray(half);

  // PKCS #7 padding is applied by the provider, including a full block when the
  // plaintext is empty or block-aligned, which the construction requires.
  const encrypted = await attempt(async () => {
    const handle = await importRaw(encryptionKey, { name: 'AES-CBC', length: half * 8 }, ['encrypt']);
    return crypto.subtle.encrypt({ name: 'AES-CBC', iv: toBufferSource(iv) }, handle, toBufferSource(plaintext));
  });

  if (!encrypted.ok) {
    return encrypted;
  }

  const ciphertext = new Uint8Array(encrypted.value);
  const tag = await computeTag(parameters, macKey, iv, ciphertext, additionalData);
  if (!tag.ok) {
    return tag;
  }

  return backendOk({ ciphertext, tag: tag.value });
}
