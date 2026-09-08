/**
 * AES key wrapping.
 *
 * RFC 3394 wrapping with the default initial value. The integrity check is the
 * recovery of those eight fixed octets: an unwrap that produces different ones
 * means the key or the wrapped bytes are wrong, and no key material is
 * released. There is no padded variant here, because substituting one would
 * change which lengths are accepted.
 *
 * This uses WebCrypto rather than the provider's cipher list. The supported
 * backends differ: one exposes an `aes256-wrap` cipher
 * and the other exposes none at all, so a cipher-based implementation would
 * leave a required capability unavailable on a supported runtime. WebCrypto
 * implements the same construction on both and was verified to produce
 * byte-identical output. The cost is that wrapping is asynchronous.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';

/** Bytes RFC 3394 adds to the wrapped output. */
export const KW_OVERHEAD_BYTES = 8;

const KEK_SIZES: Readonly<Record<string, number>> = Object.freeze({
  A128KW: 16,
  A192KW: 24,
  A256KW: 32,
});

/** KEK size the identifier requires, or `undefined` when it names no wrapping. */
export function aesKwKeySize(algorithm: string): number | undefined {
  return KEK_SIZES[algorithm];
}

/**
 * The initial value RFC 3394 fixes. WebCrypto applies it internally and offers
 * no way to override it, which is the behaviour this library wants.
 */
const DEFAULT_IV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

async function importKek(kek: Uint8Array, usage: 'wrapKey' | 'unwrapKey'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toBufferSource(kek), 'AES-KW', false, [usage]);
}

export async function wrapAesKw(
  algorithm: string,
  kek: Uint8Array,
  cek: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const kekBytes = aesKwKeySize(algorithm);
  if (kekBytes === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== kekBytes) {
    return backendError('operation_failed');
  }
  // RFC 3394 operates on whole 64-bit blocks and requires at least two of them.
  if (cek.length < 16 || cek.length % 8 !== 0) {
    return backendError('operation_failed');
  }

  try {
    const wrappingKey = await importKek(kek, 'wrapKey');
    // The CEK is imported under a placeholder type purely so it can be handed
    // to `wrapKey`; wrapping treats it as opaque octets, and the type carries
    // no meaning for the wrapped bytes.
    const target = await crypto.subtle.importKey('raw', toBufferSource(cek), { name: 'HMAC', hash: 'SHA-256' }, true, [
      'sign',
    ]);
    const wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', target, wrappingKey, 'AES-KW'));

    if (wrapped.length !== cek.length + KW_OVERHEAD_BYTES) {
      return backendError('operation_failed');
    }

    return backendOk(wrapped);
  } catch {
    return backendError('operation_failed');
  }
}
