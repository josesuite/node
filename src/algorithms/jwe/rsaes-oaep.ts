/**
 * RSAES-OAEP key transport.
 *
 * The hash is fixed by the algorithm identifier and used for both the OAEP hash
 * and its MGF1 mask generation; the two are never configured independently. The
 * label is always empty, since JOSE defines no way to carry one and a provider
 * default must not introduce one.
 *
 * The SHA-1 variant exists for receiving old objects only. It is not offered
 * for creation, and it is a separate identifier rather than a mode of the
 * SHA-256 one so that enabling it cannot be mistaken for a configuration
 * detail.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importJwk } from '../../internal/crypto/webcrypto.ts';
import type { RsaPrivateMaterial, RsaPublicMaterial } from '../../key/validation.ts';
import { rsaJwk, rsaPublicJwk } from '../jws/rsa-common.ts';

const OAEP_HASHES: Readonly<Record<string, string>> = Object.freeze({
  'RSA-OAEP-256': 'SHA-256',
  'RSA-OAEP': 'SHA-1',
});

export function oaepHash(algorithm: string): string | undefined {
  return OAEP_HASHES[algorithm];
}

export async function encryptRsaOaep(
  algorithm: string,
  key: RsaPublicMaterial,
  cek: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const hash = oaepHash(algorithm);
  if (hash === undefined) {
    return backendError('unsupported');
  }

  const result = await attempt(async () => {
    const handle = await importJwk(rsaPublicJwk(key), { name: 'RSA-OAEP', hash }, ['encrypt']);
    // No label is supplied, which is what the JOSE construction requires, and
    // MGF1 follows the same hash.
    return crypto.subtle.encrypt({ name: 'RSA-OAEP' }, handle, toBufferSource(cek));
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}

/**
 * Recovers the CEK, returning `undefined` when the ciphertext does not decrypt
 * under this key.
 *
 * OAEP decoding failures are reported the same way as a wrong key, and the
 * caller must not distinguish them in anything it emits: separating them
 * historically enabled adaptive attacks that recover the plaintext from a
 * server's differing responses.
 */
export async function decryptRsaOaep(
  algorithm: string,
  key: RsaPrivateMaterial,
  encryptedKey: Uint8Array,
): Promise<BackendResult<Uint8Array | undefined>> {
  const hash = oaepHash(algorithm);
  if (hash === undefined) {
    return backendError('unsupported');
  }
  // The ciphertext is exactly one modulus wide; anything else cannot have come
  // from this key and is rejected before the private operation.
  if (encryptedKey.length !== key.n.length) {
    return backendOk(undefined);
  }

  const imported = await attempt(() => importJwk(rsaJwk(key), { name: 'RSA-OAEP', hash }, ['decrypt']));
  if (!imported.ok) {
    return imported;
  }
  try {
    const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, imported.value, toBufferSource(encryptedKey));
    return backendOk(new Uint8Array(decrypted));
  } catch {
    return backendOk(undefined);
  }
}
