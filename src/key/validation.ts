/**
 * Key material validation.
 *
 * These checks exist because backend acceptance is not sufficient evidence of a
 * valid key. Qualification of the Node provider found that it accepts several
 * keys the implementation must reject: RSA private keys whose CRT parameters are
 * mutually inconsistent, and EC and X25519 private keys whose supplied public
 * component does not match the private scalar. Ed25519 remains disabled because
 * the available providers do not enforce the required public-key acceptance set.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import { decodeBase64url } from '../internal/encoding/base64url.ts';
import type { JsonObject } from '../internal/json/types.ts';

export interface MaterialRejection {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly reason: string;
}

export type BytesResult = { readonly ok: true; readonly bytes: Uint8Array } | MaterialRejection;

function reject(reason: string, category: ErrorCategory = 'invalid_key'): MaterialRejection {
  return { ok: false, category, reason };
}

/**
 * Decodes a required Base64url member of a JWK.
 *
 * Key material uses the same strict unpadded Base64url as the rest of JOSE, so
 * a padded or whitespace-bearing value is rejected rather than repaired.
 */
export function decodeMember(jwk: JsonObject, name: string, maxBytes: number): BytesResult {
  const member = jwk.members.get(name);
  if (member === undefined) {
    return reject(`${name}_missing`);
  }
  if (member.kind !== 'string') {
    return reject(`${name}_not_a_string`);
  }

  const decoded = decodeBase64url(member.value, maxBytes);
  if (!decoded.ok) {
    if (decoded.failure === 'too_large') {
      return reject(`${name}_too_large`, 'resource_limit');
    }
    return reject(`${name}_invalid_base64url`, 'invalid_encoding');
  }

  return { ok: true, bytes: decoded.bytes };
}

/**
 * Validates a Base64urlUInt integer: a minimal unsigned big-endian encoding.
 *
 * Redundant leading zero bytes are rejected because they let the same integer
 * be written several ways, which would make two representations of one key
 * compare as different keys and break identity comparison.
 */
export function validateUInt(bytes: Uint8Array, name: string): MaterialRejection | undefined {
  if (bytes.length === 0) {
    return reject(`${name}_empty`);
  }
  if (bytes[0] === 0) {
    return reject(`${name}_leading_zero`);
  }
  return undefined;
}

export function toBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}
