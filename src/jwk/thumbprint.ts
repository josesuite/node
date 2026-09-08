/**
 * JWK thumbprints.
 *
 * The hash input is a freshly constructed object containing only the required
 * members for the key type, in lexicographic order, with no whitespace. It is
 * deliberately not a hash of the received JSON and not general-purpose JSON
 * canonicalization: two encodings of the same key differ in whitespace, member
 * order, and optional members, and must still produce the same thumbprint.
 *
 * The serialization is built by hand rather than with `JSON.stringify` over an
 * object literal, because property order in the output would then depend on
 * insertion order rather than being explicit, and the required order is part of
 * the definition.
 */

import { createHash } from 'node:crypto';

import { decodeBase64url, encodeBase64url } from '../internal/encoding/base64url.ts';
import { encodeUtf8 } from '../internal/encoding/utf8.ts';
import { isImportedKey, type UsableKey } from '../key/import.ts';

/**
 * Required members per key type, already in lexicographic order.
 *
 * Optional metadata is excluded on purpose: `kid`, `use`, `key_ops`, and
 * certificate members describe how a key is labelled or used, not which key it
 * is, so including them would make one key produce several thumbprints. `alg`
 * is excluded for the same reason everywhere except post-quantum keys, whose
 * format makes it part of the key's identity.
 */
const THUMBPRINT_MEMBERS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  RSA: ['e', 'kty', 'n'],
  EC: ['crv', 'kty', 'x', 'y'],
  oct: ['k', 'kty'],
  OKP: ['crv', 'kty', 'x'],
  AKP: ['alg', 'kty', 'pub'],
});

/**
 * Escapes a member value for JSON.
 *
 * Every value in a thumbprint input is a JWK parameter string: a Base64url
 * value, a curve name, or a key type, all of which are ASCII with no character
 * requiring escaping. The check is kept so that an unexpected value fails
 * loudly rather than producing a subtly wrong digest.
 */
function jsonString(value: string): string {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e || code === 0x22 || code === 0x5c) {
      throw new TypeError('thumbprint member value is not a plain ASCII JWK parameter');
    }
  }
  return `"${value}"`;
}

export type ThumbprintResult =
  | { readonly ok: true; readonly thumbprint: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Computes the SHA-256 thumbprint of a validated key.
 *
 * `members` must already hold the key's canonical parameter strings; the caller
 * validates the key first, so a malformed key never reaches this point. An
 * unsupported key type is refused rather than guessed at, since guessing its
 * required members would produce an identifier that no other implementation
 * would agree with.
 */
export function computeThumbprint(key: UsableKey): ThumbprintResult {
  if (!isImportedKey(key)) {
    return { ok: false, reason: 'key_not_imported' };
  }
  const identity = key.identity;
  const members: Record<string, string> = {};
  for (const [name, value] of Object.entries(identity)) {
    if (name !== 'kty') {
      members[name] = value instanceof Uint8Array ? encodeBase64url(value) : value;
    }
  }
  return computeValidatedThumbprint(identity.kty, members);
}

function computeValidatedThumbprint(keyType: string, members: Readonly<Record<string, string>>): ThumbprintResult {
  const required = THUMBPRINT_MEMBERS[keyType];
  if (required === undefined) {
    return { ok: false, reason: 'unsupported_key_type' };
  }

  const parts: string[] = [];
  for (const name of required) {
    const value = name === 'kty' ? keyType : members[name];
    if (value === undefined) {
      return { ok: false, reason: `${name}_missing` };
    }
    try {
      parts.push(`${jsonString(name)}:${jsonString(value)}`);
    } catch {
      return { ok: false, reason: `${name}_invalid` };
    }
  }

  const materialFailure = validateThumbprintMaterial(keyType, members);
  if (materialFailure !== undefined) {
    return { ok: false, reason: materialFailure };
  }

  const serialized = `{${parts.join(',')}}`;
  const digest = createHash('sha256').update(encodeUtf8(serialized)).digest();

  return { ok: true, thumbprint: encodeBase64url(new Uint8Array(digest)) };
}

const EC_BYTES: Readonly<Record<string, number>> = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
});
const OKP_BYTES: Readonly<Record<string, number>> = Object.freeze({ Ed25519: 32, Ed448: 57, X25519: 32, X448: 56 });

function validateThumbprintMaterial(keyType: string, members: Readonly<Record<string, string>>): string | undefined {
  const encoded =
    keyType === 'RSA'
      ? ['e', 'n']
      : keyType === 'EC'
        ? ['x', 'y']
        : keyType === 'OKP'
          ? ['x']
          : keyType === 'AKP'
            ? ['pub']
            : ['k'];
  const expected =
    keyType === 'EC' ? EC_BYTES[members['crv']!] : keyType === 'OKP' ? OKP_BYTES[members['crv']!] : undefined;
  if ((keyType === 'EC' || keyType === 'OKP') && expected === undefined) {
    return 'crv_invalid';
  }
  for (const name of encoded) {
    const value = members[name];
    if (value === undefined) {
      continue;
    }
    const decoded = decodeBase64url(value, 1024);
    if (!decoded.ok || decoded.bytes.length === 0 || (expected !== undefined && decoded.bytes.length !== expected)) {
      return `${name}_invalid`;
    }
  }
  return undefined;
}
