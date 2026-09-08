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
import { LIMITS_V1 } from '../policy/limits.ts';
import type { EcCurve, OkpCurve } from './types.ts';

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

/** Number of significant bits in a nonzero byte, e.g. 0x01 -> 1, 0x80 -> 8. */
function bitLengthOfByte(byte: number): number {
  return 32 - Math.clz32(byte);
}

export interface RsaPublicMaterial {
  readonly n: Uint8Array;
  readonly e: Uint8Array;
  readonly modulusBits: number;
}

/**
 * Private RSA material, carrying the complete CRT parameter group.
 *
 * The octets are retained exactly as decoded rather than recomputed, because
 * the leading-zero padding is significant to the provider's key import.
 */
export interface RsaPrivateMaterial extends RsaPublicMaterial {
  readonly d: Uint8Array;
  readonly p: Uint8Array;
  readonly q: Uint8Array;
  readonly dp: Uint8Array;
  readonly dq: Uint8Array;
  readonly qi: Uint8Array;
}

/**
 * Validates RSA public material.
 *
 * `receiveOnly` admits the 2048 through 3071 bit range for compatibility with
 * accept for verification of existing tokens. The modern floor is 3072 bits;
 * nothing below 2048 bits is ever acceptable.
 */
export function validateRsaPublic(
  jwk: JsonObject,
  options: { readonly receiveOnly: boolean },
): { readonly ok: true; readonly material: RsaPublicMaterial } | MaterialRejection {
  const maxModulusBytes = LIMITS_V1.rsaModulusBits / 8;

  const nResult = decodeMember(jwk, 'n', maxModulusBytes);
  if (!nResult.ok) {
    return nResult;
  }
  const nInvalid = validateUInt(nResult.bytes, 'n');
  if (nInvalid !== undefined) {
    return nInvalid;
  }

  // The exponent is bounded to 32 bits, which keeps public-key operations
  // cheap; an attacker-chosen huge exponent would otherwise cost real work.
  const eResult = decodeMember(jwk, 'e', 4);
  if (!eResult.ok) {
    return eResult;
  }
  const eInvalid = validateUInt(eResult.bytes, 'e');
  if (eInvalid !== undefined) {
    return eInvalid;
  }

  const n = toBigInt(nResult.bytes);
  const e = toBigInt(eResult.bytes);

  // An even modulus is not a product of two odd primes, so it cannot be a valid
  // RSA modulus regardless of its size.
  if ((n & 1n) === 0n) {
    return reject('n_even');
  }

  // Significant bit length: all bytes but the first contribute eight bits each,
  // and the leading byte contributes only its significant bits. The encoding is
  // minimal, so the leading byte is nonzero and `bitLengthOfByte` is at least 1.
  const modulusBits = (nResult.bytes.length - 1) * 8 + bitLengthOfByte(nResult.bytes[0]!);
  const floor = options.receiveOnly ? 2048 : 3072;
  if (modulusBits < floor) {
    return reject('n_too_small', 'incompatible_key');
  }
  if (modulusBits > LIMITS_V1.rsaModulusBits) {
    return reject('n_too_large', 'resource_limit');
  }

  if ((e & 1n) === 0n) {
    return reject('e_even');
  }
  if (e < 3n) {
    return reject('e_too_small');
  }
  if (e >= n) {
    return reject('e_not_less_than_n');
  }

  return { ok: true, material: { n: nResult.bytes, e: eResult.bytes, modulusBits } };
}

/**
 * Validates the presence and consistency of RSA private material.
 *
 * The complete CRT parameter group is required, which is stricter than the
 * bare `n,e,d` form the JWK format permits. Requiring it means the arithmetic
 * relationships below can be checked at import; a key supplying only `d` would
 * have to be trusted rather than verified.
 *
 * The Node provider accepts a JWK whose `qi` is inconsistent with `p` and `q`
 * and then signs with it successfully, so these relationships are checked here
 * rather than left to the backend.
 */
export function validateRsaPrivate(
  jwk: JsonObject,
  publicMaterial: RsaPublicMaterial,
): { readonly ok: true; readonly material: RsaPrivateMaterial } | MaterialRejection {
  // Multi-prime RSA is unsupported, and its presence changes the meaning of
  // every other CRT parameter, so it is refused rather than ignored.
  if (jwk.members.has('oth')) {
    return reject('oth_unsupported');
  }

  const maxBytes = LIMITS_V1.rsaModulusBits / 8;
  const parts: Record<string, bigint> = {};
  const octets: Record<string, Uint8Array> = {};

  for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    const result = decodeMember(jwk, name, maxBytes);
    if (!result.ok) {
      return result;
    }
    const invalid = validateUInt(result.bytes, name);
    if (invalid !== undefined) {
      return invalid;
    }
    parts[name] = toBigInt(result.bytes);
    octets[name] = result.bytes;
  }

  const n = toBigInt(publicMaterial.n);
  const e = toBigInt(publicMaterial.e);
  const d = parts['d']!;
  const p = parts['p']!;
  const q = parts['q']!;
  const dp = parts['dp']!;
  const dq = parts['dq']!;
  const qi = parts['qi']!;

  if (p === q) {
    return reject('p_equals_q');
  }
  // Neither factor can be 1: no prime is, and `p - 1` and `q - 1` are used as
  // moduli below, where a zero divisor would throw out of a validation path
  // that must return a normalized rejection. A forged `p = 1, q = n` satisfies
  // the product check, so this is reached with attacker-supplied members.
  if (p <= 1n || q <= 1n) {
    return reject('factor_not_greater_than_one');
  }
  if (p * q !== n) {
    return reject('pq_product_mismatch');
  }

  // The private exponent must invert the public one modulo each prime's group
  // order. Checking per prime avoids needing lcm(p-1, q-1) directly.
  if ((e * d) % (p - 1n) !== 1n % (p - 1n)) {
    return reject('d_inconsistent_mod_p');
  }
  if ((e * d) % (q - 1n) !== 1n % (q - 1n)) {
    return reject('d_inconsistent_mod_q');
  }

  if (dp !== d % (p - 1n)) {
    return reject('dp_mismatch');
  }
  if (dq !== d % (q - 1n)) {
    return reject('dq_mismatch');
  }
  if ((qi * q) % p !== 1n % p) {
    return reject('qi_mismatch');
  }

  return {
    ok: true,
    material: {
      ...publicMaterial,
      d: octets['d']!,
      p: octets['p']!,
      q: octets['q']!,
      dp: octets['dp']!,
      dq: octets['dq']!,
      qi: octets['qi']!,
    },
  };
}

/** Fixed coordinate widths per EC curve; padding is significant and preserved. */
export const EC_COORDINATE_BYTES: Readonly<Record<EcCurve, number>> = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
});

/** Fixed public and private lengths per OKP curve. */
export const OKP_KEY_BYTES: Readonly<Record<OkpCurve, { public: number; private: number }>> = Object.freeze({
  Ed25519: { public: 32, private: 32 },
  Ed448: { public: 57, private: 57 },
  X25519: { public: 32, private: 32 },
  X448: { public: 56, private: 56 },
});

/**
 * Validates that an EC coordinate or scalar has exactly the curve's width.
 *
 * A short value must be left-padded by its producer; stripping or accepting a
 * shortened form would change the value's identity and break comparison against
 * the same key expressed canonically.
 */
export function validateEcComponentLength(
  bytes: Uint8Array,
  curve: EcCurve,
  name: string,
): MaterialRejection | undefined {
  const expected = EC_COORDINATE_BYTES[curve];
  if (bytes.length !== expected) {
    return reject(`${name}_wrong_length`);
  }
  return undefined;
}

export interface EcMaterial {
  readonly curve: EcCurve;
  readonly x: Uint8Array;
  readonly y: Uint8Array;
  readonly d: Uint8Array | undefined;
}

/**
 * Validates EC key material: coordinate widths, the point lying on the curve,
 * and, for a private key, that the supplied point is the one the scalar
 * actually generates.
 *
 * The consistency check recomputes the public point from `d` by scalar
 * multiplication. It deliberately does not sign with the key and verify under
 * the supplied public value: a mismatched pair can still produce a
 * self-consistent signature, so that would establish nothing.
 */
export function validateEcMaterial(
  jwk: JsonObject,
  curve: EcCurve,
  derivePublicPoint: (
    curve: string,
    scalar: Uint8Array,
  ) => { ok: true; value: { x: Uint8Array; y: Uint8Array } } | { ok: false },
  validatePoint: (curve: string, point: { x: Uint8Array; y: Uint8Array }) => { ok: boolean },
): { readonly ok: true; readonly material: EcMaterial } | MaterialRejection {
  // Decoding allows more than the exact width so that a wrong-width coordinate
  // is reported as malformed key material rather than as a resource limit. The
  // allowance stays bounded by the largest supported coordinate, so an
  // arbitrarily long value is still refused before it is decoded.
  const decodeAllowance = EC_COORDINATE_BYTES['P-521'];

  const xResult = decodeMember(jwk, 'x', decodeAllowance);
  if (!xResult.ok) {
    return xResult;
  }
  const xInvalid = validateEcComponentLength(xResult.bytes, curve, 'x');
  if (xInvalid !== undefined) {
    return xInvalid;
  }

  const yResult = decodeMember(jwk, 'y', decodeAllowance);
  if (!yResult.ok) {
    return yResult;
  }
  const yInvalid = validateEcComponentLength(yResult.bytes, curve, 'y');
  if (yInvalid !== undefined) {
    return yInvalid;
  }

  const point = { x: xResult.bytes, y: yResult.bytes };

  // Rejects coordinates outside the field, points off the curve, and the point
  // at infinity, any of which would make the key unusable as an identity.
  if (!validatePoint(curve, point).ok) {
    return reject('point_not_on_curve');
  }

  if (!jwk.members.has('d')) {
    return { ok: true, material: { curve, x: point.x, y: point.y, d: undefined } };
  }

  const dResult = decodeMember(jwk, 'd', decodeAllowance);
  if (!dResult.ok) {
    return dResult;
  }
  const dInvalid = validateEcComponentLength(dResult.bytes, curve, 'd');
  if (dInvalid !== undefined) {
    return dInvalid;
  }

  // Also enforces `1 <= d < n`, since a scalar outside that range has no
  // corresponding public point.
  const derived = derivePublicPoint(curve, dResult.bytes);
  if (!derived.ok) {
    return reject('private_scalar_invalid');
  }

  if (!bytesEqual(derived.value.x, point.x) || !bytesEqual(derived.value.y, point.y)) {
    return reject('public_private_mismatch');
  }

  return { ok: true, material: { curve, x: point.x, y: point.y, d: dResult.bytes } };
}

/** Plain equality for public values; no secret is compared here. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

export interface OkpMaterial {
  readonly curve: OkpCurve;
  readonly x: Uint8Array;
  readonly d: Uint8Array | undefined;
}

/**
 * Validates OKP key material.
 *
 * For the signing curves the public value additionally passes the canonical
 * encoding, identity, and subgroup checks, because the provider admits
 * low-order and non-canonical points that cannot serve as a signer identity.
 *
 * For a private key the public component is derived from `d` and compared for
 * exact octet equality. Agreement curves permit certain equivalent public
 * encodings when processing a peer's value, but a configured private key must
 * carry its canonical projection, so that one private key has one identity.
 */
export function validateOkpMaterial(
  jwk: JsonObject,
  curve: OkpCurve,
  derivePublicKey: (curve: string, privateKey: Uint8Array) => { ok: true; value: Uint8Array } | { ok: false },
  validateSigningPublicKey: (encoded: Uint8Array) => string | undefined,
): { readonly ok: true; readonly material: OkpMaterial } | MaterialRejection {
  const sizes = OKP_KEY_BYTES[curve];
  // As for EC, decoding allows more than the exact size so a wrong-length value
  // is a malformed key rather than a resource limit, while staying bounded by
  // the largest supported OKP key.
  const decodeAllowance = OKP_KEY_BYTES.Ed448.public;

  const xResult = decodeMember(jwk, 'x', decodeAllowance);
  if (!xResult.ok) {
    return xResult;
  }
  if (xResult.bytes.length !== sizes.public) {
    return reject('x_wrong_length');
  }

  if (curve === 'Ed25519') {
    const failure = validateSigningPublicKey(xResult.bytes);
    if (failure !== undefined) {
      return reject(`ed25519_${failure}`);
    }
  }

  if (!jwk.members.has('d')) {
    return { ok: true, material: { curve, x: xResult.bytes, d: undefined } };
  }

  const dResult = decodeMember(jwk, 'd', decodeAllowance);
  if (!dResult.ok) {
    return dResult;
  }
  if (dResult.bytes.length !== sizes.private) {
    return reject('d_wrong_length');
  }

  const derived = derivePublicKey(curve, dResult.bytes);
  if (!derived.ok) {
    return reject('private_key_invalid');
  }

  if (!bytesEqual(derived.value, xResult.bytes)) {
    return reject('public_private_mismatch');
  }

  return { ok: true, material: { curve, x: xResult.bytes, d: dResult.bytes } };
}

/**
 * Validates symmetric key material.
 *
 * `minimumBytes` is the algorithm's own floor, such as the hash output size for
 * an HMAC algorithm. A length check is a necessary bound but is never evidence
 * of entropy: a long, predictable value passes it, so trusted provisioning has
 * to establish where the secret came from.
 */
export function validateOctMaterial(
  jwk: JsonObject,
  minimumBytes: number,
): { readonly ok: true; readonly key: Uint8Array } | MaterialRejection {
  const result = decodeMember(jwk, 'k', LIMITS_V1.symmetricKeyOctets);
  if (!result.ok) {
    return result;
  }

  if (result.bytes.length < minimumBytes) {
    // Too short for the bound algorithm: the key is valid material but cannot
    // satisfy this binding.
    return reject('k_too_short', 'incompatible_key');
  }

  return { ok: true, key: result.bytes };
}
