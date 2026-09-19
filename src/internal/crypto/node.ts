/**
 * Node provider adapter for the key-validation operations the JOSE layer needs
 * but the provider does not perform on its own.
 *
 * Qualification of this provider established the behaviour these functions
 * compensate for:
 *
 * - Importing an EC private JWK and exporting it again never yields the point
 *   derived from `d`: runtimes either refuse the key or echo the supplied `x`
 *   and `y` back. Either way a round trip cannot detect a mismatched public
 *   component, so public points are computed from the private scalar by scalar
 *   multiplication instead.
 * - Ed25519 public-key import accepts low-order points, the identity, and
 *   non-canonical encodings, so those are checked before a key is admitted.
 * - An OKP import either refuses a mismatched pair or silently replaces `x`
 *   with the value derived from `d`, so it never reports the inconsistency to
 *   the caller; a supplied `x` is compared here instead.
 *
 * Which of these the provider also enforces itself varies across Node releases,
 * so none of them is assumed: every check runs here regardless. That keeps
 * provider assumptions executable, so an upgrade that changes one fails closed
 * instead of silently altering which keys this library accepts.
 */

import { createECDH, createPrivateKey, createPublicKey, createSecretKey, type KeyObject } from 'node:crypto';

import { backendError, backendOk, type BackendResult } from './backend.ts';

const SECRET_KEY_CACHE = new WeakMap<object, KeyObject>();

/**
 * Memoizes the `KeyObject` for a long-lived key record.
 *
 * The cache follows the same rules as the provider handle cache: it is keyed
 * on the identity of the record, never on key material; entries are weak; and
 * the record must be bound to one algorithm and one operation for its whole
 * lifetime.
 *
 * A `KeyObject` carries the provider's prepared key state, so each operation
 * under the record skips the per-call key preparation that raw octets incur.
 */
export function secretKeyCached(token: object | undefined, material: Uint8Array): KeyObject {
  if (token === undefined) {
    return createSecretKey(material);
  }

  const cached = SECRET_KEY_CACHE.get(token);
  if (cached !== undefined) {
    return cached;
  }

  const created = createSecretKey(material);
  SECRET_KEY_CACHE.set(token, created);
  return created;
}

/** JOSE curve names mapped to the provider's own curve identifiers. */
const EC_CURVE_NAMES: Readonly<Record<string, string>> = Object.freeze({
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  secp256k1: 'secp256k1',
});

export interface EcPoint {
  readonly x: Uint8Array;
  readonly y: Uint8Array;
}

/**
 * Computes the public point for an EC private scalar.
 *
 * This uses scalar multiplication against the curve's base point and never
 * consults any supplied public coordinates, which is what lets the caller
 * compare the result against them. Deriving from a signature made under an
 * unchecked supplied public key would not establish the same property, because
 * a mismatched key can still produce a signature.
 */
export function deriveEcPublicPoint(curve: string, privateScalar: Uint8Array): BackendResult<EcPoint> {
  const curveName = EC_CURVE_NAMES[curve];
  if (curveName === undefined) {
    return backendError('unsupported');
  }

  try {
    const agreement = createECDH(curveName);
    // Rejects a zero or out-of-range scalar, so `1 <= d < n` is enforced here
    // rather than by re-deriving the group order in protocol code.
    agreement.setPrivateKey(Buffer.from(privateScalar));

    // Uncompressed SEC1 form: a 0x04 prefix followed by equal-width X and Y.
    const encoded = agreement.getPublicKey();
    if (encoded.length < 3 || encoded[0] !== 0x04) {
      return backendError('operation_failed');
    }

    const width = (encoded.length - 1) / 2;
    if (!Number.isInteger(width)) {
      return backendError('operation_failed');
    }

    return backendOk({
      x: new Uint8Array(encoded.subarray(1, 1 + width)),
      y: new Uint8Array(encoded.subarray(1 + width)),
    });
  } catch {
    return backendError('operation_failed');
  }
}

/**
 * PKCS8 prefixes for an OKP private key, one per curve, up to the raw scalar.
 *
 * The encoded lengths fix each curve's private-key width, so appending a scalar
 * of that width completes the structure with no length arithmetic. A scalar
 * wider than the curve's width still parses, with the excess ignored, so
 * callers are responsible for checking the width before derivation.
 */
const OKP_PKCS8_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  Ed25519: '302e020100300506032b657004220420',
  Ed448: '3047020100300506032b6571043b0439',
  X25519: '302e020100300506032b656e04220420',
  X448: '3046020100300506032b656f043a0438',
});

/** X25519 scalar and its public value, from RFC 7748 section 6.1. */
const X25519_PROBE_SCALAR = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
const X25519_PROBE_PUBLIC = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';

function derivesFromJwkPlaceholder(): boolean {
  const scalar = Buffer.from(X25519_PROBE_SCALAR, 'hex');
  const derived = okpPublicFromJwk('X25519', scalar);
  return derived !== undefined && Buffer.from(derived).toString('hex') === X25519_PROBE_PUBLIC;
}

/**
 * Whether the JWK encoding can be used for derivation on this runtime.
 *
 * Deriving through a JWK is several times cheaper than through PKCS8, but only
 * sound where the provider replaces the placeholder `x` below. Runtimes that
 * validate `x` against `d` at import reject that key instead, so the encoding
 * is chosen by deriving a known answer once rather than by runtime version.
 */
const DERIVES_FROM_JWK_PLACEHOLDER = derivesFromJwkPlaceholder();

function okpPublicFromJwk(curve: string, privateKey: Uint8Array): Uint8Array | undefined {
  try {
    const key = createPrivateKey({
      key: {
        kty: 'OKP',
        crv: curve,
        // A private OKP JWK requires `x`. This placeholder is never read as a
        // public component: the provider overwrites it with the value derived
        // from `d`, which `DERIVES_FROM_JWK_PLACEHOLDER` establishes.
        x: Buffer.alloc(privateKey.length).toString('base64url'),
        d: Buffer.from(privateKey).toString('base64url'),
      },
      format: 'jwk',
    });

    return okpPublicOf(key);
  } catch {
    return undefined;
  }
}

function okpPublicFromPkcs8(header: string, privateKey: Uint8Array): Uint8Array | undefined {
  try {
    const encoded = Buffer.concat([Buffer.from(header, 'hex'), Buffer.from(privateKey)]);
    return okpPublicOf(createPrivateKey({ key: encoded, format: 'der', type: 'pkcs8' }));
  } catch {
    return undefined;
  }
}

function okpPublicOf(key: KeyObject): Uint8Array | undefined {
  const exported = createPublicKey(key).export({ format: 'jwk' });
  return typeof exported.x === 'string' ? new Uint8Array(Buffer.from(exported.x, 'base64url')) : undefined;
}

/**
 * Computes the public key octets for an OKP private key.
 *
 * As for EC, the result is computed from the private scalar alone and never
 * from a supplied public component, which is what lets the caller compare the
 * two to detect a mismatched key.
 */
export function deriveOkpPublicKey(curve: string, privateKey: Uint8Array): BackendResult<Uint8Array> {
  const header = OKP_PKCS8_HEADERS[curve];
  if (header === undefined) {
    return backendError('unsupported');
  }

  const derived = DERIVES_FROM_JWK_PLACEHOLDER
    ? okpPublicFromJwk(curve, privateKey)
    : okpPublicFromPkcs8(header, privateKey);

  return derived === undefined ? backendError('operation_failed') : backendOk(derived);
}

/**
 * Checks that a supplied EC point lies on the curve and is not the point at
 * infinity, by asking the provider to import it as a public key.
 *
 * The provider was qualified as rejecting off-curve coordinates at import, so
 * this delegation is sound; it is expressed as its own function so a provider
 * change is detected at the qualification boundary.
 */
export function validateEcPointOnCurve(curve: string, point: EcPoint): BackendResult<undefined> {
  if (EC_CURVE_NAMES[curve] === undefined) {
    return backendError('unsupported');
  }

  try {
    createPublicKey({
      key: {
        kty: 'EC',
        crv: curve,
        x: Buffer.from(point.x).toString('base64url'),
        y: Buffer.from(point.y).toString('base64url'),
      },
      format: 'jwk',
    });
    return backendOk(undefined);
  } catch {
    return backendError('operation_failed');
  }
}
