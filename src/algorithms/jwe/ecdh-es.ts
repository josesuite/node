/**
 * ECDH-ES key agreement.
 *
 * The sender generates a fresh ephemeral key pair for every agreement and
 * publishes only its public half as `epk`. Reusing an ephemeral key across
 * messages would derive the same CEK for each, collapsing them into one key and
 * defeating the point of the ephemeral half.
 *
 * The shared secret is the curve's fixed-width X coordinate, including leading
 * zero bytes. This is the raw agreement output and is never used as a key
 * directly; it goes through the KDF, which is what binds the derived key to the
 * algorithm and the party information.
 *
 * WebCrypto is used for every curve it carries. It rejects a private JWK whose
 * public point does not match the private scalar, which the native module
 * accepts, so importing through it removes a mismatched-pair case rather than
 * relying on a separate check. X448 is absent from at least one supported
 * runtime, so that curve alone falls back to the native module.
 *
 * The ephemeral private half never leaves the provider: the generated handle
 * performs the agreement directly and only the public half is exported, so
 * the scalar is never held in JS memory.
 *
 * Ephemeral-static agreement gives no forward secrecy: an attacker who records
 * the object and later obtains the recipient's static private key recovers the
 * plaintext.
 */

import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto';

import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { constantTime } from '../../internal/crypto/constant-time.ts';
import { attempt, base64url, importCached, importJwk } from '../../internal/crypto/webcrypto.ts';
import type { EcMaterial, OkpMaterial } from '../../key/validation.ts';

const EC_CURVES: ReadonlySet<string> = new Set(['P-256', 'P-384', 'P-521']);
const XDH_CURVES: ReadonlySet<string> = new Set(['X25519', 'X448']);

/** Curves absent from at least one supported runtime's WebCrypto. */
const NATIVE_ONLY_CURVES: ReadonlySet<string> = new Set(['X448']);

/** Field width in bytes for each supported agreement curve. */
const FIELD_BYTES: Readonly<Record<string, number>> = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  X25519: 32,
  X448: 56,
});

export function agreementFieldBytes(curve: string): number | undefined {
  return FIELD_BYTES[curve];
}

/** Whether a key's curve can be used for agreement at all. */
export function isAgreementCurve(curve: string): boolean {
  return EC_CURVES.has(curve) || XDH_CURVES.has(curve);
}

/** The public half of a sender's ephemeral key, as published in `epk`. */
export interface EphemeralPublic {
  readonly curve: string;
  readonly x: Uint8Array;
  /** Present for the NIST curves only. */
  readonly y: Uint8Array | undefined;
}

export interface EphemeralAgreement {
  readonly secret: Uint8Array;
  readonly ephemeralPublicKey: EphemeralPublic;
}

interface PeerPoint {
  readonly curve: string;
  readonly x: Uint8Array;
  readonly y?: Uint8Array | undefined;
}

/**
 * Generates an ephemeral key on the peer's curve and agrees with the peer.
 *
 * This is the sender side. The private half stays inside the provider handle
 * for the duration of this call and is unreachable afterwards.
 *
 * `handleToken` memoizes the import of the peer's static public key for a
 * long-lived recipient record, under the rule every handle cache relies on:
 * the record is bound to one algorithm and one operation for its lifetime.
 */
export async function agreeEphemeral(
  peer: PeerPoint,
  handleToken?: object,
): Promise<BackendResult<EphemeralAgreement>> {
  const fieldBytes = FIELD_BYTES[peer.curve];
  if (fieldBytes === undefined) {
    return backendError('unsupported');
  }

  const agreed = XDH_CURVES.has(peer.curve)
    ? await ephemeralXdh(peer, fieldBytes, handleToken)
    : await ephemeralEc(peer, fieldBytes, handleToken);
  if (!agreed.ok) {
    return agreed;
  }

  const checked = checkSecret(agreed.value.secret, fieldBytes);
  return checked.ok ? agreed : checked;
}

export interface EphemeralEcKey {
  readonly curve: string;
  readonly x: Uint8Array;
  readonly y: Uint8Array;
  readonly d: Uint8Array;
}

export interface EphemeralOkpKey {
  readonly curve: string;
  readonly x: Uint8Array;
  readonly d: Uint8Array;
}

export async function generateEphemeralEc(curve: string): Promise<BackendResult<EphemeralEcKey>> {
  if (!EC_CURVES.has(curve)) {
    return backendError('unsupported');
  }

  const result = await attempt(async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits']);
    return crypto.subtle.exportKey('jwk', pair.privateKey);
  });

  if (!result.ok) {
    return result;
  }

  const jwk = result.value;
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || typeof jwk.d !== 'string') {
    return backendError('operation_failed');
  }

  return backendOk({
    curve,
    x: decode(jwk.x),
    y: decode(jwk.y),
    d: decode(jwk.d),
  });
}

export async function generateEphemeralOkp(curve: string): Promise<BackendResult<EphemeralOkpKey>> {
  if (!XDH_CURVES.has(curve)) {
    return backendError('unsupported');
  }

  if (NATIVE_ONLY_CURVES.has(curve)) {
    try {
      const generated = generateKeyPairSync(curve.toLowerCase() as 'x25519');
      const jwk = generated.privateKey.export({ format: 'jwk' });
      if (typeof jwk.x !== 'string' || typeof jwk.d !== 'string') {
        return backendError('operation_failed');
      }
      return backendOk({ curve, x: decode(jwk.x), d: decode(jwk.d) });
    } catch {
      return backendError('operation_failed');
    }
  }

  const result = await attempt(async () => {
    const pair = await crypto.subtle.generateKey(curve, true, ['deriveBits']);
    return crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).privateKey);
  });

  if (!result.ok) {
    return result;
  }

  const jwk = result.value;
  if (typeof jwk.x !== 'string' || typeof jwk.d !== 'string') {
    return backendError('operation_failed');
  }

  return backendOk({ curve, x: decode(jwk.x), d: decode(jwk.d) });
}

/**
 * Agrees using whichever family the recipient key belongs to.
 *
 * A signing key is never converted into an agreement key: the curve decides,
 * and the Edwards signing curves are simply not agreement curves here.
 *
 * `handleToken` memoizes the private-key import for a long-lived key record,
 * under the same soundness rule as the signature adapters: the record is bound
 * to one algorithm and one operation for its whole lifetime.
 */
export async function agree(
  ownPrivate: EcMaterial | OkpMaterial,
  peer: PeerPoint,
  handleToken?: object,
): Promise<BackendResult<Uint8Array>> {
  if (ownPrivate.d === undefined) {
    return backendError('operation_failed');
  }
  // Both halves must name the same curve; agreeing across curves is not a
  // meaningful operation and a mismatch means one of them was substituted.
  if (ownPrivate.curve !== peer.curve) {
    return backendError('operation_failed');
  }

  const fieldBytes = agreementFieldBytes(peer.curve);
  if (fieldBytes === undefined) {
    return backendError('unsupported');
  }

  const secret = XDH_CURVES.has(peer.curve)
    ? await agreeXdh(peer.curve, ownPrivate.d, (ownPrivate as OkpMaterial).x, peer.x, handleToken)
    : await agreeEc(peer.curve, ownPrivate as EcMaterial, peer, handleToken);

  if (!secret.ok) {
    return secret;
  }

  return checkSecret(secret.value, fieldBytes);
}

/**
 * Rejects a secret of the wrong width or one forced to zero by a low-order
 * peer point, clearing it in either case.
 */
function checkSecret(secret: Uint8Array, fieldBytes: number): BackendResult<Uint8Array> {
  // A width other than the field size would silently change the KDF input.
  if (secret.length !== fieldBytes) {
    secret.fill(0);
    return backendError('operation_failed');
  }

  // An all-zero result means the peer supplied a low-order point that forces
  // the secret regardless of the private key, letting anyone derive the CEK.
  if (constantTime.equal(secret, new Uint8Array(fieldBytes))) {
    secret.fill(0);
    return backendError('operation_failed');
  }

  return backendOk(secret);
}

function ecPeerJwk(curve: string, peer: PeerPoint): JsonWebKey {
  return { kty: 'EC', crv: curve, x: base64url(peer.x), y: base64url(peer.y!) };
}

async function ephemeralEc(
  peer: PeerPoint,
  fieldBytes: number,
  handleToken: object | undefined,
): Promise<BackendResult<EphemeralAgreement>> {
  if (peer.y === undefined) {
    return backendError('operation_failed');
  }
  const curve = peer.curve;

  const result = await attempt(async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits']);
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    // Import validates the peer point lies on the curve, which is what rejects
    // an invalid-curve point supplied by an attacker.
    const publicKey = await importCached(handleToken, () =>
      importJwk(ecPeerJwk(curve, peer), { name: 'ECDH', namedCurve: curve }, []),
    );
    const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, pair.privateKey, fieldBytes * 8);
    return { publicJwk, secret };
  });
  if (!result.ok) {
    return result;
  }

  const { publicJwk, secret } = result.value;
  if (typeof publicJwk.x !== 'string' || typeof publicJwk.y !== 'string') {
    return backendError('operation_failed');
  }

  return backendOk({
    secret: new Uint8Array(secret),
    ephemeralPublicKey: { curve, x: decode(publicJwk.x), y: decode(publicJwk.y) },
  });
}

async function ephemeralXdh(
  peer: PeerPoint,
  fieldBytes: number,
  handleToken: object | undefined,
): Promise<BackendResult<EphemeralAgreement>> {
  const curve = peer.curve;

  if (NATIVE_ONLY_CURVES.has(curve)) {
    try {
      const generated = generateKeyPairSync(curve.toLowerCase() as 'x448');
      const publicJwk = generated.publicKey.export({ format: 'jwk' });
      if (typeof publicJwk.x !== 'string') {
        return backendError('operation_failed');
      }
      const peerKey = createPublicKey({ key: { kty: 'OKP', crv: curve, x: base64url(peer.x) }, format: 'jwk' });
      const secret = diffieHellman({ privateKey: generated.privateKey, publicKey: peerKey });
      return backendOk({
        secret: new Uint8Array(secret),
        ephemeralPublicKey: { curve, x: decode(publicJwk.x), y: undefined },
      });
    } catch {
      return backendError('operation_failed');
    }
  }

  const result = await attempt(async () => {
    const pair = (await crypto.subtle.generateKey(curve, true, ['deriveBits'])) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const peerKey = await importCached(handleToken, () =>
      importJwk({ kty: 'OKP', crv: curve, x: base64url(peer.x) }, curve, []),
    );
    const secret = await crypto.subtle.deriveBits({ name: curve, public: peerKey }, pair.privateKey, fieldBytes * 8);
    return { publicJwk, secret };
  });
  if (!result.ok) {
    return result;
  }

  const { publicJwk, secret } = result.value;
  if (typeof publicJwk.x !== 'string') {
    return backendError('operation_failed');
  }

  return backendOk({
    secret: new Uint8Array(secret),
    ephemeralPublicKey: { curve, x: decode(publicJwk.x), y: undefined },
  });
}

async function agreeEc(
  curve: string,
  own: EcMaterial,
  peer: PeerPoint,
  handleToken: object | undefined,
): Promise<BackendResult<Uint8Array>> {
  if (peer.y === undefined) {
    return backendError('operation_failed');
  }
  const fieldBytes = FIELD_BYTES[curve]!;

  const result = await attempt(async () => {
    const privateKey = await importCached(handleToken, () =>
      importJwk(
        { kty: 'EC', crv: curve, x: base64url(own.x), y: base64url(own.y), d: base64url(own.d!) },
        { name: 'ECDH', namedCurve: curve },
        ['deriveBits'],
      ),
    );
    // Import validates the peer point lies on the curve, which is what rejects
    // an invalid-curve point supplied by an attacker.
    const publicKey = await importJwk(ecPeerJwk(curve, peer), { name: 'ECDH', namedCurve: curve }, []);

    return crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, fieldBytes * 8);
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}

async function agreeXdh(
  curve: string,
  privateKey: Uint8Array,
  ownPublic: Uint8Array,
  peerPublicKey: Uint8Array,
  handleToken: object | undefined,
): Promise<BackendResult<Uint8Array>> {
  const fieldBytes = FIELD_BYTES[curve]!;

  if (NATIVE_ONLY_CURVES.has(curve)) {
    try {
      const own = createPrivateKey({
        key: {
          kty: 'OKP',
          crv: curve,
          x: base64url(ownPublic),
          d: base64url(privateKey),
        },
        format: 'jwk',
      });
      const peer = createPublicKey({
        key: { kty: 'OKP', crv: curve, x: base64url(peerPublicKey) },
        format: 'jwk',
      });
      return backendOk(new Uint8Array(diffieHellman({ privateKey: own, publicKey: peer })));
    } catch {
      return backendError('operation_failed');
    }
  }

  const result = await attempt(async () => {
    const own = await importCached(handleToken, () =>
      importJwk({ kty: 'OKP', crv: curve, x: base64url(ownPublic), d: base64url(privateKey) }, curve, ['deriveBits']),
    );
    const peer = await importJwk({ kty: 'OKP', crv: curve, x: base64url(peerPublicKey) }, curve, []);
    return crypto.subtle.deriveBits({ name: curve, public: peer }, own, fieldBytes * 8);
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}

function decode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}
