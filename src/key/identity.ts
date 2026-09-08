/**
 * Key-material equality and HMAC authentication-domain equivalence.
 *
 * These comparisons decide distinct-signer counting, duplicate rejection, and
 * the one-principal-per-key rule. They are defined over exact members rather
 * than left to the obvious approaches, because comparing serialized bytes,
 * `kid` values, backend handles, or object identity would each give a different
 * answer for the same input, and threshold decisions would then depend on which
 * one an implementation happened to pick.
 */

import { constantTime } from '../internal/crypto/constant-time.ts';

/**
 * The canonical members compared for each key type.
 *
 * Metadata is deliberately absent: `kid`, `use`, `key_ops`, and certificate
 * members describe how a key is labelled, not which key it is. Optional `alg`
 * is likewise excluded, except for post-quantum keys, where it is required and
 * fixes how the public value is interpreted, so it is part of the key itself.
 */
export type KeyIdentity =
  | {
      readonly kty: 'RSA';
      readonly n: Uint8Array;
      readonly e: Uint8Array;
    }
  | {
      readonly kty: 'EC';
      readonly crv: string;
      readonly x: Uint8Array;
      readonly y: Uint8Array;
    }
  | {
      readonly kty: 'OKP';
      readonly crv: string;
      readonly x: Uint8Array;
    }
  | {
      readonly kty: 'AKP';
      readonly alg: string;
      readonly pub: Uint8Array;
    }
  | {
      readonly kty: 'oct';
      readonly k: Uint8Array;
    };

/** Ordinary comparison for public values, where timing carries no secret. */
function publicBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
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

/**
 * Whether two validated keys are the same cryptographic key.
 *
 * Symmetric keys are compared in constant time because their octets are the
 * secret itself, and an early-exit comparison would leak how many leading bytes
 * a guess got right. Asymmetric material is public, so ordinary comparison is
 * used there.
 *
 * A private key must be reduced to its canonical public projection before being
 * passed here, so that a key and its own public half compare as one key.
 */
export function sameKeyMaterial(a: KeyIdentity, b: KeyIdentity): boolean {
  // Narrowing both operands together keeps each branch type-safe without
  // asserting that `b` matches `a`'s shape.
  if (a.kty === 'RSA' && b.kty === 'RSA') {
    return publicBytesEqual(a.n, b.n) && publicBytesEqual(a.e, b.e);
  }

  if (a.kty === 'EC' && b.kty === 'EC') {
    // Discriminators compare exactly, with no case folding or alias expansion:
    // a curve name is an identifier, not free text.
    return a.crv === b.crv && publicBytesEqual(a.x, b.x) && publicBytesEqual(a.y, b.y);
  }

  if (a.kty === 'OKP' && b.kty === 'OKP') {
    return a.crv === b.crv && publicBytesEqual(a.x, b.x);
  }

  if (a.kty === 'AKP' && b.kty === 'AKP') {
    return a.alg === b.alg && publicBytesEqual(a.pub, b.pub);
  }

  if (a.kty === 'oct' && b.kty === 'oct') {
    return constantTime.equal(a.k, b.k);
  }

  return false;
}
