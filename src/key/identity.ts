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

import { createHash, timingSafeEqual } from 'node:crypto';

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

/**
 * Whether equality of these two keys' public representations also establishes
 * that they belong to the same holder.
 *
 * For the agreement curves it does not: several publicly computable public
 * values produce the same shared secrets, so unequal representations are not
 * proof of distinct holders. Where a policy depends on distinct principals,
 * trusted provisioning has to supply an underlying identity instead. The
 * implementation does not compute curve equivalence itself.
 */
export function representationImpliesHolderIdentity(identity: KeyIdentity): boolean {
  if (identity.kty !== 'OKP') {
    return true;
  }
  return identity.crv !== 'X25519' && identity.crv !== 'X448';
}

/** Hash and block size for each HMAC algorithm, used for key preprocessing. */
const HMAC_PARAMETERS: Readonly<Record<string, { hash: string; blockBytes: number }>> = Object.freeze({
  HS256: { hash: 'sha256', blockBytes: 64 },
  HS384: { hash: 'sha384', blockBytes: 128 },
  HS512: { hash: 'sha512', blockBytes: 128 },
});

/**
 * Computes the effective HMAC key block for a secret.
 *
 * A key longer than the block size is hashed, and any key shorter than the
 * block size is zero-padded to it. That preprocessing means distinct secret
 * octets can still yield one authentication capability: a short key and its
 * zero-extended alias are equivalent, as are a long key and its hash.
 *
 * The returned block is secret material. It must never be exposed as an
 * identifier, thumbprint, log value, or diagnostic, because it is derived
 * directly from the key.
 */
function effectiveHmacBlock(secret: Uint8Array, algorithm: string): Uint8Array | undefined {
  const parameters = HMAC_PARAMETERS[algorithm];
  if (parameters === undefined) {
    return undefined;
  }

  const reduced =
    secret.length > parameters.blockBytes
      ? new Uint8Array(createHash(parameters.hash).update(secret).digest())
      : undefined;

  const block = new Uint8Array(parameters.blockBytes);
  block.set(reduced ?? secret);
  reduced?.fill(0);
  return block;
}

/**
 * Whether two HMAC keys bound to the same algorithm have one authentication
 * capability, and therefore cannot be assigned to different principals.
 *
 * Different secret octets are not sufficient evidence of different capability,
 * which is why this compares the preprocessed blocks rather than the keys.
 * Both keys must already have passed their own validation; this check must
 * never make an otherwise invalid key acceptable.
 */
export function sameHmacDomain(a: Uint8Array, b: Uint8Array, algorithm: string): boolean {
  const blockA = effectiveHmacBlock(a, algorithm);
  const blockB = effectiveHmacBlock(b, algorithm);
  if (blockA === undefined || blockB === undefined) {
    return false;
  }

  try {
    // Both blocks are the same fixed size for a given algorithm, so a
    // constant-time comparison is always applicable here.
    return timingSafeEqual(blockA, blockB);
  } finally {
    // The blocks are secret-derived and are not needed after the comparison.
    blockA.fill(0);
    blockB.fill(0);
  }
}
