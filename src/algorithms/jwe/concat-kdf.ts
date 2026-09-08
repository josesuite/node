/**
 * Concat KDF for ECDH-ES key agreement.
 *
 * This is the NIST one-step KDF with SHA-256, fixed regardless of the curve or
 * the content algorithm. It is not interchangeable with HKDF or with a
 * provider's generic session-key helper: the OtherInfo encoding below is what
 * binds the derived key to the algorithm and party information, and a different
 * KDF would derive a different key from identical inputs.
 *
 * Every field is length-prefixed so that no two distinct inputs can produce the
 * same OtherInfo byte string. Without the prefixes an attacker could shift
 * bytes between adjacent fields and derive the same key under different claimed
 * parameters.
 */

import { createHash } from 'node:crypto';

const SHA256_BYTES = 32;

/** Big-endian 32-bit length prefix followed by the data itself. */
function lengthPrefixed(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + data.length);
  new DataView(out.buffer).setUint32(0, data.length);
  out.set(data, 4);
  return out;
}

function uint32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

export interface ConcatKdfInput {
  /**
   * ASCII of `enc` for direct agreement, or of `alg` when the derived key wraps
   * a separately generated CEK. Using the wrong one derives a key the peer will
   * not reproduce, which is why the caller decides it explicitly.
   */
  readonly algorithmId: Uint8Array;
  /** Decoded `apu`, or empty when the header omits it. */
  readonly partyUInfo: Uint8Array;
  /** Decoded `apv`, or empty when the header omits it. */
  readonly partyVInfo: Uint8Array;
  readonly keyBytes: number;
}

/**
 * Derives a key of exactly `keyBytes` from the shared secret.
 *
 * `sharedSecret` must be the curve's fixed-width representation including any
 * leading zero bytes. Stripping them, as a bignum conversion would, changes the
 * hash input and yields a key the peer cannot reproduce for roughly one in 256
 * agreements. A failure that appears intermittent is easily mistaken for
 * something else.
 */
export function concatKdf(sharedSecret: Uint8Array, input: ConcatKdfInput): Uint8Array {
  const otherInfo = new Uint8Array([
    ...lengthPrefixed(input.algorithmId),
    ...lengthPrefixed(input.partyUInfo),
    ...lengthPrefixed(input.partyVInfo),
    ...uint32be(input.keyBytes * 8),
    // SuppPrivInfo is empty and contributes no bytes at all, not a zero-length
    // prefix.
  ]);

  const rounds = Math.ceil(input.keyBytes / SHA256_BYTES);
  const derived = new Uint8Array(rounds * SHA256_BYTES);

  for (let round = 1; round <= rounds; round += 1) {
    const hash = createHash('sha256');
    // The counter starts at one, not zero; starting elsewhere shifts every
    // derived byte.
    hash.update(uint32be(round));
    hash.update(sharedSecret);
    hash.update(otherInfo);
    // The digest is itself derived key material, so the provider's allocation is
    // cleared once transferred rather than only the copy in `derived`.
    const block = hash.digest();
    derived.set(block, (round - 1) * SHA256_BYTES);
    block.fill(0);
  }

  const key = derived.slice(0, input.keyBytes);
  derived.fill(0);
  return key;
}

/**
 * Builds the party field for a header member that may be absent.
 *
 * An absent field and a present field with empty content both contribute only a
 * zero-length prefix, so this helper deliberately treats them the same.
 */
export function partyInfo(decoded: Uint8Array | undefined): Uint8Array {
  return decoded ?? new Uint8Array(0);
}
