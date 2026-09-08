/**
 * Strict Base64url for JOSE: the URL-safe alphabet, no
 * padding, and no whitespace or line breaks. This differs from the ordinary
 * Base64 used by certificate chains, which is padded and uses `+` and `/`.
 *
 * Node's `Buffer.from(s, 'base64url')` is unusable here: it silently ignores
 * invalid characters, accepts padding and whitespace, and discards nonzero
 * unused bits, so it cannot distinguish a canonical encoding from a malleable
 * one. Several distinct inputs would decode to the same octets, which lets an
 * attacker vary a token's bytes without changing its meaning. Decoding
 * therefore validates the alphabet and the final character's unused bits
 * directly, so that exactly one encoding maps to any given octet string.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Maps a character code to its 6-bit value, or -1 when outside the alphabet. */
const DECODE_TABLE: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i += 1) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

export type Base64urlFailure =
  /** A character outside the URL-safe alphabet, including `=` and whitespace. */
  | 'alphabet'
  /** Length congruent to one modulo four, which encodes no whole octet. */
  | 'length'
  /** Nonzero unused bits in the final character, a non-canonical encoding. */
  | 'unused_bits'
  /** Decoded size would exceed the caller's budget. */
  | 'too_large';

export type Base64urlResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: Base64urlFailure };

/** Decoded octet count for a valid unpadded Base64url length. */
function decodedLength(encodedLength: number): number {
  return Math.floor((encodedLength * 3) / 4);
}

/**
 * Unpadded Base64url length needed to carry a given number of octets.
 *
 * Lets a bound stated in decoded octets be applied to an encoded component
 * without decoding it first, so an oversized one is refused before allocation.
 */
export function encodedLengthFor(decodedBytes: number): number {
  return Math.ceil((decodedBytes * 4) / 3);
}

/**
 * Decodes strict unpadded Base64url.
 *
 * `maxDecodedBytes` is checked before allocation so that an oversized component
 * cannot force a large allocation before its size limit is applied.
 */
export function decodeBase64url(input: string, maxDecodedBytes: number): Base64urlResult {
  const length = input.length;

  // A group of one leftover character carries only 6 bits and cannot complete
  // an octet, so it is invalid regardless of its value.
  if (length % 4 === 1) {
    return { ok: false, failure: 'length' };
  }

  const outputLength = decodedLength(length);
  if (outputLength > maxDecodedBytes) {
    return { ok: false, failure: 'too_large' };
  }

  const output = new Uint8Array(outputLength);
  let outputIndex = 0;
  let accumulator = 0;
  let bitsHeld = 0;

  for (let i = 0; i < length; i += 1) {
    const code = input.charCodeAt(i);
    const value = code < 128 ? DECODE_TABLE[code]! : -1;
    if (value < 0) {
      return { ok: false, failure: 'alphabet' };
    }

    accumulator = (accumulator << 6) | value;
    bitsHeld += 6;

    if (bitsHeld >= 8) {
      bitsHeld -= 8;
      output[outputIndex] = (accumulator >>> bitsHeld) & 0xff;
      outputIndex += 1;
    }
  }

  // The trailing 2 or 4 bits of the final character are not part of any octet
  // and MUST be zero; otherwise several distinct encodings decode alike.
  if (bitsHeld > 0 && (accumulator & ((1 << bitsHeld) - 1)) !== 0) {
    return { ok: false, failure: 'unused_bits' };
  }

  return { ok: true, bytes: output };
}

export function encodeBase64url(bytes: Uint8Array): string {
  let output = '';
  let accumulator = 0;
  let bitsHeld = 0;

  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bitsHeld += 8;

    while (bitsHeld >= 6) {
      bitsHeld -= 6;
      output += ALPHABET[(accumulator >>> bitsHeld) & 0x3f];
    }
  }

  if (bitsHeld > 0) {
    // Remaining bits are left-aligned into a final character, leaving the
    // unused low-order bits zero as canonical decoding requires.
    output += ALPHABET[(accumulator << (6 - bitsHeld)) & 0x3f];
  }

  return output;
}
