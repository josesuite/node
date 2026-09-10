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

/**
 * Maps an ASCII character code to its 6-bit value, or -1 when outside the
 * alphabet.
 *
 * Deliberately covers only the ASCII range. A table spanning every UTF-16 code
 * unit would let a lookup skip its range test, but 64 KiB of resident memory is
 * a poor trade for that in a library, and the small table stays cache-resident.
 */
const DECODE_TABLE: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i += 1) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Resolves one character, treating anything outside ASCII as off-alphabet. */
function sextet(code: number): number {
  return code < 128 ? DECODE_TABLE[code]! : -1;
}

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

  // Whole groups of four characters yield three octets each. Handling a group at
  // a time keeps the alphabet check and the canonical-form check identical to a
  // per-character walk while removing the per-octet shift bookkeeping.
  const wholeGroups = length - (length % 4);
  let outputIndex = 0;

  for (let i = 0; i < wholeGroups; i += 4) {
    const a = sextet(input.charCodeAt(i));
    const b = sextet(input.charCodeAt(i + 1));
    const c = sextet(input.charCodeAt(i + 2));
    const d = sextet(input.charCodeAt(i + 3));

    // One test covers all four, since any value outside the alphabet is negative
    // and a bitwise or of the group keeps that sign bit.
    if ((a | b | c | d) < 0) {
      return { ok: false, failure: 'alphabet' };
    }

    output[outputIndex] = (a << 2) | (b >> 4);
    output[outputIndex + 1] = ((b & 0x0f) << 4) | (c >> 2);
    output[outputIndex + 2] = ((c & 0x03) << 6) | d;
    outputIndex += 3;
  }

  // A trailing group of two or three characters carries one or two octets. Its
  // final character holds 4 or 2 bits belonging to no octet, which MUST be zero;
  // otherwise several distinct encodings would decode alike.
  const remaining = length - wholeGroups;
  if (remaining !== 0) {
    const a = sextet(input.charCodeAt(wholeGroups));
    const b = sextet(input.charCodeAt(wholeGroups + 1));
    if ((a | b) < 0) {
      return { ok: false, failure: 'alphabet' };
    }

    if (remaining === 2) {
      if ((b & 0x0f) !== 0) {
        return { ok: false, failure: 'unused_bits' };
      }
      output[outputIndex] = (a << 2) | (b >> 4);
    } else {
      const c = sextet(input.charCodeAt(wholeGroups + 2));
      if (c < 0) {
        return { ok: false, failure: 'alphabet' };
      }
      if ((c & 0x03) !== 0) {
        return { ok: false, failure: 'unused_bits' };
      }
      output[outputIndex] = (a << 2) | (b >> 4);
      output[outputIndex + 1] = ((b & 0x0f) << 4) | (c >> 2);
    }
  }

  return { ok: true, bytes: output };
}

/**
 * Encodes strict unpadded Base64url.
 *
 * Encoding is delegated to the runtime's native encoder, unlike decoding: every
 * octet string has exactly one unpadded Base64url encoding, so there is no
 * malleability for a lenient implementation to introduce here. Node emits the
 * URL-safe alphabet with no padding, which is the form JOSE requires, and does
 * so an order of magnitude faster than a per-character loop.
 *
 * The view's own offsets are passed explicitly so that a `Uint8Array` backed by
 * a larger `ArrayBuffer` encodes its own bytes and never its neighbours'.
 */
export function encodeBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}
