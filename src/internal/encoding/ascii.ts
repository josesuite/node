/**
 * Conversion of a string to its ASCII octets.
 *
 * Defined only for ASCII input, so a non-ASCII code point is a caller error
 * rather than something to transcode. The signing-input and additional
 * authenticated data formulas are defined over ASCII octets of components that
 * are already restricted to the Base64url alphabet and periods; silently
 * encoding a non-ASCII character would produce authenticated bytes that differ
 * from what the caller believes was authenticated.
 */

export type AsciiResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: 'non_ascii' };

const ENCODER = new TextEncoder();

/**
 * Inputs up to this length are written by the character loop; longer inputs
 * by the native encoder.
 *
 * The loop has no fixed call cost, which makes it the faster path for short
 * inputs. The bound also matches the size up to which V8 keeps a typed array's
 * storage inside the JS heap: the native encoder requires an external backing
 * store and would force one to be created for such a target. A target holding
 * more than 64 octets already has an external store.
 */
const NATIVE_THRESHOLD = 64;

/**
 * Writes the ASCII octets of `input` into `target` at `offset`, which must
 * already have room for `input.length` octets.
 *
 * Returns false when any character is outside ASCII. The target may then hold
 * a partial write, so a caller must discard it on failure.
 *
 * The native encoder writes UTF-8, which coincides with ASCII exactly when
 * every character is a single octet. Equal `read` and `written` counts that
 * both match the input length establish that, since any character above
 * 0x7F encodes to at least two octets and cannot make the counts agree.
 */
export function writeAscii(input: string, target: Uint8Array, offset: number): boolean {
  const length = input.length;

  if (length <= NATIVE_THRESHOLD) {
    for (let i = 0; i < length; i += 1) {
      const code = input.charCodeAt(i);
      if (code > 0x7f) {
        return false;
      }
      target[offset + i] = code;
    }
    return true;
  }

  const result = ENCODER.encodeInto(input, target.subarray(offset, offset + length));
  return result.read === length && result.written === length;
}

export function encodeAscii(input: string): AsciiResult {
  const bytes = new Uint8Array(input.length);
  return writeAscii(input, bytes, 0) ? { ok: true, bytes } : { ok: false, failure: 'non_ascii' };
}

export function isAscii(input: string): boolean {
  for (let i = 0; i < input.length; i += 1) {
    if (input.charCodeAt(i) > 0x7f) {
      return false;
    }
  }
  return true;
}
