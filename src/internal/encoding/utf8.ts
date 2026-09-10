/**
 * UTF-8 decoding for untrusted JOSE input.
 *
 * `TextDecoder` in fatal mode already rejects malformed sequences, overlong
 * encodings, surrogate code points, and out-of-range values, so the decoding
 * itself is delegated rather than reimplemented. One behaviour must be
 * corrected: `ignoreBOM` defaults to false, which silently *removes* a leading
 * U+FEFF. A byte-order mark must be rejected instead, because stripping it
 * would make two different byte sequences decode to the same text, and the
 * bytes are what later gets authenticated.
 */

/**
 * Shared because a non-streaming `decode` call carries no state between
 * invocations, so one instance serves every caller and avoids allocating a
 * decoder per document parsed.
 */
export const FATAL_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const ENCODER = new TextEncoder();

export type Utf8Failure =
  /** Malformed, overlong, or surrogate-encoding byte sequence. */
  | 'malformed'
  /** Leading U+FEFF byte-order mark, which the parser rejects. */
  | 'byte_order_mark';

export type Utf8Result =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly failure: Utf8Failure };

export function decodeUtf8(bytes: Uint8Array): Utf8Result {
  let text: string;
  try {
    text = FATAL_DECODER.decode(bytes);
  } catch {
    // The only documented throw from a fatal TextDecoder is a decoding error.
    return { ok: false, failure: 'malformed' };
  }

  // With `ignoreBOM: true` a leading U+FEFF survives decoding as a character,
  // which is what allows it to be rejected rather than silently stripped.
  if (text.charCodeAt(0) === 0xfeff) {
    return { ok: false, failure: 'byte_order_mark' };
  }

  return { ok: true, text };
}

export function encodeUtf8(text: string): Uint8Array {
  return ENCODER.encode(text);
}

/** UTF-8 octet length without materializing the encoded bytes. */
export function utf8Length(text: string): number {
  return Buffer.byteLength(text, 'utf8');
}
