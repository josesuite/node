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

import { encodeUtf8 } from './utf8.ts';

export type AsciiResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: 'non_ascii' };

export function encodeAscii(input: string): AsciiResult {
  // Native encoding pays off for longer components; the loop is faster for headers.
  if (input.length >= 256) {
    return /[\u0080-\uffff]/.test(input) ? { ok: false, failure: 'non_ascii' } : { ok: true, bytes: encodeUtf8(input) };
  }

  const bytes = new Uint8Array(input.length);

  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code > 0x7f) {
      return { ok: false, failure: 'non_ascii' };
    }
    bytes[i] = code;
  }

  return { ok: true, bytes };
}

export function isAscii(input: string): boolean {
  for (let i = 0; i < input.length; i += 1) {
    if (input.charCodeAt(i) > 0x7f) {
      return false;
    }
  }
  return true;
}
