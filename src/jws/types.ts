/**
 * JWS payload modes and signing-input construction.
 *
 * The signing input is built from the *original received* components, never
 * from anything reserialized out of parsed JSON. Whitespace and member order
 * change the authenticated bytes without changing the decoded value, so
 * regenerating a protected header would authenticate different bytes than the
 * producer signed.
 */

import { concatBytes } from '../internal/bytes.ts';
import { encodeAscii } from '../internal/encoding/ascii.ts';
import { encodeBase64url } from '../internal/encoding/base64url.ts';

/**
 * Whether the payload travels inside the object or is supplied separately.
 *
 * Detachment is always an explicit caller choice. It is never inferred from an
 * empty component, and external content is never fetched from an address found
 * in the token.
 */
export type PayloadLocation = 'attached' | 'detached';

/**
 * The payload as it participates in the signing input.
 *
 * `encoded` is the default. When false, the raw payload octets are
 * authenticated directly, which requires the producer to have marked the
 * choice critical so a consumer cannot silently build a different input.
 */
export interface PayloadMode {
  readonly encoded: boolean;
  readonly location: PayloadLocation;
}

export type SigningInputFailure =
  /** A component contained a byte outside the ASCII range it is defined over. */
  | 'non_ascii_component'
  /** Unencoded inline payload contains a character the accepted form excludes. */
  | 'payload_character_not_permitted'
  /** Both an embedded payload and external content were supplied. */
  | 'ambiguous_payload_source';

export type SigningInputResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: SigningInputFailure };

/**
 * Characters permitted in an inline unencoded payload.
 *
 * Restricted to printable ASCII so that acceptance never depends on the
 * Unicode version a runtime happens to ship. Compact form additionally
 * excludes the period, which would otherwise be read as a component separator.
 * Anything outside this range uses detached mode instead.
 */
function isPermittedUnencodedChar(code: number, allowPeriod: boolean): boolean {
  if (code === 0x2e) {
    return allowPeriod;
  }
  return code >= 0x20 && code <= 0x7e;
}

export function validateInlineUnencodedPayload(payload: Uint8Array, allowPeriod: boolean): SigningInputResult {
  for (const byte of payload) {
    if (!isPermittedUnencodedChar(byte, allowPeriod)) {
      return { ok: false, failure: 'payload_character_not_permitted' };
    }
  }
  return { ok: true, bytes: payload };
}

/**
 * Builds the exact octets a signature covers.
 *
 * `protectedComponent` is the original received Base64url string, not a
 * re-encoding of the decoded header. For an encoded payload the received
 * payload component is likewise used verbatim, so that a signature verifies
 * against precisely the bytes that arrived.
 */
export function buildSigningInput(
  protectedComponent: string,
  payload: { readonly component: string } | { readonly octets: Uint8Array },
): SigningInputResult {
  const prefix = encodeAscii(`${protectedComponent}.`);
  if (!prefix.ok) {
    return { ok: false, failure: 'non_ascii_component' };
  }

  if ('component' in payload) {
    const encoded = encodeAscii(payload.component);
    if (!encoded.ok) {
      return { ok: false, failure: 'non_ascii_component' };
    }
    return { ok: true, bytes: concatBytes(prefix.bytes, encoded.bytes) };
  }

  // Unencoded mode appends the payload octets directly after the period,
  // with no Base64url layer in between.
  return { ok: true, bytes: concatBytes(prefix.bytes, payload.octets) };
}

/**
 * Builds the signing input for a payload this library is about to encode.
 *
 * Creation and verification share `buildSigningInput` so that the bytes signed
 * and the bytes verified cannot drift apart.
 */
export function buildSigningInputForOctets(
  protectedComponent: string,
  payload: Uint8Array,
  mode: PayloadMode,
): SigningInputResult {
  if (mode.encoded) {
    return buildSigningInput(protectedComponent, { component: encodeBase64url(payload) });
  }
  return buildSigningInput(protectedComponent, { octets: payload });
}
