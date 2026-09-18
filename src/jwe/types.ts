/**
 * JWE authenticated-data construction.
 *
 * The AEAD additional authenticated data is built by concatenating the
 * *original encoded* components, never the decoded octets they represent. Two
 * different encoded strings can decode to the same bytes, so authenticating the
 * decoded form would let an attacker rewrite the encoding while keeping the tag
 * valid.
 */

import { encodeAscii, writeAscii } from '../internal/encoding/ascii.ts';

export type AadFailure =
  /** A component held a byte outside the ASCII range it is defined over. */
  'non_ascii_component';

export type AadResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: AadFailure };

/**
 * Builds the additional authenticated data.
 *
 * With no external AAD the value is the protected-header string alone. With
 * external AAD present the two encoded strings are joined by a period. The
 * separator is what keeps the boundary unambiguous: without it, moving
 * characters between the header and the AAD would leave the concatenation
 * unchanged.
 *
 * An absent `aad` member and a present one are different inputs, which is why
 * an explicitly empty member is rejected at parse rather than treated as
 * absence. The two would otherwise produce different tags for what a caller
 * believes is the same object.
 */
export function buildAdditionalData(protectedComponent: string, aadComponent: string | undefined): AadResult {
  const header = encodeAscii(protectedComponent);
  if (!header.ok) {
    return { ok: false, failure: 'non_ascii_component' };
  }

  if (aadComponent === undefined) {
    return { ok: true, bytes: header.bytes };
  }

  // Assembled directly into one allocation of its final size; allocation is
  // the dominant cost at these sizes.
  const bytes = new Uint8Array(protectedComponent.length + 1 + aadComponent.length);
  bytes.set(header.bytes);
  bytes[protectedComponent.length] = 0x2e;
  if (!writeAscii(aadComponent, bytes, protectedComponent.length + 1)) {
    return { ok: false, failure: 'non_ascii_component' };
  }

  return { ok: true, bytes };
}
