/**
 * Compact JWE entry points.
 *
 * Compact form carries five components and nothing else: no unprotected
 * headers, no external AAD, and exactly one recipient. Those absences are
 * enforced rather than tolerated. Silently dropping an unprotected header a
 * caller supplied would emit an object missing data the caller believed was
 * present, and silently dropping external AAD would produce a tag over
 * different bytes than intended.
 *
 * The JSON flows do the work; this layer converts between the five-component
 * string and the shape those flows use. Keeping one implementation means the
 * two serializations cannot drift apart in what they accept.
 */

import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { type DecryptOptions, type DecryptResult, decryptParsed } from './decrypt.ts';
import { type EncryptOptions, encryptJson } from './encrypt.ts';
import { parseCompactJwe } from './parse.ts';

export type CompactEncryptResult =
  | { readonly ok: true; readonly token: string }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly stage: TrustStage;
      readonly reason: string;
    };

/** Options a Compact object cannot express, removed from the JSON set. */
export type CompactEncryptOptions = Omit<EncryptOptions, 'flattened' | 'externalAad'>;

function fail(category: ErrorCategory, reason: string, stage: TrustStage = 'configuration'): CompactEncryptResult {
  return { ok: false, category, stage, reason };
}

/**
 * Encrypts to exactly one recipient in Compact form.
 *
 * The Flattened JSON form is produced first and then reduced to five
 * components. That reduction is only sound because Compact can express nothing
 * the Flattened form cannot, which the checks below establish before any
 * cryptography runs.
 */
export async function encryptCompact(
  plaintext: Uint8Array,
  options: CompactEncryptOptions,
): Promise<CompactEncryptResult> {
  if (options.recipients.length !== 1) {
    return fail('policy_violation', 'compact_requires_single_recipient');
  }

  const recipient = options.recipients[0]!;
  if (recipient.unprotectedHeader !== undefined && Object.keys(recipient.unprotectedHeader).length > 0) {
    // Compact has nowhere to put these, and dropping them would emit an object
    // missing data the caller supplied.
    return fail('invalid_header', 'compact_has_no_unprotected_header');
  }

  const encrypted = await encryptJson(plaintext, { ...options, flattened: true });
  if (!encrypted.ok) {
    return encrypted;
  }

  const object = JSON.parse(encrypted.value) as Record<string, string | undefined>;
  const components = [
    object['protected'],
    // Direct modes emit no member at all; Compact spells that absence as an
    // empty component, which is the same state in that serialization.
    object['encrypted_key'] ?? '',
    object['iv'],
    object['ciphertext'],
    object['tag'],
  ];

  if (components.some((component) => component === undefined)) {
    return fail('backend_failure', 'incomplete_serialization', 'cryptographic');
  }

  return { ok: true, token: components.join('.') };
}

export async function decryptCompact(token: string, options: DecryptOptions): Promise<DecryptResult> {
  const parsed = parseCompactJwe(token, options.limits);
  if (!parsed.ok) {
    return { ok: false, category: parsed.category, stage: 'syntax', reason: parsed.reason };
  }

  return decryptParsed(parsed.value, options);
}
