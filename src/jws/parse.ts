/**
 * JSON JWS structural parsing.
 *
 * Flattened and General forms are parsed together because the rule that
 * separates them is a rejection: an object carrying both a `signatures` array
 * and top-level signature members is a hybrid and is refused. Deciding the form
 * first and then validating would have to guess which half to believe.
 *
 * Every component is kept as its original string. The signature covers the
 * received `protected` bytes, so reserializing the decoded header would
 * authenticate different octets whenever whitespace or member order differ.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import { isJsonObject, type JsonObject, type JsonValue } from '../internal/json/types.ts';
import type { Limits } from '../policy/limits.ts';

/** One signature entry, with its components exactly as received. */
export interface JsonSignatureEntry {
  /** Original Base64url protected header string. */
  readonly protectedComponent: string;
  /** Per-entry unprotected header, absent when the member is omitted. */
  readonly unprotectedHeader: JsonObject | undefined;
  /** Original Base64url signature string. */
  readonly signatureComponent: string;
}

export interface ParsedJsonJws {
  /**
   * Original `payload` string, absent in detached form.
   *
   * An empty string and an absent member are different states: the first is an
   * embedded empty payload, the second says the payload travels separately.
   */
  readonly payloadComponent: string | undefined;
  readonly signatures: readonly JsonSignatureEntry[];
  /** Which form the object was written in, for creation-side round trips. */
  readonly form: 'flattened' | 'general';
}

export type JsonParseResult =
  | { readonly ok: true; readonly value: ParsedJsonJws }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(reason: string, category: ErrorCategory = 'malformed_input'): JsonParseResult {
  return { ok: false, category, reason };
}

/** Members that belong to a signature entry rather than the enclosing object. */
const ENTRY_MEMBERS = ['protected', 'header', 'signature'] as const;

function readString(object: JsonObject, name: string): JsonValue | undefined {
  return object.members.get(name);
}

/**
 * Parses a decoded JSON JWS into its entries without interpreting any header.
 *
 * Structure, types, and counts are settled here so that later stages never have
 * to re-derive them from a value that could be a different shape than assumed.
 */
export function parseJsonJws(value: JsonValue, limits: Limits): JsonParseResult {
  if (!isJsonObject(value)) {
    return reject('jws_not_an_object');
  }

  const signaturesMember = value.members.get('signatures');
  const hasEntryMember = ENTRY_MEMBERS.some((name) => value.members.has(name));

  // A hybrid names one signature twice with no rule for which wins.
  if (signaturesMember !== undefined && hasEntryMember) {
    return reject('hybrid_serialization', 'invalid_header');
  }

  const payloadMember = value.members.get('payload');
  if (payloadMember !== undefined && payloadMember.kind !== 'string') {
    return reject('payload_not_a_string');
  }
  const payloadComponent = payloadMember?.kind === 'string' ? payloadMember.value : undefined;

  if (payloadComponent !== undefined && payloadComponent.length > limits.joseInput) {
    return reject('payload_too_large', 'resource_limit');
  }

  if (signaturesMember !== undefined) {
    if (signaturesMember.kind !== 'array') {
      return reject('signatures_not_an_array');
    }

    // An empty array can never satisfy the requirement that at least one
    // signature validate. Rejecting it structurally keeps the failure category
    // deterministic and stops an aggregate policy from being vacuously
    // satisfied over zero entries.
    if (signaturesMember.elements.length === 0) {
      return reject('signatures_empty');
    }
    if (signaturesMember.elements.length > limits.signatures) {
      return reject('too_many_signature_entries', 'resource_limit');
    }

    const signatures: JsonSignatureEntry[] = [];
    for (const element of signaturesMember.elements) {
      const entry = parseEntry(element);
      if (!entry.ok) {
        return entry;
      }
      signatures.push(entry.entry);
    }

    return { ok: true, value: { payloadComponent, signatures, form: 'general' } };
  }

  const entry = parseEntry(value);
  if (!entry.ok) {
    return entry;
  }

  return { ok: true, value: { payloadComponent, signatures: [entry.entry], form: 'flattened' } };
}

type EntryResult = { readonly ok: true; readonly entry: JsonSignatureEntry } | Extract<JsonParseResult, { ok: false }>;

/**
 * Validates one signature object.
 *
 * In the Flattened form this is the enclosing object itself, which is why
 * unrelated members such as `payload` are ignored here rather than rejected:
 * unknown noncritical members stay ignorable and must not acquire meaning.
 */
function parseEntry(value: JsonValue): EntryResult {
  if (!isJsonObject(value)) {
    return reject('signature_entry_not_an_object') as EntryResult;
  }

  const protectedMember = readString(value, 'protected');
  if (protectedMember === undefined) {
    // The algorithm must be protected, so an entry without a protected header
    // cannot describe an acceptable signature.
    return reject('protected_missing', 'invalid_header') as EntryResult;
  }
  if (protectedMember.kind !== 'string') {
    return reject('protected_not_a_string') as EntryResult;
  }
  if (protectedMember.value.length === 0) {
    return reject('protected_empty', 'invalid_header') as EntryResult;
  }

  const signatureMember = readString(value, 'signature');
  if (signatureMember === undefined) {
    return reject('signature_missing') as EntryResult;
  }
  if (signatureMember.kind !== 'string') {
    return reject('signature_not_a_string') as EntryResult;
  }
  // Supported algorithms produce nonempty signatures. An empty one is the shape
  // of an unsecured object.
  if (signatureMember.value.length === 0) {
    return reject('empty_signature') as EntryResult;
  }

  const headerMember = value.members.get('header');
  let unprotectedHeader: JsonObject | undefined;

  if (headerMember !== undefined) {
    if (!isJsonObject(headerMember)) {
      return reject('header_not_an_object', 'invalid_header') as EntryResult;
    }
    // An empty optional value is required to be omitted, so an explicit empty
    // object is a malformed encoding rather than a header carrying nothing.
    if (headerMember.members.size === 0) {
      return reject('header_empty', 'invalid_header') as EntryResult;
    }
    unprotectedHeader = headerMember;
  }

  return {
    ok: true,
    entry: {
      protectedComponent: protectedMember.value,
      unprotectedHeader,
      signatureComponent: signatureMember.value,
    },
  };
}
