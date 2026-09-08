/**
 * JWE structural parsing.
 *
 * Compact and JSON forms produce the same parsed shape so that later stages
 * never branch on serialization to decide what a component means. Every
 * component is kept as its original string: the authenticated data is built
 * from the received protected-header bytes, so reserializing a decoded header
 * would authenticate different octets whenever whitespace or member order
 * differ.
 *
 * A missing member and a present-but-empty one are different states throughout.
 * The format requires empty optional values to be omitted, so an explicit empty
 * string is a malformed encoding rather than an alias for absence. Treating
 * the two alike would let an attacker choose which reading applies.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import { decodeBase64url, encodedLengthFor } from '../internal/encoding/base64url.ts';
import { isJsonObject, type JsonObject, type JsonValue } from '../internal/json/types.ts';
import type { Limits } from '../policy/limits.ts';

/** One recipient's key-management contribution. */
export interface JweRecipient {
  /** Per-recipient unprotected header, absent when the member is omitted. */
  readonly unprotectedHeader: JsonObject | undefined;
  /**
   * Original Base64url encrypted key, absent for direct modes.
   *
   * Absence is meaningful: direct key use and direct agreement carry no
   * encrypted key at all, while every wrapping algorithm requires bytes here.
   */
  readonly encryptedKeyComponent: string | undefined;
}

export interface ParsedJwe {
  /** Original Base64url protected header string. */
  readonly protectedComponent: string;
  /** Shared unprotected header, absent when the member is omitted. */
  readonly sharedUnprotectedHeader: JsonObject | undefined;
  readonly recipients: readonly JweRecipient[];
  readonly ivComponent: string;
  readonly ciphertextComponent: string;
  readonly tagComponent: string;
  /**
   * Original Base64url external AAD string, absent when the member is omitted.
   *
   * The original string is retained because the authenticated data is built by
   * concatenating encoded components, never decoded octets.
   */
  readonly aadComponent: string | undefined;
  readonly form: 'compact' | 'flattened' | 'general';
}

export type JweParseResult =
  | { readonly ok: true; readonly value: ParsedJwe }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(reason: string, category: ErrorCategory = 'malformed_input'): JweParseResult {
  return { ok: false, category, reason };
}

/**
 * Parses the Compact form.
 *
 * Exactly five components separated by four periods. The count is checked
 * before anything is decoded, so a token with a missing or extra separator is
 * refused as malformed rather than being read with components shifted by one.
 */
export function parseCompactJwe(token: string, limits: Limits): JweParseResult {
  if (token.length > limits.joseInput) {
    return reject('jwe_too_large', 'resource_limit');
  }

  const parts = token.split('.');
  if (parts.length !== 5) {
    return reject('compact_component_count');
  }

  const [protectedComponent, encryptedKeyComponent, ivComponent, ciphertextComponent, tagComponent] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];

  if (protectedComponent.length === 0) {
    return reject('protected_empty', 'invalid_header');
  }
  // The IV and tag are fixed-width for every supported content algorithm, so an
  // empty component cannot describe one. Exact widths are checked once the
  // algorithm is known.
  if (ivComponent.length === 0) {
    return reject('iv_empty');
  }
  if (tagComponent.length === 0) {
    return reject('tag_empty');
  }

  return {
    ok: true,
    value: {
      protectedComponent,
      sharedUnprotectedHeader: undefined,
      recipients: [
        {
          unprotectedHeader: undefined,
          // Compact carries an empty component for direct modes, which is the
          // same state the JSON forms express by omitting the member.
          encryptedKeyComponent: encryptedKeyComponent.length === 0 ? undefined : encryptedKeyComponent,
        },
      ],
      ivComponent,
      ciphertextComponent,
      tagComponent,
      aadComponent: undefined,
      form: 'compact',
    },
  };
}

type Optional<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: JweParseResult };

const RECIPIENT_MEMBERS = ['header', 'encrypted_key'] as const;

function readMember(object: JsonObject, name: string): JsonValue | undefined {
  return object.members.get(name);
}

/**
 * Reads a required Base64url string member.
 *
 * Emptiness is rejected here because every one of these components has content
 * for the supported algorithms; `ciphertext` is handled separately
 * since an empty plaintext legitimately produces zero ciphertext octets.
 */
function requireComponent(object: JsonObject, name: string): Optional<string> {
  const member = readMember(object, name);
  if (member === undefined) {
    return { ok: false, failure: reject(`${name}_missing`) };
  }
  if (member.kind !== 'string') {
    return { ok: false, failure: reject(`${name}_not_a_string`) };
  }
  if (member.value.length === 0) {
    return { ok: false, failure: reject(`${name}_empty`) };
  }
  return { ok: true, value: member.value };
}

/**
 * Parses either JSON form.
 *
 * Absence of `recipients` selects the Flattened form. The two are parsed
 * together because separating them would require deciding the form before
 * validating it, and the rule that distinguishes them is a rejection: an object
 * carrying both a `recipients` array and top-level recipient members is a
 * hybrid with no rule for which half wins.
 */
export function parseJsonJwe(value: JsonValue, limits: Limits): JweParseResult {
  if (!isJsonObject(value)) {
    return reject('jwe_not_an_object');
  }

  const recipientsMember = value.members.get('recipients');
  const hasRecipientMember = RECIPIENT_MEMBERS.some((name) => value.members.has(name));

  if (recipientsMember !== undefined && hasRecipientMember) {
    return reject('hybrid_serialization', 'invalid_header');
  }

  const protectedComponent = requireComponent(value, 'protected');
  if (!protectedComponent.ok) {
    return protectedComponent.failure;
  }
  // `headerSource` bounds the decoded header, and Base64url expands its input,
  // so comparing the encoded string against it directly would admit roughly a
  // third more than the limit names. The decoded bound itself is applied where
  // the component is decoded.
  if (protectedComponent.value.length > encodedLengthFor(limits.headerSource)) {
    return reject('protected_too_large', 'resource_limit');
  }

  const ivComponent = requireComponent(value, 'iv');
  if (!ivComponent.ok) {
    return ivComponent.failure;
  }

  const tagComponent = requireComponent(value, 'tag');
  if (!tagComponent.ok) {
    return tagComponent.failure;
  }

  // `ciphertext` must be present but may be the empty string: an empty
  // plaintext under GCM produces no ciphertext octets, and that is a different
  // state from the member being absent.
  const ciphertextMember = readMember(value, 'ciphertext');
  if (ciphertextMember === undefined) {
    return reject('ciphertext_missing');
  }
  if (ciphertextMember.kind !== 'string') {
    return reject('ciphertext_not_a_string');
  }
  if (ciphertextMember.value.length > limits.joseInput) {
    return reject('ciphertext_too_large', 'resource_limit');
  }

  const aad = readOptionalString(value, 'aad');
  if (aad !== undefined && !aad.ok) {
    return aad.failure;
  }
  if (aad?.ok === true) {
    // The component enters the authenticated data verbatim, so its bytes are
    // never replaced by the decoded value. It is still validated as canonical
    // Base64url and bounded: a member that decodes to nothing meaningful is a
    // syntax defect, not authenticated context.
    const decoded = decodeBase64url(aad.value, limits.joseInput);
    if (!decoded.ok) {
      return decoded.failure === 'too_large'
        ? reject('aad_too_large', 'resource_limit')
        : reject('aad_invalid_base64url', 'invalid_encoding');
    }
  }

  const sharedUnprotected = readOptionalObject(value, 'unprotected');
  if (sharedUnprotected !== undefined && !sharedUnprotected.ok) {
    return sharedUnprotected.failure;
  }

  const recipients = parseRecipients(value, recipientsMember, limits);
  if (!recipients.ok) {
    return recipients.failure;
  }

  return {
    ok: true,
    value: {
      protectedComponent: protectedComponent.value,
      sharedUnprotectedHeader: sharedUnprotected?.value,
      recipients: recipients.value,
      ivComponent: ivComponent.value,
      ciphertextComponent: ciphertextMember.value,
      tagComponent: tagComponent.value,
      aadComponent: aad?.value,
      form: recipientsMember === undefined ? 'flattened' : 'general',
    },
  };
}

/**
 * Reads an optional string member, rejecting an explicit empty value.
 *
 * The format requires an empty optional value to be omitted, so `""` is
 * malformed rather than equivalent to absence. Accepting it would create two
 * encodings of one state, and for `aad` the two produce different authenticated
 * data.
 */
function readOptionalString(object: JsonObject, name: string): Optional<string> | undefined {
  const member = readMember(object, name);
  if (member === undefined) {
    return undefined;
  }
  if (member.kind !== 'string') {
    return { ok: false, failure: reject(`${name}_not_a_string`) };
  }
  if (member.value.length === 0) {
    return { ok: false, failure: reject(`${name}_empty`, 'invalid_header') };
  }
  return { ok: true, value: member.value };
}

function readOptionalObject(object: JsonObject, name: string): Optional<JsonObject> | undefined {
  const member = readMember(object, name);
  if (member === undefined) {
    return undefined;
  }
  if (!isJsonObject(member)) {
    return { ok: false, failure: reject(`${name}_not_an_object`, 'invalid_header') };
  }
  if (member.members.size === 0) {
    return { ok: false, failure: reject(`${name}_empty`, 'invalid_header') };
  }
  return { ok: true, value: member };
}

function parseRecipients(
  object: JsonObject,
  recipientsMember: JsonValue | undefined,
  limits: Limits,
): Optional<readonly JweRecipient[]> {
  if (recipientsMember === undefined) {
    // Flattened form: the enclosing object is itself the single recipient.
    const single = parseRecipient(object);
    return single.ok ? { ok: true, value: [single.value] } : single;
  }

  if (recipientsMember.kind !== 'array') {
    return { ok: false, failure: reject('recipients_not_an_array') };
  }
  // An empty array is a rejected General JWE, never an implicit Flattened one:
  // zero recipients can never yield a decryptable object.
  if (recipientsMember.elements.length === 0) {
    return { ok: false, failure: reject('recipients_empty') };
  }
  if (recipientsMember.elements.length > limits.recipients) {
    return { ok: false, failure: reject('too_many_recipients', 'resource_limit') };
  }

  const recipients: JweRecipient[] = [];
  for (const element of recipientsMember.elements) {
    if (!isJsonObject(element)) {
      return { ok: false, failure: reject('recipient_not_an_object') };
    }
    const parsed = parseRecipient(element);
    if (!parsed.ok) {
      return parsed;
    }
    recipients.push(parsed.value);
  }

  return { ok: true, value: recipients };
}

/**
 * Validates one recipient object.
 *
 * In the Flattened form this is the enclosing object, which is why unrelated
 * members such as `ciphertext` are ignored here rather than rejected: unknown
 * noncritical members stay ignorable and must not acquire meaning.
 */
function parseRecipient(value: JsonObject): Optional<JweRecipient> {
  const header = readOptionalObject(value, 'header');
  if (header !== undefined && !header.ok) {
    return header;
  }

  const encryptedKey = readOptionalString(value, 'encrypted_key');
  if (encryptedKey !== undefined && !encryptedKey.ok) {
    return encryptedKey;
  }

  return {
    ok: true,
    value: {
      unprotectedHeader: header?.value,
      encryptedKeyComponent: encryptedKey?.value,
    },
  };
}
