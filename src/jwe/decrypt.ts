/**
 * JWE decryption.
 *
 * Stages run in a fixed order: structure, then whole-object header checks, then
 * algorithm policy, then recipient selection, and only then cryptography. The
 * whole-object checks run before any recipient is considered, because a
 * prohibited algorithm anywhere rejects the entire object even if that
 * recipient would never have been selected.
 *
 * Exactly one recipient is selected and exactly one key is tried. Trying each
 * key in turn would let the object's author decide which identity a successful
 * decryption is attributed to, so zero eligible recipients and several eligible
 * recipients are both refused rather than resolved by attempting them.
 *
 * Plaintext is released only after the content tag verifies. Nothing
 * provisional reaches the caller: no parser, callback, or nested operation sees
 * bytes that have not been authenticated.
 */

import { contentEncryptionShape, openContent } from '../algorithms/content-encryption/index.ts';
import { GCMKW_IV_BYTES, GCMKW_TAG_BYTES } from '../algorithms/jwe/aes-gcm-kw.ts';
import { keyManagementShape } from '../algorithms/jwe/index.ts';
import { checkWorkFactor } from '../algorithms/jwe/pbes2.ts';
import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { decodeBase64url } from '../internal/encoding/base64url.ts';
import { validateCritical, validateParameterTypes } from '../internal/headers/critical.ts';
import { mergeHeaders, requireHeaderObject } from '../internal/headers/merge.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import { parseJson } from '../internal/json/parse.ts';
import { OperationBudget } from '../internal/validation/limits.ts';
import type { UsableKey } from '../key/import.ts';
import type { EcCurve } from '../key/types.ts';
import { EC_COORDINATE_BYTES, OKP_KEY_BYTES } from '../key/validation.ts';
import { type AlgorithmPolicy, decideAlgorithm } from '../policy/algorithms.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import type { JsonObject, JsonValue } from '../internal/json/types.ts';
import { type JweRecipient, type ParsedJwe, parseJsonJwe } from './parse.ts';
import { type AgreementHeaders, type GcmKwHeaders, type Pbes2Headers, recoverCek } from './recover-cek.ts';
import { buildAdditionalData } from './types.ts';

/** A decryption key the caller already trusts, with the principal it belongs to. */
export interface TrustedRecipient {
  readonly principalId: string;
  readonly key: UsableKey;
  /**
   * Password octets for the password-based modes, supplied by trusted
   * configuration. It is bound to this key rather than to the operation, so an
   * object cannot select which password applies.
   */
  readonly password?: Uint8Array | undefined;
}

export interface DecryptOptions {
  /** Permitted key-management algorithms. */
  readonly keyPolicy: AlgorithmPolicy;
  /** Permitted content-encryption algorithms. */
  readonly contentPolicy: AlgorithmPolicy;
  readonly recipients: readonly TrustedRecipient[];
  /**
   * The one principal this operation decrypts as, chosen by the caller from
   * trusted context. Nothing in the object may change it.
   */
  readonly principalId: string;
  readonly limits: Limits;
  readonly operationBudget?: OperationBudget | undefined;
  /**
   * Enables the multi-recipient profile in which recipients may name differing
   * `alg` values in their own unprotected headers. Off by default: with one
   * algorithm the protected header is the only placement that binds it to the
   * authenticated data, and this profile is sound only because trusted
   * configuration independently constrains each recipient's algorithm and key.
   */
  readonly differingRecipientAlgorithms?: boolean | undefined;
}

/**
 * `not_selected` is neither a success nor an error category: those entries pass
 * structural and resource validation and are never cryptographically tried.
 */
export type RecipientOutcome =
  | { readonly index: number; readonly status: 'success' }
  | { readonly index: number; readonly status: 'not_selected' }
  | { readonly index: number; readonly status: 'failed'; readonly category: ErrorCategory };

export interface DecryptSuccess {
  readonly ok: true;
  /** Authenticated plaintext. Never populated unless the tag verified. */
  readonly plaintext: Uint8Array;
  readonly header: MergedHeader;
  /**
   * The principal whose key opened the object.
   *
   * This names the recipient that decrypted, not the sender: content
   * authentication proves the holder of the CEK produced the ciphertext, and
   * every recipient able to recover the CEK could have done so.
   */
  readonly principalId: string;
  readonly recipients: readonly RecipientOutcome[];
}

export interface DecryptFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
  /**
   * Per-entry statuses, present only when selection completed and the failure
   * came from the selected entry. A whole-object rejection evaluates no entry
   * and fabricates no status for one.
   */
  readonly recipients?: readonly RecipientOutcome[] | undefined;
}

export type DecryptResult = DecryptSuccess | DecryptFailure;

function fail(stage: TrustStage, category: ErrorCategory, reason: string): DecryptFailure {
  return { ok: false, category, stage, reason };
}

export async function decryptJson(source: Uint8Array, options: DecryptOptions): Promise<DecryptResult> {
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('configuration', 'policy_violation', limitDefect);
  }
  if (source.length > options.limits.joseInput) {
    return fail('syntax', 'resource_limit', 'jwe_too_large');
  }
  const json = parseJson(source, options.limits);
  if (!json.ok) {
    const category =
      json.failure === 'resource_limit'
        ? 'resource_limit'
        : json.failure === 'duplicate_member'
          ? 'malformed_input'
          : 'invalid_encoding';
    return fail('syntax', category, 'jwe_invalid_json');
  }
  const parsed = parseJsonJwe(json.value, options.limits);
  return parsed.ok ? decryptParsed(parsed.value, options) : fail('syntax', parsed.category, parsed.reason);
}

/**
 * Decrypts a parsed JWE.
 *
 * The parsed object holds the original component strings, which is what lets
 * the authenticated data be rebuilt from received bytes rather than from a
 * reserialization of the decoded header.
 */
export async function decryptParsed(object: ParsedJwe, options: DecryptOptions): Promise<DecryptResult> {
  // The selected principal is validated against trusted configuration before
  // the object is examined, so a configuration naming no usable key fails as
  // the configuration defect it is rather than as a key-resolution outcome
  // that reveals which recipients the object contains.
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('configuration', 'policy_violation', limitDefect);
  }
  if (options.principalId.length === 0) {
    return fail('configuration', 'policy_violation', 'principal_id_empty');
  }
  if (!options.recipients.some((trusted) => trusted.principalId === options.principalId)) {
    return fail('configuration', 'policy_violation', 'selected_principal_has_no_trusted_key');
  }

  // A standalone call owns its budget, so the accounting below and in the
  // per-recipient stage always applies. Enforcing it only when an enclosing
  // operation supplies one would leave every direct call unbounded.
  const budget = options.operationBudget ?? new OperationBudget(options.limits);
  const bounded: DecryptOptions = { ...options, operationBudget: budget };
  if (!budget.consumeLayer()) {
    return fail('syntax', 'resource_limit', 'too_many_cryptographic_layers');
  }
  const headerBytes = decodeBase64url(object.protectedComponent, options.limits.headerSource);
  if (!headerBytes.ok) {
    return headerBytes.failure === 'too_large'
      ? fail('syntax', 'resource_limit', 'protected_header_too_large')
      : fail('syntax', 'invalid_encoding', 'protected_header_invalid_base64url');
  }

  const headerJson = parseJson(headerBytes.bytes, options.limits);
  if (!headerJson.ok) {
    return fail(
      'syntax',
      headerJson.failure === 'resource_limit'
        ? 'resource_limit'
        : headerJson.failure === 'duplicate_member'
          ? 'malformed_input'
          : 'invalid_encoding',
      'protected_header_invalid_json',
    );
  }
  if (!budget.consumeJsonNodes(headerJson.nodes)) {
    return fail('syntax', 'resource_limit', 'json_node_budget_exceeded');
  }

  const protectedObject = requireHeaderObject(headerJson.value);
  if (!protectedObject.ok) {
    return fail('header', protectedObject.category, protectedObject.reason);
  }

  // The content algorithm is shared by every recipient and decides the sizes
  // each component must have, so it is settled before recipients are examined.
  const contentAlgorithm = readProtectedString(protectedObject.object, 'enc');
  if (contentAlgorithm === undefined) {
    return fail('header', 'invalid_header', 'enc_missing_or_not_a_string');
  }

  const contentDecision = decideAlgorithm(options.contentPolicy, contentAlgorithm);
  if (!contentDecision.ok) {
    return fail('header', contentDecision.category, contentDecision.reason);
  }

  const content = contentEncryptionShape(contentAlgorithm);
  if (content === undefined) {
    return fail('header', 'unsupported_algorithm', 'unsupported_content_algorithm');
  }

  // Every recipient's key-management algorithm is screened before any of them
  // is selected: a prohibited identifier anywhere rejects the whole object,
  // including in a recipient that would not have been chosen.
  const screened = screenRecipients(object, protectedObject.object, headerBytes.bytes.length, options);
  if (!screened.ok) {
    return screened.failure;
  }

  const selected = selectRecipient(screened.value, options, contentAlgorithm);
  if (!selected.ok) {
    return selected.failure;
  }

  const result = await decryptSelected(
    object,
    selected.value,
    contentAlgorithm,
    content.ivBytes,
    content.tagBytes,
    bounded,
  );

  // Unselected entries report `not_selected` rather than being omitted, so a
  // caller cannot read a missing status as a silent cryptographic failure.
  const outcomes = screened.value.map((entry): RecipientOutcome =>
    entry.index === selected.value.index
      ? result.ok
        ? { index: entry.index, status: 'success' }
        : { index: entry.index, status: 'failed', category: result.category }
      : { index: entry.index, status: 'not_selected' },
  );

  return { ...result, recipients: outcomes };
}

interface ScreenedRecipient {
  readonly index: number;
  readonly recipient: JweRecipient;
  readonly keyAlgorithm: string;
  readonly header: MergedHeader;
  readonly algProtected: boolean;
}

type Screened =
  | { readonly ok: true; readonly value: readonly ScreenedRecipient[] }
  | { readonly ok: false; readonly failure: DecryptFailure };

function screenRecipients(
  object: ParsedJwe,
  protectedHeader: JsonObject,
  protectedBytes: number,
  options: DecryptOptions,
): Screened {
  const screened: ScreenedRecipient[] = [];

  for (const [index, recipient] of object.recipients.entries()) {
    const merged = mergeHeaders(
      [
        { origin: 'protected' as const, object: protectedHeader, sourceBytes: protectedBytes },
        ...(object.sharedUnprotectedHeader === undefined
          ? []
          : [
              // Unprotected headers are already counted in the enclosing
              // document's byte budget, so they add nothing here.
              { origin: 'shared_unprotected' as const, object: object.sharedUnprotectedHeader, sourceBytes: 0 },
            ]),
        ...(recipient.unprotectedHeader === undefined
          ? []
          : [{ origin: 'per_entry_unprotected' as const, object: recipient.unprotectedHeader, sourceBytes: 0 }]),
      ],
      options.limits,
    );
    if (!merged.ok) {
      return { ok: false, failure: fail('header', merged.category, merged.reason) };
    }

    const types = validateParameterTypes(merged.header, options.limits);
    if (!types.ok) {
      return { ok: false, failure: fail('header', 'invalid_header', types.reason) };
    }

    const critical = validateCritical(merged.header, 'jwe');
    if (!critical.ok) {
      return { ok: false, failure: fail('header', critical.category, critical.reason) };
    }

    // Compression is disabled for acceptance. Without this the object would
    // decrypt and hand back compressed octets as if they were the plaintext,
    // which a caller has no way to distinguish from a genuine payload.
    const zip = merged.header.parameters.get('zip');
    if (zip !== undefined) {
      return { ok: false, failure: fail('header', 'policy_violation', 'compression_not_enabled') };
    }

    const algMember = merged.header.parameters.get('alg');
    if (algMember === undefined || algMember.value.kind !== 'string') {
      return { ok: false, failure: fail('header', 'invalid_header', 'alg_missing_or_not_a_string') };
    }
    const keyAlgorithm = algMember.value.value;

    const decision = decideAlgorithm(options.keyPolicy, keyAlgorithm);
    // A prohibited identifier rejects the whole object here and now. Anything
    // else is deferred: an algorithm this caller did not permit only disallows
    // this recipient, and reporting it before selection would say which
    // recipients exist.
    if (!decision.ok && decision.category === 'prohibited_algorithm') {
      return { ok: false, failure: fail('header', 'prohibited_algorithm', decision.reason) };
    }

    // A direct mode derives the CEK from one recipient's own key, so it cannot
    // describe a multi-recipient object. Checked for every entry rather than
    // only the selected one, since an unselected direct entry makes the object
    // malformed regardless of which recipient this caller opens.
    if (object.recipients.length > 1 && keyManagementShape(keyAlgorithm)?.singleRecipientOnly === true) {
      return { ok: false, failure: fail('header', 'policy_violation', 'algorithm_requires_single_recipient') };
    }

    screened.push({
      index,
      recipient,
      keyAlgorithm,
      header: merged.header,
      algProtected: algMember.origin === 'protected',
    });
  }

  const placement = checkAlgorithmPlacement(screened, options);
  if (placement !== undefined) {
    return { ok: false, failure: placement };
  }

  return { ok: true, value: screened };
}

/**
 * A single algorithm across the object has no reason to sit outside the
 * protected header, where the additional authenticated data covers it. Only the
 * separately enabled differing-algorithm profile permits per-recipient
 * placement, and even there the value grants no policy: trusted configuration
 * still decides each recipient's permitted algorithm and key.
 */
function checkAlgorithmPlacement(
  screened: readonly ScreenedRecipient[],
  options: DecryptOptions,
): DecryptFailure | undefined {
  if (screened.every((entry) => entry.algProtected)) {
    return undefined;
  }

  const distinct = new Set(screened.map((entry) => entry.keyAlgorithm));
  if (distinct.size === 1) {
    return fail('header', 'policy_violation', 'alg_must_be_protected');
  }
  if (options.differingRecipientAlgorithms !== true) {
    return fail('header', 'policy_violation', 'differing_recipient_algorithms_not_enabled');
  }

  return undefined;
}

interface SelectedRecipient extends ScreenedRecipient {
  readonly trusted: TrustedRecipient;
}

type Selection =
  | { readonly ok: true; readonly value: SelectedRecipient }
  | { readonly ok: false; readonly failure: DecryptFailure };

/**
 * Chooses the one recipient this caller can open.
 *
 * Eligibility is decided entirely by trusted configuration: a key must be bound
 * to the recipient's algorithm and usable for decryption. Nothing in the object
 * introduces a key. Zero and several eligible pairings are both refused,
 * because attempting them in turn would let the object decide which key gets
 * used and which principal a success is attributed to.
 */
function selectRecipient(
  screened: readonly ScreenedRecipient[],
  options: DecryptOptions,
  contentAlgorithm: string,
): Selection {
  // The principal comes from trusted application context. Searching every
  // configured principal instead would let the object decide which identity a
  // successful decryption is attributed to, simply by naming another
  // recipient's key.
  const forPrincipal = options.recipients.filter((trusted) => trusted.principalId === options.principalId);

  const eligible: SelectedRecipient[] = [];

  for (const entry of screened) {
    if (!options.keyPolicy.has(entry.keyAlgorithm)) {
      continue;
    }

    // A present `kid` is an exact filter on the entry, applied whatever the
    // candidate count. Ignoring an unmatched hint would open an entry naming a
    // key absent from the trusted configuration using a different key.
    const kid = entry.header.parameters.get('kid');
    const hint = kid?.value.kind === 'string' ? kid.value.value : undefined;

    for (const trusted of forPrincipal) {
      const shape = keyManagementShape(entry.keyAlgorithm);
      const requiredOperation =
        shape?.mode === 'direct'
          ? 'decrypt'
          : shape?.mode === 'direct_agreement' || shape?.mode === 'agreement_with_wrapping'
            ? 'deriveKey'
            : 'unwrapKey';
      if (
        trusted.key.algorithm !== entry.keyAlgorithm ||
        trusted.key.operation !== requiredOperation ||
        !trusted.key.contentAlgorithms.includes(contentAlgorithm)
      ) {
        continue;
      }
      if (hint !== undefined && trusted.key.metadata.kid !== hint) {
        continue;
      }
      eligible.push({ ...entry, trusted });
    }
  }

  if (eligible.length === 0) {
    return { ok: false, failure: fail('key_resolution', 'key_resolution_failure', 'no_eligible_recipient') };
  }
  if (eligible.length > 1) {
    return { ok: false, failure: fail('key_resolution', 'key_resolution_failure', 'ambiguous_recipient') };
  }

  return { ok: true, value: eligible[0]! };
}

async function decryptSelected(
  object: ParsedJwe,
  selected: SelectedRecipient,
  contentAlgorithm: string,
  ivBytes: number,
  tagBytes: number,
  options: DecryptOptions,
): Promise<DecryptResult> {
  const shape = keyManagementShape(selected.keyAlgorithm);
  if (shape === undefined) {
    return fail('header', 'unsupported_algorithm', 'unsupported_key_algorithm');
  }

  // Presence of the encrypted key is structural: the direct modes carry none,
  // and every wrapping mode requires bytes. A mismatch means the object does
  // not describe the algorithm it names.
  if (shape.carriesEncryptedKey === (selected.recipient.encryptedKeyComponent === undefined)) {
    return fail('header', 'invalid_header', 'encrypted_key_presence_mismatch');
  }

  const iv = decodeExact(object.ivComponent, ivBytes);
  if (iv === undefined) {
    return fail('syntax', 'malformed_input', 'iv_wrong_length');
  }

  const tag = decodeExact(object.tagComponent, tagBytes);
  if (tag === undefined) {
    return fail('syntax', 'malformed_input', 'tag_wrong_length');
  }

  const ciphertext = decodeBase64url(object.ciphertextComponent, options.limits.ciphertext);
  if (!ciphertext.ok) {
    return ciphertext.failure === 'too_large'
      ? fail('syntax', 'resource_limit', 'ciphertext_too_large')
      : fail('syntax', 'invalid_encoding', 'ciphertext_invalid_base64url');
  }

  let encryptedKey: Uint8Array | undefined;
  if (selected.recipient.encryptedKeyComponent !== undefined) {
    const decoded = decodeBase64url(selected.recipient.encryptedKeyComponent, options.limits.serializedJwk);
    if (!decoded.ok) {
      return fail('syntax', 'invalid_encoding', 'encrypted_key_invalid_base64url');
    }
    encryptedKey = decoded.bytes;
  }

  // The agreement parameters are only meaningful for a mode that agrees. Under
  // any other algorithm an `epk` selects nothing, so it stays an ignorable
  // noncritical member rather than being interpreted out of context.
  const agrees = shape.mode === 'direct_agreement' || shape.mode === 'agreement_with_wrapping';
  const agreement = agrees ? readAgreementHeaders(selected.header, options.limits) : undefined;
  if (agreement !== undefined && !agreement.ok) {
    return fail('header', 'invalid_header', agreement.reason);
  }

  const gcmKw = shape.mode === 'gcm_wrapping' ? readGcmKwHeaders(selected.header) : undefined;
  if (gcmKw !== undefined && !gcmKw.ok) {
    return fail('header', 'invalid_header', gcmKw.reason);
  }

  // The work factor is public and attacker-supplied, so it is validated at the
  // header stage rather than deferred into the derivation.
  const pbes2 = shape.mode === 'password_wrapping' ? readPbes2Headers(selected.header, options.limits) : undefined;
  if (pbes2 !== undefined && !pbes2.ok) {
    return fail('header', pbes2.category, pbes2.reason);
  }

  const additionalData = buildAdditionalData(object.protectedComponent, object.aadComponent);
  if (!additionalData.ok) {
    return fail('syntax', 'malformed_input', additionalData.failure);
  }

  if (options.operationBudget !== undefined && !options.operationBudget.consumeAttempt()) {
    return fail('cryptographic', 'resource_limit', 'cryptographic_attempt_budget_exceeded');
  }
  const recovered = await recoverCek({
    keyAlgorithm: selected.keyAlgorithm,
    contentAlgorithm,
    shape,
    key: selected.trusted.key,
    encryptedKey,
    agreement: agreement?.value,
    gcmKw: gcmKw?.value,
    pbes2: pbes2?.value,
    password: selected.trusted.password,
  });

  if (!recovered.ok) {
    // A failed recovery is reported as an authentication failure, identical to
    // a failed content tag. Reporting the key step separately would tell an
    // attacker whether their guess reached the content stage.
    return recovered.failure === 'backend_failure'
      ? fail('cryptographic', 'backend_failure', 'provider_failure')
      : fail('cryptographic', 'authentication_failure', 'decryption_failed');
  }

  if (options.operationBudget !== undefined && !options.operationBudget.consumeAttempt()) {
    if (recovered.owned) {
      recovered.cek.fill(0);
    }
    return fail('cryptographic', 'resource_limit', 'cryptographic_attempt_budget_exceeded');
  }
  const opened = await openContent(contentAlgorithm, recovered.cek, iv, ciphertext.bytes, tag, additionalData.bytes);
  if (recovered.owned) {
    recovered.cek.fill(0);
  }
  if (!opened.ok) {
    return fail('cryptographic', 'backend_failure', 'provider_failure');
  }
  // A failed tag yields no plaintext at all, so there is nothing provisional to
  // leak here even by accident.
  if (opened.value === undefined) {
    return fail('cryptographic', 'authentication_failure', 'decryption_failed');
  }

  // The plaintext length is only known once the tag verifies, so the bound is
  // applied here rather than to the ciphertext, whose length depends on the
  // construction. An over-limit plaintext is discarded rather than returned.
  if (opened.value.length > options.limits.payload) {
    opened.value.fill(0);
    return fail('cryptographic', 'resource_limit', 'plaintext_too_large');
  }

  return {
    ok: true,
    plaintext: opened.value,
    header: selected.header,
    principalId: selected.trusted.principalId,
    recipients: [],
  };
}

/**
 * Decodes a component that must have one exact length.
 *
 * The length comes from the content algorithm, so a component of another size
 * is rejected before it reaches the provider rather than being padded or
 * truncated to fit.
 */
function decodeExact(component: string, expectedBytes: number): Uint8Array | undefined {
  const decoded = decodeBase64url(component, expectedBytes);
  return decoded.ok && decoded.bytes.length === expectedBytes ? decoded.bytes : undefined;
}

function readProtectedString(header: JsonObject, name: string): string | undefined {
  return stringMember(header.members, name);
}

type AgreementRead =
  | { readonly ok: true; readonly value: AgreementHeaders }
  | { readonly ok: false; readonly reason: string };

/**
 * Members that make a JWK private for any of the agreement key types. `epk` is
 * public-only, so any of them present means the object is not an `epk`.
 */
const EPK_PRIVATE_MEMBERS: readonly string[] = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/** The key type a curve belongs to; absent when it is not an agreement curve. */
function expectedEpkKeyType(curve: string): 'EC' | 'OKP' | undefined {
  if (curve in EC_COORDINATE_BYTES) {
    return 'EC';
  }
  return curve === 'X25519' || curve === 'X448' ? 'OKP' : undefined;
}

/** Exact published width for one coordinate of an agreement curve. */
function coordinateBytes(curve: string): number | undefined {
  if (curve in EC_COORDINATE_BYTES) {
    return EC_COORDINATE_BYTES[curve as EcCurve];
  }
  return curve === 'X25519' || curve === 'X448' ? OKP_KEY_BYTES[curve].public : undefined;
}

/**
 * Reads the agreement parameters for a key-agreement algorithm.
 *
 * `epk` is required by the mode rather than optional within it, so its absence
 * is a header defect here instead of a failure discovered later during CEK
 * recovery. It is attacker-supplied and validated as a complete public-only
 * JWK: a private member would mean the sender leaked their own key or is
 * substituting one, and a coordinate of the wrong width is not a point on the
 * curve it claims.
 */
function readAgreementHeaders(header: MergedHeader, limits: Limits): AgreementRead {
  const epk = header.parameters.get('epk');
  if (epk === undefined) {
    return { ok: false, reason: 'epk_missing' };
  }
  if (epk.value.kind !== 'object') {
    return { ok: false, reason: 'epk_not_an_object' };
  }

  const members = epk.value.members;
  for (const name of EPK_PRIVATE_MEMBERS) {
    if (members.has(name)) {
      return { ok: false, reason: 'epk_carries_private_key' };
    }
  }

  const keyType = stringMember(members, 'kty');
  const curve = stringMember(members, 'crv');
  const x = stringMember(members, 'x');
  if (keyType === undefined || curve === undefined || x === undefined) {
    return { ok: false, reason: 'epk_incomplete' };
  }

  // The key type is decided by the curve, so a header naming one that
  // disagrees does not describe the key it carries.
  const expected = expectedEpkKeyType(curve);
  if (expected === undefined) {
    return { ok: false, reason: 'epk_curve_not_usable_for_agreement' };
  }
  if (keyType !== expected) {
    return { ok: false, reason: 'epk_kty_does_not_match_curve' };
  }

  const xBytes = decodeBase64url(x, limits.serializedJwk);
  if (!xBytes.ok) {
    return { ok: false, reason: 'epk_x_invalid_base64url' };
  }
  if (xBytes.bytes.length !== coordinateBytes(curve)) {
    return { ok: false, reason: 'epk_x_wrong_length' };
  }

  // `y` is required for the NIST curves and prohibited for the Montgomery
  // ones, which is decided by the curve rather than by what the header supplies.
  const y = stringMember(members, 'y');
  let yBytes: Uint8Array | undefined;
  if (expected === 'EC') {
    if (y === undefined) {
      return { ok: false, reason: 'epk_incomplete' };
    }
    const decoded = decodeBase64url(y, limits.serializedJwk);
    if (!decoded.ok) {
      return { ok: false, reason: 'epk_y_invalid_base64url' };
    }
    if (decoded.bytes.length !== coordinateBytes(curve)) {
      return { ok: false, reason: 'epk_y_wrong_length' };
    }
    yBytes = decoded.bytes;
  } else if (y !== undefined) {
    return { ok: false, reason: 'epk_y_not_valid_for_curve' };
  }

  const partyU = decodeParty(header, 'apu', limits);
  if (partyU !== undefined && !partyU.ok) {
    return { ok: false, reason: 'apu_invalid_base64url' };
  }
  const partyV = decodeParty(header, 'apv', limits);
  if (partyV !== undefined && !partyV.ok) {
    return { ok: false, reason: 'apv_invalid_base64url' };
  }

  return {
    ok: true,
    value: {
      ephemeral: { curve, x: xBytes.bytes, y: yBytes },
      partyU: partyU?.value,
      partyV: partyV?.value,
    },
  };
}

function decodeParty(
  header: MergedHeader,
  name: string,
  limits: Limits,
): { ok: true; value: Uint8Array } | { ok: false } | undefined {
  const member = header.parameters.get(name);
  if (member === undefined) {
    return undefined;
  }
  if (member.value.kind !== 'string') {
    return { ok: false };
  }
  const decoded = decodeBase64url(member.value.value, limits.headerSource);
  return decoded.ok ? { ok: true, value: decoded.bytes } : { ok: false };
}

function stringMember(members: ReadonlyMap<string, JsonValue>, name: string): string | undefined {
  const member = members.get(name);
  return member?.kind === 'string' ? member.value : undefined;
}

type GcmKwRead = { readonly ok: true; readonly value: GcmKwHeaders } | { readonly ok: false; readonly reason: string };

/**
 * Reads the wrapping IV and tag the GCM key-wrap mode carries.
 *
 * These are header parameters of the same names as the content components but
 * are entirely separate values; reading the content ones here would attempt to
 * unwrap with the wrong nonce.
 */
function readGcmKwHeaders(header: MergedHeader): GcmKwRead {
  const iv = header.parameters.get('iv');
  const tag = header.parameters.get('tag');
  if (iv?.value.kind !== 'string' || tag?.value.kind !== 'string') {
    return { ok: false, reason: 'gcmkw_parameters_missing' };
  }

  const ivBytes = decodeBase64url(iv.value.value, GCMKW_IV_BYTES);
  const tagBytes = decodeBase64url(tag.value.value, GCMKW_TAG_BYTES);
  if (!ivBytes.ok || !tagBytes.ok) {
    return { ok: false, reason: 'gcmkw_parameters_invalid_base64url' };
  }
  // Both widths are fixed by the construction, so a different width means the
  // object does not describe the algorithm it names.
  if (ivBytes.bytes.length !== GCMKW_IV_BYTES || tagBytes.bytes.length !== GCMKW_TAG_BYTES) {
    return { ok: false, reason: 'gcmkw_parameters_wrong_length' };
  }

  return { ok: true, value: { iv: ivBytes.bytes, tag: tagBytes.bytes } };
}

type Pbes2Read =
  | { readonly ok: true; readonly value: Pbes2Headers }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

/**
 * Reads and bounds the password-derivation parameters.
 *
 * `p2c` must be an integer lexeme with no fraction or exponent: a value written
 * as `1e9` names an iteration count far outside policy while looking small, and
 * a fractional count has no meaning for the derivation.
 */
function readPbes2Headers(header: MergedHeader, limits: Limits): Pbes2Read {
  const algorithm = header.parameters.get('alg');
  const salt = header.parameters.get('p2s');
  const count = header.parameters.get('p2c');

  if (algorithm?.value.kind !== 'string') {
    return { ok: false, category: 'invalid_header', reason: 'alg_missing_or_not_a_string' };
  }
  if (salt?.value.kind !== 'string') {
    return { ok: false, category: 'invalid_header', reason: 'p2s_missing_or_not_a_string' };
  }
  if (count?.value.kind !== 'number') {
    return { ok: false, category: 'invalid_header', reason: 'p2c_missing_or_not_a_number' };
  }
  if (!/^\d+$/.test(count.value.lexeme)) {
    return { ok: false, category: 'invalid_header', reason: 'p2c_not_a_positive_integer' };
  }

  const iterations = Number(count.value.lexeme);
  if (!Number.isSafeInteger(iterations)) {
    return { ok: false, category: 'invalid_header', reason: 'p2c_not_a_positive_integer' };
  }

  const saltBytes = decodeBase64url(salt.value.value, limits.headerSource);
  if (!saltBytes.ok) {
    return { ok: false, category: 'invalid_encoding', reason: 'p2s_invalid_base64url' };
  }

  const bounded = checkWorkFactor(algorithm.value.value, saltBytes.bytes, iterations);
  if (!bounded.ok) {
    // Out-of-policy work factors are refused before any derivation runs, so a
    // hostile count never costs this side the work it names.
    return { ok: false, category: 'policy_violation', reason: bounded.reason };
  }

  return { ok: true, value: { saltInput: saltBytes.bytes, iterations } };
}
