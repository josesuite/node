/**
 * JSON JWS verification with aggregate acceptance.
 *
 * Every supplied entry is evaluated. Evaluation deliberately does not stop at
 * the first success or the first failure: the aggregate predicate is defined
 * over the whole set of established principals, and per-entry results are
 * reported separately from the aggregate decision.
 *
 * A failed entry contributes no principal and never removes one established by
 * another entry, so a valid and an invalid signature from the same signer still
 * satisfy a policy naming that signer.
 */

import { verifyWithKey } from '../algorithms/index.ts';
import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { decodeBase64url } from '../internal/encoding/base64url.ts';
import { resolveB64, validateCritical, validateParameterTypes } from '../internal/headers/critical.ts';
import { type HeaderSource, mergeHeaders, requireHeaderObject } from '../internal/headers/merge.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import { parseJson } from '../internal/json/parse.ts';
import { OperationBudget } from '../internal/validation/limits.ts';
import type { JsonObject } from '../internal/json/types.ts';
import type { UsableKey } from '../key/import.ts';
import { isProhibitedAlgorithm } from '../algorithms/registry.ts';
import { type AlgorithmPolicy, decideAlgorithm } from '../policy/algorithms.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import { checkPrincipalInvariants } from '../jwk/jwks.ts';
import { type AggregatePolicy, isSatisfied, referencedPrincipals } from './aggregate.ts';
import { type JsonSignatureEntry, parseJsonJws } from './parse.ts';
import { buildSigningInput, validateInlineUnencodedPayload } from './types.ts';

/**
 * A key bound to the principal that trusted configuration says holds it.
 *
 * The principal comes from configuration, never from the token: a `kid` may
 * narrow which candidates are tried, but can never introduce a key or a signer
 * identity the caller did not already trust.
 */
export interface TrustedSigner {
  readonly principalId: string;
  readonly key: UsableKey;
}

export interface EntryOutcome {
  /** Index in the received `signatures` array, preserving input order. */
  readonly index: number;
  readonly ok: boolean;
  /** Principal established by this entry, present only on success. */
  readonly principalId: string | undefined;
  readonly header: MergedHeader | undefined;
  readonly category: ErrorCategory | undefined;
  readonly stage: TrustStage | undefined;
  readonly reason: string | undefined;
}

export interface JsonVerifyFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
  /** Per-entry results, retained even when the aggregate decision rejects. */
  readonly entries: readonly EntryOutcome[];
}

export interface JsonVerifySuccess {
  readonly ok: true;
  readonly payload: Uint8Array;
  /** Distinct principals established by successful entries. */
  readonly principals: ReadonlySet<string>;
  readonly entries: readonly EntryOutcome[];
}

export type JsonVerifyResult = JsonVerifySuccess | JsonVerifyFailure;

export interface JsonVerifyOptions {
  readonly policy: AlgorithmPolicy;
  readonly aggregate: AggregatePolicy;
  /** Candidate keys with their configured principals. */
  readonly signers: readonly TrustedSigner[];
  readonly limits: Limits;
  readonly detachedPayload?: Uint8Array | undefined;
  /**
   * Accepts RFC 7797 unencoded payloads. Off by default: the parameter decides
   * what the signing input is built from, so a token must not be able to select
   * a payload mode the caller never enabled.
   */
  readonly unencodedPayload?: boolean | undefined;
  readonly legacyEddsaCurve?: string | undefined;
  /**
   * Opt in to counting MAC-backed principals in the aggregate policy.
   *
   * Only a profile whose semantics treat the corresponding principals as
   * shared-secret security domains, rather than as independently attributable
   * parties, may set this.
   */
  readonly sharedSecretDomains?: boolean | undefined;
  /**
   * Budget shared with an enclosing operation, so a nested token's work counts
   * against the same totals as its container. Absent, this operation owns its
   * own budget: a standalone call still accounts, rather than running unbounded
   * because nobody passed one in.
   */
  readonly operationBudget?: OperationBudget | undefined;
}

function fail(
  stage: TrustStage,
  category: ErrorCategory,
  reason: string,
  entries: readonly EntryOutcome[] = [],
): JsonVerifyFailure {
  return { ok: false, category, stage, reason, entries };
}

/**
 * These are the same invariants a published key snapshot must satisfy. They are
 * checked here because this API accepts a signer list directly, which would
 * otherwise be a way to reach verification with a configuration the snapshot
 * builder would have refused.
 */
function validateSignerConfiguration(options: JsonVerifyOptions): JsonVerifyFailure | undefined {
  if (options.signers.length === 0) {
    return fail('configuration', 'policy_violation', 'no_trusted_signers');
  }
  if (options.signers.length > options.limits.jwksKeys) {
    return fail('configuration', 'resource_limit', 'too_many_trusted_signers');
  }
  if (options.signers.some((signer) => signer.principalId.length === 0)) {
    return fail('configuration', 'policy_violation', 'principal_id_empty');
  }

  // The policy is a structural value, so a hand-built one can reach here
  // without passing its constructor. An empty required or eligible set would be
  // satisfied by no signatures at all.
  if (referencedPrincipals(options.aggregate).size === 0) {
    return fail('configuration', 'policy_violation', 'aggregate_policy_references_no_principal');
  }

  const invariant = checkPrincipalInvariants(options.signers);
  if (invariant !== undefined && !invariant.ok) {
    return fail('configuration', invariant.category, invariant.reason);
  }

  // A MAC establishes only that some holder of the shared secret produced the
  // entry, so MAC-backed principals are not independently attributable signers.
  // Counting them toward a distinct-signer policy requires a profile that
  // explicitly treats them as shared-secret domains.
  if (!(options.sharedSecretDomains ?? false)) {
    const counted = referencedPrincipals(options.aggregate);
    const macPrincipal = options.signers.find(
      (signer) => signer.key.keyType === 'oct' && counted.has(signer.principalId),
    );
    if (macPrincipal !== undefined) {
      return fail('configuration', 'policy_violation', 'mac_principal_requires_shared_secret_profile');
    }
  }

  return undefined;
}

export async function verifyJson(source: Uint8Array, options: JsonVerifyOptions): Promise<JsonVerifyResult> {
  // The signer collection is trusted configuration, so it is validated as a
  // whole before the token is looked at. The aggregate predicate counts
  // distinct principals; without these invariants one key bound to two
  // principals, or two HMAC secrets sharing an authentication capability,
  // would let a single signer satisfy a policy demanding several.
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('configuration', 'policy_violation', limitDefect);
  }

  const signers = validateSignerConfiguration(options);
  if (signers !== undefined) {
    return signers;
  }

  if (source.length > options.limits.joseInput) {
    return fail('syntax', 'resource_limit', 'input_too_large');
  }

  const budget = options.operationBudget ?? new OperationBudget(options.limits);
  if (!budget.consumeLayer()) {
    return fail('syntax', 'resource_limit', 'too_many_cryptographic_layers');
  }

  const json = parseJson(source, options.limits);
  if (!json.ok) {
    const category: ErrorCategory =
      json.failure === 'resource_limit'
        ? 'resource_limit'
        : json.failure === 'invalid_encoding'
          ? 'invalid_encoding'
          : 'malformed_input';
    return fail('syntax', category, `jws_${json.failure}`);
  }

  if (!budget.consumeJsonNodes(json.nodes)) {
    return fail('syntax', 'resource_limit', 'json_node_budget_exceeded');
  }

  const parsed = parseJsonJws(json.value, options.limits);
  if (!parsed.ok) {
    return fail('syntax', parsed.category, parsed.reason);
  }
  const object = parsed.value;

  const payload = resolvePayloadSource(object.payloadComponent, options);
  if (!payload.ok) {
    return payload.failure;
  }

  // Every entry is prepared before any of them is verified. A structural defect
  // anywhere rejects the whole object, including in an entry that would not have
  // satisfied the policy, so the construction is unreachable rather than merely
  // outvoted by entries that happened to verify.
  const prepared = preflight(object.signatures, options);
  if (!prepared.ok) {
    return prepared.failure;
  }

  const entries: EntryOutcome[] = [];
  const established = new Set<string>();

  for (const [index, entry] of prepared.value.entries()) {
    // Sequential on purpose: every entry is evaluated, in order, with no
    // short-circuit, so one failing entry never stops the others being tried.
    // Running these concurrently would also let the object's entry count decide
    // how much work is done at once.
    // oxlint-disable-next-line no-await-in-loop
    const outcome = await evaluateEntry(entry, index, object.payloadComponent, payload, options, budget);
    entries.push(outcome);

    if (outcome.ok && outcome.principalId !== undefined) {
      established.add(outcome.principalId);
    }
  }

  const b64Values = new Set(prepared.value.map((entry) => entry.encoded));

  if (!isSatisfied(options.aggregate, established)) {
    // Per-entry results are preserved: the object may contain perfectly valid
    // signatures that simply do not satisfy the configured signer policy.
    return fail('cryptographic', 'policy_violation', 'aggregate_policy_unsatisfied', entries);
  }

  // Decoding is deferred until acceptance so that no payload is produced from
  // an object whose signatures did not satisfy the policy. The encoding is
  // taken from the entries, which have just been shown to agree.
  const encoded = !b64Values.has(false);
  const plaintext = decodeAcceptedPayload(object.payloadComponent, payload, encoded, options.limits);
  if (!plaintext.ok) {
    return fail('syntax', plaintext.category, plaintext.reason, entries);
  }

  return { ok: true, payload: plaintext.bytes, principals: established, entries };
}

interface PayloadSource {
  readonly ok: true;
  /** External octets in detached mode; empty when the payload is embedded. */
  readonly plaintext: Uint8Array;
  readonly detached: boolean;
}

/**
 * Produces the authenticated payload octets once the object has been accepted.
 *
 * In detached mode the caller already supplied them. In embedded mode the
 * member is decoded according to the payload-encoding mode the entries agreed
 * on.
 */
function decodeAcceptedPayload(
  component: string | undefined,
  payload: PayloadSource,
  encoded: boolean,
  limits: Limits,
):
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string } {
  if (payload.detached || component === undefined) {
    return { ok: true, bytes: payload.plaintext };
  }

  if (!encoded) {
    const octets = new TextEncoder().encode(component);
    if (octets.length > limits.payload) {
      return { ok: false, category: 'resource_limit', reason: 'payload_too_large' };
    }
    // The accepted inline profile matches creation's. JSON mode permits the
    // period, which has no separator role in this serialization.
    const permitted = validateInlineUnencodedPayload(octets, true);
    if (!permitted.ok) {
      return { ok: false, category: 'policy_violation', reason: permitted.failure };
    }
    return { ok: true, bytes: octets };
  }

  const decoded = decodeBase64url(component, limits.payload);
  if (!decoded.ok) {
    return decoded.failure === 'too_large'
      ? { ok: false, category: 'resource_limit', reason: 'payload_too_large' }
      : { ok: false, category: 'invalid_encoding', reason: 'payload_invalid_base64url' };
  }
  return { ok: true, bytes: decoded.bytes };
}

function resolvePayloadSource(
  component: string | undefined,
  options: JsonVerifyOptions,
): PayloadSource | { readonly ok: false; readonly failure: JsonVerifyFailure } {
  const detached = options.detachedPayload;

  if (detached !== undefined) {
    // Detached form omits the member entirely; an embedded payload alongside
    // external content is ambiguous about which one the signatures cover.
    if (component !== undefined) {
      return { ok: false, failure: fail('syntax', 'invalid_header', 'ambiguous_payload_source') };
    }
    if (detached.length > options.limits.detachedPayload) {
      return { ok: false, failure: fail('syntax', 'resource_limit', 'detached_payload_too_large') };
    }
    // Snapshotted once at entry: the caller retains its array and can change it
    // while entries await the provider, which would otherwise let the returned
    // payload differ from the bytes every entry authenticated.
    return { ok: true, plaintext: new Uint8Array(detached), detached: true };
  }

  if (component === undefined) {
    // Detachment is never inferred from an absent member; the caller must say so.
    return { ok: false, failure: fail('syntax', 'invalid_header', 'payload_missing') };
  }

  return { ok: true, plaintext: new Uint8Array(), detached: false };
}

/**
 * An entry carried through preflight with everything the entry loop needs, so
 * no header or signature component is decoded twice.
 *
 * `deferred` holds a rejection whose scope is this entry alone. It is not
 * raised during preflight because the object may still be valid: an entry
 * naming an unimplemented critical extension fails on its own without making
 * the shared payload or the other entries unusable.
 */
interface PreparedEntry {
  readonly entry: JsonSignatureEntry;
  readonly header: MergedHeader;
  readonly encoded: boolean;
  readonly signature: Uint8Array;
  readonly deferred?: { readonly category: ErrorCategory; readonly reason: string } | undefined;
}

type Preflight =
  | { readonly ok: true; readonly value: readonly PreparedEntry[] }
  | { readonly ok: false; readonly failure: JsonVerifyFailure };

/**
 * Validates every whole-object invariant before any entry is verified.
 *
 * Structure, header collisions, parameter types, signature encoding, and the
 * shared payload-encoding agreement all describe the object rather than one
 * entry, so a defect in any of them rejects it outright. Checking them after
 * the entry loop would let cryptographically valid entries in a malformed
 * object reach the aggregate policy, and would run the cryptography of an
 * object already known to be unusable.
 */
function preflight(entries: readonly JsonSignatureEntry[], options: JsonVerifyOptions): Preflight {
  const prepared: PreparedEntry[] = [];

  for (const entry of entries) {
    const decoded = decodeProtectedHeader(entry.protectedComponent, options.limits);
    if (!decoded.ok) {
      return { ok: false, failure: fail('syntax', decoded.category, decoded.reason) };
    }

    // A prohibited algorithm anywhere makes the whole object unreachable, so it
    // is read from the protected members directly rather than waiting for the
    // merged header: no later defect should be able to preempt it.
    const alg = decoded.object.members.get('alg');
    if (alg !== undefined && alg.kind === 'string' && isProhibitedAlgorithm(alg.value, 'jws')) {
      return { ok: false, failure: fail('header', 'prohibited_algorithm', 'prohibited_algorithm') };
    }

    const sources: HeaderSource[] = [{ origin: 'protected', object: decoded.object, sourceBytes: decoded.byteLength }];
    if (entry.unprotectedHeader !== undefined) {
      // Unprotected members are not covered by the signature. They are merged
      // for provenance and collision detection only, and never contribute to
      // the signing input.
      sources.push({ origin: 'per_entry_unprotected', object: entry.unprotectedHeader, sourceBytes: 0 });
    }

    const merged = mergeHeaders(sources, options.limits);
    if (!merged.ok) {
      return { ok: false, failure: fail('header', merged.category, merged.reason) };
    }
    const header = merged.header;

    const types = validateParameterTypes(header, options.limits);
    if (!types.ok) {
      return { ok: false, failure: fail('header', types.category, types.reason) };
    }

    const critical = validateCritical(header, 'jws');
    // A structurally malformed list rejects the object; an unimplemented
    // extension is this entry's own failure and still yields its names, so the
    // `b64` it declared counts toward the agreement below.
    if (!critical.ok && !('names' in critical)) {
      return { ok: false, failure: fail('header', critical.category, critical.reason) };
    }

    const b64 = resolveB64(header, critical.names, options.unencodedPayload === true);
    if (!b64.ok) {
      return { ok: false, failure: fail('header', b64.category, b64.reason) };
    }

    const signature = decodeBase64url(entry.signatureComponent, options.limits.signatureOctets);
    if (!signature.ok) {
      const category: ErrorCategory = signature.failure === 'too_large' ? 'resource_limit' : 'invalid_encoding';
      return { ok: false, failure: fail('syntax', category, 'signature_invalid') };
    }

    prepared.push({
      entry,
      header,
      encoded: b64.encoded,
      signature: signature.bytes,
      deferred: critical.ok ? undefined : { category: critical.category, reason: critical.reason },
    });
  }

  // Entries disagreeing about payload encoding describe different signing
  // inputs for one shared payload, which is not a valid object regardless of
  // which entries would have verified.
  if (new Set(prepared.map((item) => item.encoded)).size > 1) {
    return { ok: false, failure: fail('header', 'invalid_header', 'inconsistent_b64_across_signatures') };
  }

  return { ok: true, value: prepared };
}

type DecodedHeader =
  | { readonly ok: true; readonly object: JsonObject; readonly byteLength: number }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function decodeProtectedHeader(component: string, limits: Limits): DecodedHeader {
  const bytes = decodeBase64url(component, limits.headerSource);
  if (!bytes.ok) {
    return bytes.failure === 'too_large'
      ? { ok: false, category: 'resource_limit', reason: 'protected_header_too_large' }
      : { ok: false, category: 'invalid_encoding', reason: 'protected_header_invalid_base64url' };
  }

  const json = parseJson(bytes.bytes, limits);
  if (!json.ok) {
    const category: ErrorCategory =
      json.failure === 'resource_limit'
        ? 'resource_limit'
        : json.failure === 'invalid_encoding'
          ? 'invalid_encoding'
          : 'malformed_input';
    return { ok: false, category, reason: `protected_header_${json.failure}` };
  }

  const object = requireHeaderObject(json.value);
  if (!object.ok) {
    return { ok: false, category: object.category, reason: object.reason };
  }

  return { ok: true, object: object.object, byteLength: bytes.bytes.length };
}

function entryFailure(index: number, stage: TrustStage, category: ErrorCategory, reason: string): EntryOutcome {
  return { index, ok: false, principalId: undefined, header: undefined, category, stage, reason };
}

/**
 * Evaluates one prepared entry's algorithm policy and cryptography.
 *
 * A failure here is recorded against this entry alone. It never aborts the
 * loop, because another entry may still establish a principal the aggregate
 * policy needs. Everything with whole-object scope has already been settled.
 */
async function evaluateEntry(
  prepared: PreparedEntry,
  index: number,
  payloadComponent: string | undefined,
  payload: PayloadSource,
  options: JsonVerifyOptions,
  budget: OperationBudget,
): Promise<EntryOutcome> {
  const { entry, header, encoded, signature } = prepared;

  if (prepared.deferred !== undefined) {
    return entryFailure(index, 'header', prepared.deferred.category, prepared.deferred.reason);
  }

  const algMember = header.parameters.get('alg');
  if (algMember === undefined) {
    return entryFailure(index, 'header', 'invalid_header', 'alg_missing');
  }
  if (algMember.value.kind !== 'string') {
    return entryFailure(index, 'header', 'invalid_header', 'alg_not_a_string');
  }
  // An unprotected algorithm is not covered by the signature and could be
  // rewritten in transit.
  if (algMember.origin !== 'protected') {
    return entryFailure(index, 'header', 'invalid_header', 'alg_not_protected');
  }

  const algorithm = algMember.value.value;

  const decision = decideAlgorithm(options.policy, algorithm);
  if (!decision.ok) {
    return entryFailure(index, 'header', decision.category, decision.reason);
  }

  const signingInput = buildEntrySigningInput(entry.protectedComponent, payloadComponent, payload, encoded);
  if (!signingInput.ok) {
    return entryFailure(index, 'cryptographic', 'invalid_header', signingInput.failure);
  }

  // Exactly one key must be eligible. Several eligible keys is ambiguity about
  // who signed, not permission to try each one until something verifies:
  // trying them in turn would let the object's author decide which identity a
  // successful signature is attributed to.
  let eligible = options.signers.filter(
    (signer) => signer.key.algorithm === algorithm && signer.key.operation === 'verify',
  );

  const kid = header.parameters.get('kid');
  if (kid !== undefined && kid.value.kind === 'string') {
    // A present `kid` is applied as an exact filter over the already-trusted
    // candidates. It never introduces a key or widens the set. Matching nothing
    // is a resolution failure rather than a fallback to the unnarrowed set:
    // falling back would accept an object naming a key absent from the snapshot
    // by verifying it against a different key the caller happens to trust.
    const hint = kid.value.value;
    eligible = eligible.filter((signer) => signer.key.metadata.kid === hint);
  }

  if (eligible.length === 0) {
    return entryFailure(index, 'key_resolution', 'key_resolution_failure', 'no_eligible_key');
  }
  if (eligible.length > options.limits.candidateKeys) {
    return entryFailure(index, 'key_resolution', 'key_resolution_failure', 'ambiguous_key');
  }

  // Charged per entry, before the operation runs: the object's entry count
  // decides how many verifications a caller is asked to perform, so it must not
  // be able to demand unbounded work.
  if (!budget.consumeAttempt()) {
    return entryFailure(index, 'cryptographic', 'resource_limit', 'cryptographic_attempt_budget_exceeded');
  }

  const candidate = eligible[0]!;
  const verified = await verifyWithKey(candidate.key, signingInput.bytes, signature, {
    legacyEddsaCurve: options.legacyEddsaCurve,
  });

  if (!verified.ok) {
    // A provider fault is reported as such rather than collapsed into a
    // verification failure, which would make an outage look like a forgery.
    const category: ErrorCategory = verified.failure === 'unsupported' ? 'unsupported_algorithm' : 'backend_failure';
    return entryFailure(index, 'cryptographic', category, 'provider_failure');
  }

  if (!verified.value) {
    return entryFailure(index, 'cryptographic', 'signature_verification_failure', 'signature_did_not_verify');
  }

  return {
    index,
    ok: true,
    principalId: candidate.principalId,
    header,
    category: undefined,
    stage: undefined,
    reason: undefined,
  };
}

/**
 * Builds one entry's signing input.
 *
 * Each entry has its own protected header, so each has its own signing input
 * even though the payload is shared.
 */
function buildEntrySigningInput(
  protectedComponent: string,
  payloadComponent: string | undefined,
  payload: PayloadSource,
  encoded: boolean,
) {
  if (!payload.detached && payloadComponent !== undefined) {
    // The received component is authenticated verbatim in encoded mode. In
    // unencoded mode the member holds the payload characters themselves, which
    // must satisfy the accepted profile before any signature is computed over
    // them.
    if (!encoded) {
      const octets = new TextEncoder().encode(payloadComponent);
      const permitted = validateInlineUnencodedPayload(octets, true);
      if (!permitted.ok) {
        return permitted;
      }
      return buildSigningInput(protectedComponent, { octets });
    }
    return buildSigningInput(protectedComponent, { component: payloadComponent });
  }

  // Detached encoded mode authenticates Base64url of the external bytes;
  // unencoded mode authenticates those bytes directly.
  return encoded
    ? buildSigningInput(protectedComponent, {
        component: Buffer.from(payload.plaintext).toString('base64url'),
      })
    : buildSigningInput(protectedComponent, { octets: payload.plaintext });
}
