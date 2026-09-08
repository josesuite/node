/**
 * JWE creation.
 *
 * There is one plaintext and one content-encryption operation regardless of how
 * many recipients there are. Every recipient receives the same CEK by its own
 * key-management path; encrypting the plaintext separately per recipient would
 * produce several ciphertexts where the format defines one, and would multiply
 * the nonce budget without the allocator knowing.
 *
 * The protected header is serialized once and its encoded form is what enters
 * the authenticated data. Nothing downstream reserializes it, so the bytes a
 * recipient authenticates are exactly the bytes emitted here.
 *
 * Output is published only when every step succeeded. A partial object would
 * offer an attacker a ciphertext whose recipient set was decided by a failure.
 */

import { contentEncryptionShape, sealContent } from '../algorithms/content-encryption/index.ts';
import { keyManagementShape } from '../algorithms/jwe/index.ts';
import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { decodeBase64url, encodeBase64url } from '../internal/encoding/base64url.ts';
import { encodeUtf8 } from '../internal/encoding/utf8.ts';
import { checkSuppliedParameterType, isBaseParameter, type SuppliedHeaderValue } from '../internal/headers/critical.ts';
import type { RandomSource } from '../internal/crypto/backend.ts';
import type { UsableKey } from '../key/import.ts';
import { type AlgorithmPolicy, decideAlgorithm } from '../policy/algorithms.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import { type NonceAllocator, nonceFailureCategory } from './nonce.ts';
import { type EphemeralPublicKey, type PartyInfo, type ProtectedRecipient, protectCek } from './protect-cek.ts';
import { buildAdditionalData } from './types.ts';

/** One recipient's key and the header members its algorithm needs. */
export interface RecipientInput {
  readonly key: UsableKey;
  /**
   * Unprotected members for this recipient, carried verbatim and excluded from
   * the authenticated data. These stay unauthenticated hints and must not hold
   * security-relevant data.
   */
  readonly unprotectedHeader?: Readonly<Record<string, string>> | undefined;
  /**
   * Names this recipient's long-lived AES key in the nonce allocator, required
   * whenever that key is used under a construction whose nonce must never
   * repeat: `dir` with a GCM content algorithm, and the GCM key-wrap modes.
   *
   * Provisioned by the deployment rather than derived here, for two reasons.
   * Only the deployment knows which separately configured entries are aliases of
   * one physical key, and every value derivable from a symmetric key is
   * secret-derived, so computing one would publish it to an external store. Two
   * names for one key must be given one identity: treating them separately
   * issues one nonce twice under that key, which is the failure the allocator
   * exists to prevent.
   */
  readonly keyIdentity?: string | undefined;
}

export interface EncryptOptions {
  readonly keyPolicy: AlgorithmPolicy;
  readonly contentPolicy: AlgorithmPolicy;
  readonly contentAlgorithm: string;
  readonly recipients: readonly RecipientInput[];
  readonly limits: Limits;
  readonly random: RandomSource;
  /**
   * Durable allocator, required whenever the content algorithm uses a nonce
   * that must never repeat. Its absence is a configuration error rather than a
   * cue to generate one locally.
   */
  readonly nonceAllocator?: NonceAllocator | undefined;
  /** Extra protected members; `alg` and `enc` come from the keys and options. */
  readonly protectedHeader?: Readonly<Record<string, string | boolean | string[]>> | undefined;
  /** External AAD octets. Zero octets emit no `aad` member. */
  readonly externalAad?: Uint8Array | undefined;
  /** Emit the single-recipient Flattened form instead of `recipients`. */
  readonly flattened?: boolean | undefined;
}

export type EncryptResult =
  | { readonly ok: true; readonly value: string }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly stage: TrustStage;
      readonly reason: string;
    };

function fail(category: ErrorCategory, reason: string, stage: TrustStage = 'configuration'): EncryptResult {
  return { ok: false, category, stage, reason };
}

export async function encryptJson(plaintext: Uint8Array, options: EncryptOptions): Promise<EncryptResult> {
  // Limits arrive as a structural value, so a caller can present one that was
  // never lowered from the baseline. Checked here so an operation either runs
  // under genuine bounds or does not run.
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('policy_violation', limitDefect);
  }
  // A policy built for acceptance permits identifiers this direction refuses,
  // so passing one here is a configuration defect rather than a per-identifier
  // outcome to be discovered further down.
  if (options.keyPolicy.operation !== 'create' || options.contentPolicy.operation !== 'create') {
    return fail('policy_violation', 'policy_not_built_for_creation');
  }
  if (options.recipients.length === 0) {
    return fail('policy_violation', 'no_recipients');
  }
  if (options.recipients.length > options.limits.recipients) {
    return fail('resource_limit', 'too_many_recipients');
  }
  if (options.flattened === true && options.recipients.length !== 1) {
    return fail('policy_violation', 'flattened_requires_single_recipient');
  }
  if (plaintext.length > options.limits.payload) {
    return fail('resource_limit', 'plaintext_too_large');
  }

  const contentDecision = decideAlgorithm(options.contentPolicy, options.contentAlgorithm);
  if (!contentDecision.ok) {
    return fail(contentDecision.category, contentDecision.reason);
  }

  const content = contentEncryptionShape(options.contentAlgorithm);
  if (content === undefined) {
    return fail('unsupported_algorithm', 'unsupported_content_algorithm');
  }

  // Every recipient's algorithm is settled before any key material is touched,
  // so a rejected combination never reaches a cryptographic operation.
  const algorithms: string[] = [];
  for (const recipient of options.recipients) {
    const algorithm = recipient.key.algorithm;
    const decision = decideAlgorithm(options.keyPolicy, algorithm);
    if (!decision.ok) {
      return fail(decision.category, decision.reason);
    }

    const shape = keyManagementShape(algorithm);
    if (shape === undefined) {
      return fail('unsupported_algorithm', 'unsupported_key_algorithm');
    }
    // The direct modes derive the CEK from one recipient's key, so a second
    // recipient could never recover it.
    if (shape.singleRecipientOnly && options.recipients.length > 1) {
      return fail('policy_violation', 'algorithm_requires_single_recipient');
    }
    const requiredOperation =
      shape.mode === 'direct'
        ? 'encrypt'
        : shape.mode === 'direct_agreement' || shape.mode === 'agreement_with_wrapping'
          ? 'deriveKey'
          : 'wrapKey';
    if (recipient.key.operation !== requiredOperation) {
      return fail('incompatible_key', 'key_operation_mismatch');
    }
    if (!recipient.key.contentAlgorithms.includes(options.contentAlgorithm)) {
      return fail('incompatible_key', 'content_algorithm_not_bound');
    }

    algorithms.push(algorithm);
  }

  // A single shared `alg` goes in the protected header; differing values would
  // need a separate policy that constrains each recipient's key
  // independently, which this entry point does not offer.
  const sharedAlgorithm = algorithms.every((value) => value === algorithms[0]) ? algorithms[0]! : undefined;
  if (sharedAlgorithm === undefined) {
    return fail('policy_violation', 'recipients_disagree_on_algorithm');
  }

  // Header semantics are settled before any randomness is drawn, any nonce is
  // reserved, or any key is used, so a rejected configuration leaves no trace:
  // no burned nonce, no consumed entropy, no cryptographic operation.
  const headerCheck = checkCallerHeaders(options);
  if (headerCheck !== undefined) {
    return headerCheck;
  }

  // Party information is emitted in the header and must also enter the KDF.
  // Deriving without it while publishing it would produce an object whose own
  // recipient derives a different key and cannot decrypt.
  const party = readPartyInfo(options.protectedHeader, keyManagementShape(sharedAlgorithm), options.limits);
  if (!party.ok) {
    return party.failure;
  }

  // The GCM key-wrap mode needs its own nonce, drawn from a space scoped to the
  // wrapping key rather than the content key: the two are different keys with
  // independent budgets, so sharing a counter would misreport both.
  const wrappingNonces: Uint8Array[] = [];
  if (keyManagementShape(sharedAlgorithm)?.mode === 'gcm_wrapping') {
    for (const recipient of options.recipients) {
      // oxlint-disable-next-line no-await-in-loop
      const reserved = await reserveWrappingNonce(recipient, options);
      if (!reserved.ok) {
        return reserved.failure;
      }
      wrappingNonces.push(reserved.bytes);
    }
  }

  // Key protection runs first because the agreement modes produce an ephemeral
  // public key that has to appear in the protected header, and the header's
  // encoded bytes are what the content is authenticated against.
  const protectedCek = await protectCek(
    options.contentAlgorithm,
    content.cekBytes,
    options.recipients,
    options.random,
    wrappingNonces,
    party.value,
  );
  if (!protectedCek.ok) {
    return fail(protectedCek.category, protectedCek.reason, 'cryptographic');
  }

  // Agreement and wrapping parameters are produced per recipient and differ
  // between them, so they only belong in the shared protected header when there
  // is exactly one recipient. With several, each recipient carries its own; the
  // parameters describe key management, which JWE-01a allows to vary per
  // recipient, and none of them decides how the plaintext is treated.
  const single = protectedCek.recipients.length === 1 ? protectedCek.recipients[0] : undefined;
  const protectedResult = buildProtectedHeader(
    sharedAlgorithm,
    single?.ephemeralPublicKey,
    single?.gcmKw,
    options,
    protectedCek.recipients,
  );
  if (!protectedResult.ok) {
    discardCek(protectedCek);
    return protectedResult.failure;
  }

  const iv = await allocateIv(sharedAlgorithm, content, options);
  if (!iv.ok) {
    discardCek(protectedCek);
    return iv.failure;
  }

  const protectedComponent = protectedResult.component;
  const aadComponent =
    options.externalAad === undefined || options.externalAad.length === 0
      ? undefined
      : encodeBase64url(options.externalAad);

  const additionalData = buildAdditionalData(protectedComponent, aadComponent);
  if (!additionalData.ok) {
    discardCek(protectedCek);
    return fail('invalid_header', additionalData.failure);
  }

  const sealed = await sealContent(
    options.contentAlgorithm,
    protectedCek.cek,
    iv.bytes,
    plaintext,
    additionalData.bytes,
  );
  discardCek(protectedCek);
  if (!sealed.ok) {
    return fail('backend_failure', 'content_encryption_failed', 'cryptographic');
  }

  const object: Record<string, unknown> = {
    protected: protectedComponent,
    iv: encodeBase64url(iv.bytes),
    ciphertext: encodeBase64url(sealed.value.ciphertext),
    tag: encodeBase64url(sealed.value.tag),
  };
  if (aadComponent !== undefined) {
    object['aad'] = aadComponent;
  }

  const entries = protectedCek.recipients.map((entry, index) => {
    const recipient: Record<string, unknown> = {};
    // Direct modes carry no encrypted key at all; the member is omitted rather
    // than emitted empty, which is a different state.
    if (entry.encryptedKey !== undefined) {
      recipient['encrypted_key'] = encodeBase64url(entry.encryptedKey);
    }
    const unprotected = options.recipients[index]!.unprotectedHeader;
    const header: Record<string, unknown> = {
      ...unprotected,
      ...(single === undefined ? algorithmParameters(entry) : {}),
    };
    if (Object.keys(header).length > 0) {
      recipient['header'] = header;
    }
    return recipient;
  });

  if (options.flattened === true) {
    Object.assign(object, entries[0]);
  } else {
    object['recipients'] = entries;
  }

  return { ok: true, value: JSON.stringify(object) };
}

type PartyResult =
  | { readonly ok: true; readonly value: PartyInfo }
  | { readonly ok: false; readonly failure: EncryptResult };

/**
 * Decodes the caller's `apu`/`apv` so the same octets reach both the emitted
 * header and the KDF.
 *
 * The two are only defined for the agreement modes. Supplying them elsewhere is
 * refused rather than serialized as an inert member, because a producer setting
 * them expects them bound into a derivation that never runs.
 */
function readPartyInfo(
  header: Readonly<Record<string, string | boolean | string[]>> | undefined,
  shape: { readonly mode: string } | undefined,
  limits: Limits,
): PartyResult {
  const supplied = { apu: header?.['apu'], apv: header?.['apv'] };
  if (supplied.apu === undefined && supplied.apv === undefined) {
    return { ok: true, value: {} };
  }

  if (shape?.mode !== 'direct_agreement' && shape?.mode !== 'agreement_with_wrapping') {
    return { ok: false, failure: fail('invalid_header', 'party_info_requires_agreement_algorithm') };
  }

  const decoded: { -readonly [K in keyof PartyInfo]: PartyInfo[K] } = {};
  for (const [member, name] of [
    ['apu', 'partyU'],
    ['apv', 'partyV'],
  ] as const) {
    const value = supplied[member];
    if (value === undefined) {
      continue;
    }
    if (typeof value !== 'string') {
      return { ok: false, failure: fail('invalid_header', `${member}_not_a_string`) };
    }
    const bytes = decodeBase64url(value, limits.headerSource);
    if (!bytes.ok) {
      return { ok: false, failure: fail('invalid_header', `${member}_invalid_base64url`) };
    }
    decoded[name] = bytes.bytes;
  }

  return { ok: true, value: decoded };
}

/**
 * Serializes one recipient's own agreement or wrapping parameters.
 *
 * Only the public members of the ephemeral key are published; a private member
 * would leak the ephemeral secret and let anyone derive the CEK. The `iv` and
 * `tag` here name the wrapping values, not the content ones.
 */
function algorithmParameters(entry: ProtectedRecipient): Record<string, unknown> {
  const members: Record<string, unknown> = {};

  if (entry.ephemeralPublicKey !== undefined) {
    members['epk'] = encodeEphemeral(entry.ephemeralPublicKey);
  }
  if (entry.gcmKw !== undefined) {
    members['iv'] = encodeBase64url(entry.gcmKw.iv);
    members['tag'] = encodeBase64url(entry.gcmKw.tag);
  }

  return members;
}

function encodeEphemeral(key: EphemeralPublicKey): Record<string, string> {
  const epk: Record<string, string> = { kty: key.kty, crv: key.crv, x: encodeBase64url(key.x) };
  if (key.y !== undefined) {
    epk['y'] = encodeBase64url(key.y);
  }
  return epk;
}

function discardCek(value: { readonly cek: Uint8Array; readonly ownsCek: boolean }): void {
  if (value.ownsCek) {
    value.cek.fill(0);
  }
}

type WrappingNonceResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: EncryptResult };

/**
 * Reserves a wrapping nonce from the durable allocator.
 *
 * The space is scoped to the recipient's actual wrapping key and prefixed to
 * keep it separate from that key's content-encryption space, so a key used for
 * both is not counted once under two constructions.
 */
async function reserveWrappingNonce(recipient: RecipientInput, options: EncryptOptions): Promise<WrappingNonceResult> {
  if (options.nonceAllocator === undefined) {
    return { ok: false, failure: fail('policy_violation', 'nonce_allocator_required') };
  }
  if (recipient.keyIdentity === undefined || recipient.keyIdentity.length === 0) {
    // Without it the allocator cannot tell this key from any other key sharing
    // the algorithm, and would hand both the same counter.
    return { ok: false, failure: fail('policy_violation', 'key_identity_required') };
  }

  let reservation;
  try {
    reservation = await options.nonceAllocator.reserve(`keywrap:${recipient.keyIdentity}`);
  } catch {
    return { ok: false, failure: fail('backend_failure', 'nonce_allocator_unavailable', 'cryptographic') };
  }
  if (!reservation.ok) {
    return {
      ok: false,
      failure: fail(nonceFailureCategory(reservation.failure), `nonce_${reservation.failure}`, 'cryptographic'),
    };
  }

  return { ok: true, bytes: reservation.reservation.nonce };
}

type IvResult =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: EncryptResult };

/**
 * Obtains the content IV.
 *
 * A construction whose nonce must never repeat draws from the durable
 * allocator, so uniqueness survives restarts, forks, and snapshot restores.
 * One that needs only an unpredictable IV draws from the CSPRNG. The two are
 * not interchangeable: a random 96-bit GCM nonce repeats often enough to matter
 * at scale, and a counter would make CBC's IV predictable.
 *
 * Which key owns the reserved space depends on the mode. Under `dir` the CEK is
 * the caller's configured long-lived key, so the space is that key's and must
 * persist across every message and every process encrypting under it. Every
 * other mode generates a fresh CEK for this message alone, and a nonce cannot
 * repeat under a key that encrypts exactly once, so no durable reservation
 * applies there.
 */
async function allocateIv(
  keyAlgorithm: string,
  content: { ivBytes: number; requiresUniqueNonce: boolean },
  options: EncryptOptions,
): Promise<IvResult> {
  const cekIsConfigured = keyManagementShape(keyAlgorithm)?.mode === 'direct';

  if (!content.requiresUniqueNonce || !cekIsConfigured) {
    let random;
    try {
      random = options.random.randomBytes(content.ivBytes);
    } catch {
      return { ok: false, failure: fail('backend_failure', 'randomness_unavailable', 'cryptographic') };
    }
    return random.ok && random.value.length === content.ivBytes
      ? { ok: true, bytes: random.value }
      : { ok: false, failure: fail('backend_failure', 'randomness_unavailable', 'cryptographic') };
  }

  if (options.nonceAllocator === undefined) {
    // Generating one locally would satisfy the type while losing the guarantee
    // the allocator exists to provide, so this fails closed instead.
    return { ok: false, failure: fail('policy_violation', 'nonce_allocator_required') };
  }

  // `dir` is limited to one recipient, so that recipient names the content key.
  const identity = options.recipients[0]?.keyIdentity;
  if (identity === undefined || identity.length === 0) {
    return { ok: false, failure: fail('policy_violation', 'key_identity_required') };
  }

  // Prefixed so a key used both to wrap and to encrypt content keeps two
  // separate spaces rather than one counter shared across constructions.
  let reservation;
  try {
    reservation = await options.nonceAllocator.reserve(`content:${identity}`);
  } catch {
    return { ok: false, failure: fail('backend_failure', 'nonce_allocator_unavailable', 'cryptographic') };
  }
  if (!reservation.ok) {
    return {
      ok: false,
      failure: fail(nonceFailureCategory(reservation.failure), `nonce_${reservation.failure}`, 'cryptographic'),
    };
  }

  if (reservation.reservation.nonce.length !== content.ivBytes) {
    return { ok: false, failure: fail('policy_violation', 'nonce_wrong_length', 'cryptographic') };
  }

  return { ok: true, bytes: reservation.reservation.nonce };
}

/**
 * Header names this entry point sets itself.
 *
 * The algorithms come from the keys and the caller's content choice, the
 * agreement and wrapping parameters are produced by key protection, and
 * compression is not offered, so none may be supplied by a caller.
 */
const RESERVED_HEADER_NAMES: ReadonlySet<string> = new Set(['alg', 'enc', 'zip', 'epk', 'iv', 'tag', 'p2s', 'p2c']);

/**
 * Names that must never appear in an unprotected header.
 *
 * `crit` and `zip` are required to be protected, so emitting either
 * unprotected would produce an object a conforming recipient rejects.
 */
const PROTECTED_ONLY_NAMES: ReadonlySet<string> = new Set(['crit', 'zip', 'alg', 'enc']);

/**
 * Validates the caller's header configuration before any cryptography.
 *
 * A producer must not emit what its corresponding consumer refuses, so this
 * applies the same recognized-parameter types and critical-extension rules the
 * receive side enforces. Own properties only: a name such as `constructor` or
 * `__proto__` supplied by a caller stays ordinary data rather than reaching an
 * inherited member or a prototype assignment.
 */
function checkCallerHeaders(options: EncryptOptions): EncryptResult | undefined {
  const supplied = options.protectedHeader ?? {};

  for (const name of Object.keys(supplied)) {
    if (!checkSuppliedParameterType(name, supplied[name], options.limits)) {
      return fail('invalid_header', `header_${name}_wrong_type`);
    }
  }

  const critical = checkCriticalList(supplied);
  if (critical !== undefined) {
    return critical;
  }

  for (const recipient of options.recipients) {
    const unprotected = recipient.unprotectedHeader ?? {};
    for (const name of Object.keys(unprotected)) {
      if (PROTECTED_ONLY_NAMES.has(name)) {
        return fail('invalid_header', `unprotected_${name}_not_permitted`);
      }
      if (RESERVED_HEADER_NAMES.has(name)) {
        return fail('invalid_header', `reserved_header_${name}`);
      }
      // Recognized types are fixed by the parameter, not by which header source
      // carries it, so an unprotected member is held to the same contract.
      if (!checkSuppliedParameterType(name, unprotected[name], options.limits)) {
        return fail('invalid_header', `header_${name}_wrong_type`);
      }
    }
  }

  return undefined;
}

/**
 * Applies the critical-list construction rules to a producer's own header.
 *
 * A producer must not name an extension its corresponding consumer does not
 * implement: doing so emits an object that consumer is required to reject, so
 * the defect belongs here rather than at the recipient.
 */
function checkCriticalList(supplied: Readonly<Record<string, SuppliedHeaderValue>>): EncryptResult | undefined {
  const critical = supplied['crit'];
  if (critical === undefined) {
    return undefined;
  }

  const names = critical as readonly string[];
  if (names.length === 0) {
    return fail('invalid_header', 'crit_empty');
  }

  // Every name is checked for the malformed-list defects before any is reported
  // as unimplemented, so a list that is both malformed and unimplementable is
  // reported as malformed, matching the receive side's precedence.
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) {
      return fail('invalid_header', 'crit_duplicate_name');
    }
    seen.add(name);

    if (isBaseParameter(name, 'jwe')) {
      return fail('invalid_header', 'crit_names_base_parameter');
    }
    if (!Object.hasOwn(supplied, name)) {
      return fail('invalid_header', 'crit_names_absent_parameter');
    }
  }

  // No JWE critical extension has implemented semantics here, so a well-formed
  // list still demands processing that does not exist.
  return fail('unsupported_critical_parameter', 'critical_extension_not_implemented');
}

type HeaderResult =
  | { readonly ok: true; readonly component: string }
  | { readonly ok: false; readonly failure: EncryptResult };

function buildProtectedHeader(
  algorithm: string,
  ephemeralPublicKey: EphemeralPublicKey | undefined,
  gcmKw: { readonly iv: Uint8Array; readonly tag: Uint8Array } | undefined,
  options: EncryptOptions,
  protectedRecipients: readonly ProtectedRecipient[],
): HeaderResult {
  const members: Record<string, string | boolean | string[] | Record<string, string>> = {};

  for (const [name, value] of Object.entries(options.protectedHeader ?? {})) {
    // The algorithms come from the keys and the caller's content choice, and
    // compression is not offered, so none may be supplied here.
    if (RESERVED_HEADER_NAMES.has(name)) {
      return { ok: false, failure: fail('invalid_header', `reserved_header_${name}`) };
    }
    members[name] = value;
  }

  members['alg'] = algorithm;
  members['enc'] = options.contentAlgorithm;

  if (ephemeralPublicKey !== undefined) {
    members['epk'] = encodeEphemeral(ephemeralPublicKey);
  }

  if (gcmKw !== undefined) {
    // These name the wrapping IV and tag, not the content ones; a recipient
    // cannot unwrap without them.
    members['iv'] = encodeBase64url(gcmKw.iv);
    members['tag'] = encodeBase64url(gcmKw.tag);
  }

  // With one recipient the algorithm parameters are in the protected header
  // above rather than in a recipient header, so they cannot collide with
  // themselves.
  const perRecipient = protectedRecipients.length === 1 ? [] : protectedRecipients;

  for (const [index, recipient] of options.recipients.entries()) {
    const emitted = perRecipient[index];
    const names = [
      ...Object.keys(recipient.unprotectedHeader ?? {}),
      ...(emitted === undefined ? [] : Object.keys(algorithmParameters(emitted))),
    ];
    for (const name of names) {
      // A name appearing in both a protected and an unprotected header has
      // ambiguous provenance, so the collision is refused at creation.
      if (name in members) {
        return { ok: false, failure: fail('invalid_header', 'header_name_collision') };
      }
    }
  }

  const serialized = encodeUtf8(JSON.stringify(members));
  if (serialized.length > options.limits.headerSource) {
    return { ok: false, failure: fail('resource_limit', 'header_too_large') };
  }

  return { ok: true, component: encodeBase64url(serialized) };
}
