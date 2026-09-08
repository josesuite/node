import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { utf8Length } from '../internal/encoding/utf8.ts';
import { normalizeMediaType } from '../internal/headers/media-type.ts';
import { isProtected } from '../internal/headers/types.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import { parseJson } from '../internal/json/parse.ts';
import type { JsonObject, JsonValue } from '../internal/json/types.ts';
import { OperationBudget } from '../internal/validation/limits.ts';
import { decryptCompact } from '../jwe/compact.ts';
import { verifyCompact, type VerifySuccess } from '../jws/verify.ts';
import { checkLimits } from '../policy/limits.ts';
import { isJwtProfile } from './profile.ts';
import { validateClaims } from './claims.ts';
import type { JwtFailure, JwtValidationResult, ValidateJwtOptions } from './types.ts';

function fail(stage: TrustStage, category: ErrorCategory, reason: string): JwtFailure {
  return { ok: false, stage, category, reason };
}

/** Reads a header parameter only when it is protected, ignoring it otherwise. */
function protectedString(header: MergedHeader, name: string): string | undefined {
  const parameter = header.parameters.get(name);
  return parameter?.origin === 'protected' && parameter.value.kind === 'string' ? parameter.value.value : undefined;
}

/**
 * Identifies the serialization by component count alone.
 *
 * A `~` marks an SD-JWT, whose trailing disclosures would otherwise be counted
 * as part of the token; it is rejected outright rather than truncated, since
 * validating only the leading portion would silently drop the disclosures.
 */
function classify(token: string): 'jws' | 'jwe' | undefined {
  if (token.includes('~')) {
    return undefined;
  }
  const segments = token.split('.').length;
  return segments === 3 ? 'jws' : segments === 5 ? 'jwe' : undefined;
}

export async function validateJwt(token: string, options: ValidateJwtOptions): Promise<JwtValidationResult> {
  const { profile, limits } = options;
  // Limits arrive as a structural value, so a caller can present one that was
  // never lowered from the baseline.
  const limitDefect = checkLimits(limits);
  if (limitDefect !== undefined) {
    return fail('configuration', 'policy_violation', limitDefect);
  }
  if (!isJwtProfile(profile)) {
    return fail('configuration', 'policy_violation', 'invalid_jwt_profile');
  }
  // One budget spans every nested layer, so a token cannot multiply the work it
  // costs by nesting structures that each stay within the per-layer limits.
  const budget = new OperationBudget(limits);

  // The clock is read once, before any parsing, so the whole validation judges
  // the token at one instant and no attacker-controlled work can shift it.
  let now: bigint;
  try {
    now = await profile.clock.now();
  } catch {
    return fail('configuration', 'backend_failure', 'trusted_clock_unavailable');
  }
  // A caller-supplied clock is untrusted input: a non-bigint or negative value
  // would otherwise silently corrupt every temporal comparison.
  if (typeof now !== 'bigint' || now < 0n) {
    return fail('configuration', 'backend_failure', 'trusted_clock_invalid');
  }
  if (utf8Length(token) > limits.jwtInput) {
    return fail('syntax', 'resource_limit', 'jwt_too_large');
  }

  const outer = classify(token);
  if (outer === undefined) {
    return fail('syntax', 'unsupported_serialization', 'jwt_requires_compact_serialization');
  }
  // The profile fixes the expected structure, so an encrypted token cannot be
  // presented where a signed one is configured or the reverse.
  if ((profile.chain === 'JWS -> claims') !== (outer === 'jws')) {
    return fail('header', 'policy_violation', 'jwt_chain_mismatch');
  }

  let verified: VerifySuccess;
  let outerHeader: VerifySuccess['header'] | undefined;
  if (outer === 'jwe') {
    const decrypted = await decryptCompact(token, { ...profile.decryption!, limits, operationBudget: budget });
    if (!decrypted.ok) {
      return decrypted;
    }
    outerHeader = decrypted.header;
    // The nested content type must be stated and protected. Inferring it from
    // the plaintext's shape would let the sender's intent be decided by the
    // bytes they supplied.
    const cty = protectedString(decrypted.header, 'cty');
    if (cty === undefined || normalizeMediaType(cty) !== 'application/jwt') {
      return fail('nested_layer', 'token_type_mismatch', 'nested_cty_mismatch');
    }
    // Fatal decoding rejects malformed sequences instead of substituting
    // replacement characters, which would alter the token being verified.
    const inner = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    let innerToken: string;
    try {
      innerToken = inner.decode(decrypted.plaintext);
    } catch {
      return fail('nested_layer', 'invalid_encoding', 'inner_jwt_invalid_utf8');
    }
    if (classify(innerToken) !== 'jws') {
      return fail('nested_layer', 'policy_violation', 'inner_layer_must_be_compact_jws');
    }
    const result = await verifyCompact(innerToken, { ...profile.verification, limits, operationBudget: budget });
    if (!result.ok) {
      return result;
    }
    verified = result;
  } else {
    const result = await verifyCompact(token, { ...profile.verification, limits, operationBudget: budget });
    if (!result.ok) {
      return result;
    }
    verified = result;
  }

  // A JWT payload is always Base64url-encoded JSON, so an unencoded payload is
  // refused rather than parsed: it could carry a period and change how the
  // token's own components are split.
  const b64 = verified.header.parameters.get('b64');
  if (b64 !== undefined && (b64.value.kind !== 'boolean' || !b64.value.value)) {
    return fail('header', 'policy_violation', 'jwt_unencoded_payload_forbidden');
  }
  const parsed = parseJson(verified.payload, limits);
  if (!parsed.ok) {
    return fail(
      'claims_syntax',
      parsed.failure === 'resource_limit'
        ? 'resource_limit'
        : parsed.failure === 'invalid_encoding'
          ? 'invalid_encoding'
          : 'malformed_input',
      `claims_${parsed.failure}`,
    );
  }
  if (!budget.consumeJsonNodes(parsed.nodes)) {
    return fail('claims_syntax', 'resource_limit', 'json_node_budget_exceeded');
  }
  if (parsed.value.kind !== 'object') {
    return fail('claims_syntax', 'claim_validation_failure', 'claims_must_be_object');
  }

  // The complete claim schema and required-field pass runs before any semantic
  // check, so a token that is both missing a required claim and carrying the
  // wrong type reports the missing claim as its primary failure.
  const claims = await validateClaims(parsed.value, profile, now, limits);
  if (!claims.ok) {
    return claims;
  }

  const typ = protectedString(verified.header, 'typ');
  if (typ === undefined || normalizeMediaType(typ) !== normalizeMediaType(profile.type)) {
    return fail('claims_semantics', 'token_type_mismatch', 'jwt_type_mismatch');
  }
  // A claim replicated into the encrypted layer's header is readable before
  // decryption, so it must agree exactly with the authenticated claim and must
  // itself be protected. A replica that disagrees would let the two layers
  // describe different tokens to different readers.
  for (const name of ['iss', 'sub', 'aud'] as const) {
    const replica = outerHeader?.parameters.get(name);
    // Replication is optional; only a present replica has to be consistent.
    if (replica === undefined) {
      continue;
    }
    const claim = parsed.value.members.get(name);
    // `aud` compares as a set, since one string and a single-element array
    // denote the same audience.
    const equal = name === 'aud' ? equalAudience(replica.value, claim) : equalJson(replica.value, claim);
    if (!isProtected(outerHeader!, name) || !equal) {
      return fail('claims_semantics', 'claim_validation_failure', `replicated_${name}_mismatch`);
    }
  }

  // The key that actually signed the token must belong to the issuer the claims
  // name. Without this, any trusted key could mint a token for any issuer.
  if (verified.principalId !== claims.value.issuer) {
    return fail('claims_semantics', 'issuer_mismatch', 'key_issuer_mismatch');
  }

  // Built before replay admission, which is an irreversible side effect: a
  // failure while projecting the claims must not consume a single-use token
  // without returning the success that consumption paid for.
  const value = Object.freeze({
    claims: claimsView(claims.value.object, true),
    profile: profile.name,
    version: 1,
    issuer: claims.value.issuer,
    principalId: verified.principalId,
    sharedSecretDomain: verified.isSharedSecret,
    validatedAt: now,
  });

  // Replay admission runs last: it records the token as consumed, so it must not
  // happen until every other check has already accepted it.
  if (profile.name === 'project-single-use-jwt-v1') {
    let admission: Awaited<ReturnType<NonNullable<typeof profile.replayStore>['admit']>>;
    try {
      admission = await profile.replayStore!.admit(
        profile.replayNamespace,
        claims.value.jwtId!,
        // Retention extends past expiry by the skew, so a token still acceptable
        // to a clock running behind cannot be replayed after its record lapses.
        claims.value.expiration + profile.skew,
      );
    } catch {
      return fail('context_admission', 'backend_failure', 'replay_store_unavailable');
    }
    if (admission === 'already_present') {
      return fail('context_admission', 'replay_detected', 'jwt_replayed');
    }
    // Any outcome other than a definite admission fails closed: a store that
    // cannot confirm uniqueness offers no replay protection.
    if (admission !== 'admitted') {
      return fail('context_admission', 'backend_failure', 'replay_store_unavailable');
    }
  }

  return { ok: true, value };
}

/**
 * Projects validated claims into a frozen plain view for the caller.
 *
 * Numbers keep their original lexeme instead of becoming JavaScript numbers,
 * which cannot represent every JSON number exactly; the registered temporal
 * claims are the exception, as they are already validated as integers and are
 * far more useful as `bigint`. The prototype is null so a claim named like an
 * `Object` member cannot appear to be present when it was never in the token.
 *
 * `topLevel` confines the NumericDate projection to the registered claims.
 * A member named `exp` inside a custom claim is an ordinary JSON number that
 * never passed NumericDate validation, so converting it could both misrepresent
 * its type and throw on a fractional or exponent lexeme.
 */
function claimsView(object: JsonObject, topLevel = false): Readonly<Record<string, unknown>> {
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [name, value] of object.members) {
    result[name] =
      value.kind === 'object'
        ? claimsView(value)
        : value.kind === 'array'
          ? Object.freeze(value.elements.map(jsonValue))
          : value.kind === 'number' && topLevel && (name === 'exp' || name === 'nbf' || name === 'iat')
            ? BigInt(value.lexeme)
            : jsonValue(value);
  }
  return Object.freeze(result);
}

function jsonValue(value: JsonValue): unknown {
  switch (value.kind) {
    case 'string':
    case 'boolean':
      return value.value;
    case 'number':
      return Object.freeze({ lexeme: value.lexeme });
    case 'null':
      return null;
    case 'object':
      return claimsView(value);
    case 'array':
      return Object.freeze(value.elements.map(jsonValue));
  }
}

/**
 * Equality for replicated claims, which are defined as strings.
 *
 * Only strings can compare equal; any other type is a mismatch rather than a
 * value to compare structurally, so a replica of an unexpected shape is refused
 * instead of being coerced into agreement.
 */
function equalJson(a: JsonValue | undefined, b: JsonValue | undefined): boolean {
  if (a === undefined || b === undefined || a.kind !== b.kind) {
    return false;
  }
  if (a.kind === 'string' && b.kind === 'string') {
    return a.value === b.value;
  }
  return false;
}

function equalAudience(a: JsonValue | undefined, b: JsonValue | undefined): boolean {
  const left = audienceSet(a);
  const right = audienceSet(b);
  return (
    left !== undefined &&
    right !== undefined &&
    left.size === right.size &&
    [...left].every((value) => right.has(value))
  );
}

/**
 * Reduces an audience value to a set, or `undefined` when it is not a valid
 * audience. A duplicate entry yields `undefined` rather than collapsing, so two
 * differently-sized lists cannot compare as the same audience.
 */
function audienceSet(value: JsonValue | undefined): ReadonlySet<string> | undefined {
  const strings =
    value?.kind === 'string'
      ? [value.value]
      : value?.kind === 'array'
        ? value.elements.map((item) => (item.kind === 'string' ? item.value : undefined))
        : undefined;
  if (strings === undefined || strings.includes(undefined)) {
    return undefined;
  }
  const set = new Set(strings as string[]);
  return set.size === strings.length ? set : undefined;
}
