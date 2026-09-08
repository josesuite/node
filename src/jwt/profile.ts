import { utf8Length } from '../internal/encoding/utf8.ts';
import { normalizeMediaType } from '../internal/headers/media-type.ts';
import { LIMITS_V1 } from '../policy/limits.ts';
import type { JwtFailure, JwtProfile, JwtProfileInput, JwtProfileName, JwtProfileResult } from './types.ts';

const NAMES = new Set<JwtProfileName>(['project-jwt-v1', 'project-single-use-jwt-v1', 'oauth-at-jwt-v1']);

/**
 * Identifies profiles that were actually built here. A structurally similar
 * object literal cannot be forged into one, so validation cannot be bypassed by
 * assembling a profile-shaped value that skipped these checks. Weak references
 * keep this from retaining profiles the caller has dropped.
 */
const PROFILES = new WeakSet<object>();

function fail(reason: string): JwtFailure {
  return { ok: false, category: 'policy_violation', stage: 'configuration', reason };
}

export function createJwtProfile(input: JwtProfileInput): JwtProfileResult {
  if (!NAMES.has(input.name as JwtProfileName)) {
    return fail('unsupported_jwt_profile');
  }
  if (input.issuer.length === 0) {
    return fail('expected_issuer_required');
  }
  if (input.audience.length === 0) {
    return fail('expected_audience_required');
  }
  if (utf8Length(input.issuer) > LIMITS_V1.identifier || utf8Length(input.audience) > LIMITS_V1.identifier) {
    return fail('expected_identifier_too_long');
  }
  // The generic `application/jwt` is refused: an explicit type is what lets a
  // verifier distinguish one kind of token from another, and accepting the
  // generic value would defeat the type check it is configured to perform.
  if (!validMediaType(input.type) || normalizeMediaType(input.type) === 'application/jwt') {
    return fail('expected_type_invalid');
  }
  if (input.name === 'oauth-at-jwt-v1' && normalizeMediaType(input.type) !== 'application/at+jwt') {
    return fail('oauth_access_token_type_required');
  }
  if (input.chain !== 'JWS -> claims' && input.chain !== 'JWE -> JWS -> claims') {
    return fail('invalid_jwt_chain');
  }
  if (input.chain === 'JWE -> JWS -> claims' && input.decryption === undefined) {
    return fail('decryption_policy_required');
  }
  if (input.chain === 'JWS -> claims' && input.decryption !== undefined) {
    return fail('unexpected_decryption_policy');
  }
  // Fixed at configuration time so that validation can compare the signing key's
  // principal against the issuer without trusting anything from the token.
  if (input.verification.principalId !== input.issuer) {
    return fail('verification_principal_must_match_issuer');
  }
  // A JWT claims set is JSON, which the unencoded profile's printable-ASCII
  // restriction cannot carry safely, and the mode is unavailable to JWT under
  // any profile rather than being merely off by default.
  if (input.verification.unencodedPayload === true) {
    return fail('unencoded_payload_not_available_for_jwt');
  }
  if (typeof input.subject !== 'function') {
    return fail('subject_validator_required');
  }
  // Skew widens every temporal window, so it is capped rather than left to the
  // caller: a large value would keep expired tokens acceptable indefinitely.
  const skew = input.skew ?? 0;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 300) {
    return fail('invalid_clock_skew');
  }
  if (input.name === 'project-single-use-jwt-v1' && input.replayStore === undefined) {
    return fail('replay_store_required');
  }
  if (
    input.name === 'oauth-at-jwt-v1' &&
    (!input.verification.policy.has('RS256') || input.verification.key.algorithm !== 'RS256')
  ) {
    return fail('oauth_rs256_support_required');
  }
  if (
    input.maximumLifetime !== undefined &&
    (!Number.isSafeInteger(input.maximumLifetime) || input.maximumLifetime <= 0)
  ) {
    return fail('invalid_maximum_lifetime');
  }
  if (input.name === 'oauth-at-jwt-v1' && input.maximumLifetime === undefined) {
    return fail('oauth_maximum_lifetime_required');
  }
  if (input.name !== 'oauth-at-jwt-v1' && input.maximumLifetime !== undefined) {
    return fail('fixed_maximum_lifetime');
  }

  const name = input.name as JwtProfileName;
  const verification = Object.freeze({ ...input.verification });
  const decryption =
    input.decryption === undefined
      ? undefined
      : Object.freeze({ ...input.decryption, recipients: Object.freeze([...input.decryption.recipients]) });
  const profile: JwtProfile = Object.freeze({
    ...input,
    verification,
    decryption,
    name,
    version: 1,
    skew: BigInt(skew),
    maximumLifetime: BigInt(input.maximumLifetime ?? 3600),
    // Namespaces replay records by the identifiers that define the token's
    // context, so a `jti` consumed for one issuer or audience cannot suppress a
    // distinct token that legitimately reuses that identifier. JSON encoding of
    // an array keeps the parts unambiguous where concatenation would let one
    // component's content imitate a boundary.
    replayNamespace: JSON.stringify([name, 1, input.issuer, input.audience]),
  });
  PROFILES.add(profile);
  return { ok: true, profile };
}

export function isJwtProfile(value: JwtProfile): boolean {
  return PROFILES.has(value);
}

function validMediaType(value: string): boolean {
  return utf8Length(value) > 0 && normalizeMediaType(value) !== undefined;
}
