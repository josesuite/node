import type { ErrorCategory } from '../errors/codes.ts';
import { utf8Length } from '../internal/encoding/utf8.ts';
import type { JsonArray, JsonObject, JsonValue } from '../internal/json/types.ts';
import type { Limits } from '../policy/limits.ts';
import { numericDate } from './numeric-date.ts';
import type { ClaimsResult, JwtFailure, JwtProfile } from './types.ts';

function fail(reason: string, category: ErrorCategory = 'claim_validation_failure'): JwtFailure {
  return { ok: false, category, stage: 'claims_semantics', reason };
}

function requiredString(object: JsonObject, name: string): string | undefined {
  const value = object.members.get(name);
  return value?.kind === 'string' && value.value.length > 0 ? value.value : undefined;
}

/**
 * RFC 3986 absolute-URI syntax, checked against the original characters.
 *
 * Written out from the grammar rather than delegated to WHATWG `URL`, which
 * repairs its input: it percent-encodes a space, deletes a tab, and strips
 * trailing controls, so an invalid value parses successfully and the repaired
 * form differs from the bytes compared later. StringOrURI comparison must stay
 * exact, so the received characters are the ones validated.
 *
 * `hier-part` and `query` are checked as a character-class set rather than by
 * decomposing authority/path, which is enough to exclude the characters the
 * grammar forbids.
 */
const ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.-]*:(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~!$&'()*+,;=:@/?[\]])*$/;

/**
 * StringOrURI: a value containing `:` must be a valid URI, and one without it is
 * an opaque string. The colon is what distinguishes the two, so a bare string is
 * accepted as-is rather than being forced through URI parsing.
 */
function validStringOrUri(value: string): boolean {
  if (!value.includes(':')) {
    return true;
  }
  return ABSOLUTE_URI.test(value);
}

/**
 * Normalizes `aud`, which is either one string or an array of them, into a list.
 *
 * A duplicate entry is rejected rather than collapsed: it makes the audience set
 * ambiguous, and silently deduplicating would accept a token whose encoding
 * misrepresents how many distinct audiences were intended.
 */
function audience(value: JsonValue | undefined): readonly string[] | undefined {
  const strings = value?.kind === 'string' ? [value.value] : value?.kind === 'array' ? arrayStrings(value) : undefined;
  if (
    strings === undefined ||
    strings.length === 0 ||
    strings.some((item) => item.length === 0 || !validStringOrUri(item))
  ) {
    return undefined;
  }
  return new Set(strings).size === strings.length ? Object.freeze(strings) : undefined;
}

function arrayStrings(value: JsonArray): string[] | undefined {
  const result: string[] = [];
  for (const item of value.elements) {
    if (item.kind !== 'string') {
      return undefined;
    }
    result.push(item.value);
  }
  return result;
}

/**
 * Validates the claim set against a profile at a fixed instant.
 *
 * `now` is passed in rather than read here so that every comparison in one
 * validation uses a single instant; sampling the clock per claim could otherwise
 * accept a token that expires midway through.
 *
 * Order matters: every claim is type-checked before any is interpreted, so a
 * malformed value is reported as such rather than as a semantic failure like
 * expiry.
 */
export async function validateClaims(
  object: JsonObject,
  profile: JwtProfile,
  now: bigint,
  limits: Limits,
): Promise<ClaimsResult> {
  // Type validity is checked for these even when absent-and-optional, so a
  // present but malformed claim is never silently ignored as missing.
  for (const name of ['iss', 'sub', 'jti'] as const) {
    const present = object.members.get(name);
    if (present !== undefined && (present.kind !== 'string' || present.value.length === 0)) {
      return fail(`${name}_invalid`);
    }
  }
  for (const name of ['exp', 'nbf', 'iat'] as const) {
    const present = object.members.get(name);
    if (present !== undefined && numericDate(present) === undefined) {
      return fail(`${name}_invalid`);
    }
  }

  const issuer = requiredString(object, 'iss');
  const subject = requiredString(object, 'sub');
  const audiences = audience(object.members.get('aud'));
  const expiration = numericDate(object.members.get('exp'));
  const issuedAt = numericDate(object.members.get('iat'));
  if (
    issuer === undefined ||
    subject === undefined ||
    audiences === undefined ||
    expiration === undefined ||
    issuedAt === undefined
  ) {
    return fail('required_claim_missing_or_invalid');
  }
  if (!validStringOrUri(issuer) || !validStringOrUri(subject)) {
    return fail('string_or_uri_invalid');
  }
  if (
    utf8Length(issuer) > limits.identifier ||
    utf8Length(subject) > limits.identifier ||
    audiences.some((value) => utf8Length(value) > limits.identifier)
  ) {
    return { ok: false, category: 'resource_limit', stage: 'claims_semantics', reason: 'identifier_too_long' };
  }

  const jwtId = requiredString(object, 'jti');
  // The size cap applies wherever the claim is present, not only where the
  // profile requires it: an optional `jti` is still attacker-supplied and is
  // still carried into replay state.
  if (jwtId !== undefined && utf8Length(jwtId) > limits.jti) {
    return { ok: false, category: 'resource_limit', stage: 'claims_semantics', reason: 'jti_too_long' };
  }
  if ((profile.name === 'project-single-use-jwt-v1' || profile.name === 'oauth-at-jwt-v1') && jwtId === undefined) {
    return fail('jti_missing_or_invalid');
  }
  if (profile.name === 'oauth-at-jwt-v1') {
    const clientId = requiredString(object, 'client_id');
    if (clientId === undefined) {
      return fail('client_id_missing_or_invalid');
    }
    if (utf8Length(clientId) > limits.identifier) {
      return { ok: false, category: 'resource_limit', stage: 'claims_semantics', reason: 'client_id_too_long' };
    }
  }
  if (issuer !== profile.issuer) {
    return fail('issuer_mismatch', 'issuer_mismatch');
  }
  let accepted: boolean;
  try {
    accepted = await profile.subject(issuer, subject);
  } catch {
    return {
      ok: false,
      category: 'backend_failure',
      stage: 'context_admission',
      reason: 'subject_validator_failed',
    };
  }
  if (!accepted) {
    return fail('subject_rejected');
  }
  if (!audiences.includes(profile.audience)) {
    return fail('audience_mismatch', 'audience_mismatch');
  }

  // Skew is applied in whichever direction widens the acceptance window, since
  // it compensates for clock disagreement between issuer and verifier. Expiry
  // uses `>=` so a token is invalid at exactly its expiration instant.
  const skew = profile.skew;
  if (now >= expiration + skew) {
    return fail('token_expired', 'expired_token');
  }
  const notBefore = numericDate(object.members.get('nbf'));
  if (notBefore !== undefined && now + skew < notBefore) {
    return fail('token_not_yet_valid', 'token_not_yet_valid');
  }
  // A validity window that never opens describes a token that could not be used
  // at any instant, which is a malformed claim set rather than a timing outcome.
  if (notBefore !== undefined && notBefore >= expiration) {
    return fail('nbf_not_before_exp');
  }
  if (issuedAt > now + skew || issuedAt > expiration) {
    return fail('iat_invalid');
  }
  // The issuer's stated lifetime is capped independently of expiry, so a token
  // minted with a far-future `exp` is refused even while unexpired.
  const lifetime = expiration - issuedAt;
  if (lifetime < 0n || lifetime > profile.maximumLifetime) {
    return fail('lifetime_invalid');
  }
  // Bounds actual age as well as the claimed lifetime, so a reissued `exp`
  // cannot extend a token indefinitely beyond when it was minted.
  if (now - issuedAt > profile.maximumLifetime + skew) {
    return fail('token_too_old');
  }

  // Remaining profile-specific claims are checked after the ordered issuer,
  // subject, audience and time semantics, so a token failing both reports the
  // earlier stage as its primary failure.
  if (profile.name === 'oauth-at-jwt-v1') {
    const scope = object.members.get('scope');
    if (scope !== undefined && (scope.kind !== 'string' || !validScope(scope.value))) {
      return fail('scope_invalid');
    }
  }

  return { ok: true, value: { object, issuer, subject, audience: audiences, expiration, issuedAt, notBefore, jwtId } };
}

/**
 * OAuth scope: space-delimited tokens drawn from the printable ASCII range
 * excluding `"` and `\`. Empty items are rejected, so leading, trailing, or
 * repeated separators make the whole value invalid rather than being skipped.
 */
function validScope(value: string): boolean {
  return (
    value.length > 0 && value.split(' ').every((item) => item.length > 0 && /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(item))
  );
}
