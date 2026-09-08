import { encodeBase64url } from '../internal/encoding/base64url.ts';
import { encodeUtf8 } from '../internal/encoding/utf8.ts';
import { systemRandom } from '../internal/crypto/random.ts';
import type { RandomSource } from '../internal/crypto/backend.ts';
import { normalizeMediaType } from '../internal/headers/media-type.ts';
import { parseJson } from '../internal/json/parse.ts';
import { encryptCompact } from '../jwe/compact.ts';
import { signCompact } from '../jws/sign.ts';
import { sameKeyMaterial } from '../key/identity.ts';
import { checkLimits } from '../policy/limits.ts';
import { validateClaims } from './claims.ts';
import { isJwtProfile } from './profile.ts';
import type { CreateJwtOptions, CreateJwtResult, JwtFailure } from './types.ts';

function fail(reason: string): JwtFailure {
  return { ok: false, category: 'policy_violation', stage: 'configuration', reason };
}

export async function createJwt(options: CreateJwtOptions): Promise<CreateJwtResult> {
  return createJwtWithRandom(options, systemRandom);
}

/** Test seam kept outside the package entry point. */
export async function createJwtWithRandom(
  options: CreateJwtOptions,
  randomSource: RandomSource,
): Promise<CreateJwtResult> {
  const { profile, limits } = options;
  const limitDefect = checkLimits(limits);
  if (limitDefect !== undefined) {
    return fail(limitDefect);
  }
  if (!isJwtProfile(profile)) {
    return fail('invalid_jwt_profile');
  }
  if (normalizeMediaType(profile.type) === undefined) {
    return fail('expected_type_invalid');
  }
  if ((profile.chain === 'JWE -> JWS -> claims') !== (options.encryption !== undefined)) {
    return fail('creation_chain_mismatch');
  }
  // The signing key must be the one the profile verifies with, so a profile
  // cannot be used to mint tokens that its own validation would then reject.
  if (
    options.signing.key.algorithm !== profile.verification.key.algorithm ||
    !sameKeyMaterial(options.signing.key.identity, profile.verification.key.identity)
  ) {
    return fail('signing_key_not_bound_to_profile');
  }
  if (options.encryption !== undefined) {
    const trusted = profile.decryption!.recipients;
    if (
      options.encryption.recipients.length !== 1 ||
      trusted.length !== 1 ||
      !sameKeyMaterial(options.encryption.recipients[0]!.key.identity, trusted[0]!.key.identity) ||
      options.encryption.recipients[0]!.key.algorithm !== trusted[0]!.key.algorithm ||
      options.encryption.contentAlgorithm === undefined ||
      !profile.decryption!.contentPolicy.has(options.encryption.contentAlgorithm) ||
      !sameIdentifiers(options.encryption.keyPolicy.identifiers(), profile.decryption!.keyPolicy.identifiers()) ||
      !sameIdentifiers(options.encryption.contentPolicy.identifiers(), profile.decryption!.contentPolicy.identifiers())
    ) {
      return fail('encryption_key_not_bound_to_profile');
    }
  }

  let now: bigint;
  try {
    now = await profile.clock.now();
  } catch {
    return { ok: false, category: 'backend_failure', stage: 'configuration', reason: 'trusted_clock_unavailable' };
  }
  if (typeof now !== 'bigint' || now < 0n) {
    return { ok: false, category: 'backend_failure', stage: 'configuration', reason: 'trusted_clock_invalid' };
  }

  const claims: Record<string, unknown> = { ...options.claims };
  if (
    (profile.name === 'project-single-use-jwt-v1' || profile.name === 'oauth-at-jwt-v1') &&
    claims['jti'] === undefined
  ) {
    // 128 bits from a CSPRNG, so identifiers do not collide across issuers at
    // any practical volume. Generation fails closed rather than falling back to
    // a weaker source, since a predictable `jti` would undermine replay
    // detection for the profiles that require one.
    let random;
    try {
      random = randomSource.randomBytes(16);
    } catch {
      return { ok: false, category: 'backend_failure', stage: 'cryptographic', reason: 'randomness_unavailable' };
    }
    if (!random.ok || random.value.length !== 16) {
      return { ok: false, category: 'backend_failure', stage: 'cryptographic', reason: 'randomness_unavailable' };
    }
    claims['jti'] = encodeBase64url(random.value);
  }

  // The serialized bytes are validated and then signed unchanged, so what was
  // checked is exactly what the signature covers.
  let bytes: Uint8Array;
  try {
    bytes = encodeUtf8(stableJson(claims));
  } catch {
    return fail('claims_not_json_serializable');
  }
  // Issued tokens go through the same parser and claim validation as received
  // ones, so this side cannot mint a token its own verifier would reject.
  const parsed = parseJson(bytes, limits);
  if (!parsed.ok || parsed.value.kind !== 'object') {
    return fail('claims_invalid');
  }
  const checked = await validateClaims(parsed.value, profile, now, limits);
  if (!checked.ok) {
    return checked;
  }

  const signed = await signCompact(bytes, {
    policy: options.signing.policy,
    key: options.signing.key,
    limits,
    protectedHeader: { typ: profile.type },
    detached: false,
    unencoded: false,
  });
  if (!signed.ok) {
    return signed;
  }
  if (profile.chain === 'JWS -> claims') {
    return encodedTokenResult(signed.token, limits.jwtInput);
  }

  const encrypted = await encryptCompact(encodeUtf8(signed.token), {
    ...options.encryption!,
    limits,
    protectedHeader: { cty: 'JWT' },
  });
  return encrypted.ok ? encodedTokenResult(encrypted.token, limits.jwtInput) : encrypted;
}

function sameIdentifiers(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function encodedTokenResult(token: string, maximumBytes: number): CreateJwtResult {
  return encodeUtf8(token).length <= maximumBytes
    ? { ok: true, token }
    : { ok: false, category: 'resource_limit', stage: 'syntax', reason: 'jwt_input_too_large' };
}

/**
 * Serializes claims deterministically, so the same claim set always produces the
 * same octets regardless of the order the caller happened to build it in.
 *
 * `JSON.stringify` is not used for objects because it preserves insertion order
 * and silently drops `undefined` and functions; unsupported values throw here
 * instead, so a claim can never be omitted without the caller being told.
 */
function stableJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    // `NaN` and the infinities have no JSON form and would serialize as `null`,
    // turning a malformed claim into a valid-looking one.
    if (!Number.isFinite(value)) {
      throw new TypeError('non-finite number');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') {
    // Restricted to the range that survives a round trip through a JSON parser
    // using doubles, so a recipient reads back the value that was signed.
    if (value < 0n || value > 9_007_199_254_740_991n) {
      throw new TypeError('unsafe bigint');
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    // Members are ordered so that one claim set serializes to one byte string.
    // The comparison is locale-sensitive and therefore depends on the runtime's
    // ICU data, which only matters if these bytes are ever compared across
    // hosts; the signature covers whatever this host produced, so verification
    // is unaffected.
    // ponytail: locale-sensitive ordering, switch to code-unit comparison if
    // byte-identical output across runtimes is ever required.
    const entries = Object.entries(value as Record<string, unknown>).toSorted(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(',')}}`;
  }
  // Reached for `undefined`, functions, and symbols, which `JSON.stringify`
  // would drop from an object rather than reporting.
  throw new TypeError('not JSON');
}
