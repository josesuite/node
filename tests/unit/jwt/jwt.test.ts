import { describe, expect, test } from 'bun:test';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { createJwt, createJwtWithRandom } from '../../../src/jwt/create.ts';
import { createJwtProfile } from '../../../src/jwt/profile.ts';
import type { ReplayStore } from '../../../src/jwt/types.ts';
import { validateJwt } from '../../../src/jwt/validate.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
import { signCompact } from '../../../src/jws/sign.ts';
import { importKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';

function jsonObject(value: Record<string, unknown>): JsonObject {
  const parsed = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!parsed.ok || parsed.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return parsed.value;
}

function keys() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signing = importKey(jsonObject(pair.privateKey.export({ format: 'jwk' }) as Record<string, unknown>), {
    algorithm: 'ES256',
    operation: 'sign',
  });
  const verification = importKey(jsonObject(pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>), {
    algorithm: 'ES256',
    operation: 'verify',
  });
  if (!signing.ok || !verification.ok) {
    throw new Error('key import failed');
  }
  return { signing: signing.key, verification: verification.key };
}

function rsaKeys() {
  const pair = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const signing = importKey(jsonObject(pair.privateKey.export({ format: 'jwk' }) as Record<string, unknown>), {
    algorithm: 'RS256',
    operation: 'sign',
  });
  const verification = importKey(jsonObject(pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>), {
    algorithm: 'RS256',
    operation: 'verify',
  });
  if (!signing.ok || !verification.ok) {
    throw new Error('RSA key import failed');
  }
  return { signing: signing.key, verification: verification.key };
}

function encryptionKeys() {
  const material = { kty: 'oct', k: Buffer.alloc(32, 7).toString('base64url') };
  const encryption = importKey(jsonObject(material), {
    algorithm: 'A256KW',
    operation: 'wrapKey',
    contentAlgorithms: ['A128GCM'],
  });
  const decryption = importKey(jsonObject(material), {
    algorithm: 'A256KW',
    operation: 'unwrapKey',
    contentAlgorithms: ['A128GCM'],
  });
  if (!encryption.ok || !decryption.ok) {
    throw new Error('encryption key import failed');
  }
  return { encryption: encryption.key, decryption: decryption.key };
}

function allocator(): NonceAllocator {
  let counter = 0n;
  return {
    reserve(): Promise<NonceResult> {
      counter += 1n;
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(1, counter)! } });
    },
  };
}

function profile(
  name: 'project-jwt-v1' | 'project-single-use-jwt-v1',
  replayStore?: ReplayStore,
  clock = { now: () => 1_000n },
) {
  const pair = keys();
  const result = createJwtProfile({
    name,
    issuer: 'https://issuer.example',
    audience: 'api',
    type: 'project+jwt',
    chain: 'JWS -> claims',
    clock,
    subject: () => true,
    replayStore,
    verification: {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      key: pair.verification,
      principalId: 'https://issuer.example',
    },
  });
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return { profile: result.profile, signing: pair.signing };
}

function oauthProfile() {
  const pair = rsaKeys();
  const result = createJwtProfile({
    name: 'oauth-at-jwt-v1',
    issuer: 'https://issuer.example',
    audience: 'api',
    type: 'at+jwt',
    chain: 'JWS -> claims',
    maximumLifetime: 600,
    clock: { now: () => 1_000n },
    subject: () => true,
    verification: {
      policy: AlgorithmPolicy.create('jws', ['RS256'], 'receive'),
      key: pair.verification,
      principalId: 'https://issuer.example',
    },
  });
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return { profile: result.profile, signing: pair.signing };
}

const CLAIMS = { iss: 'https://issuer.example', sub: 'alice', aud: 'api', iat: 900, exp: 1_100 };

async function signed(fixture: ReturnType<typeof profile>, claims: string, type = 'project+jwt') {
  const result = await signCompact(new TextEncoder().encode(claims), {
    policy: AlgorithmPolicy.create('jws', [fixture.signing.algorithm], 'create'),
    key: fixture.signing,
    limits: LIMITS_V1,
    protectedHeader: { typ: type },
  });
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return result.token;
}

describe('JWT profiles', () => {
  test('creation rejects invalid clocks, short randomness, and oversized final tokens', async () => {
    const invalidClock = profile('project-jwt-v1', undefined, { now: () => -1n });
    const clockResult = await createJwt({
      profile: invalidClock.profile,
      limits: LIMITS_V1,
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: invalidClock.signing },
    });
    expect(clockResult.ok).toBe(false);
    if (!clockResult.ok) {
      expect(clockResult.reason).toBe('trusted_clock_invalid');
    }

    const oauth = oauthProfile();
    const shortRandom = await createJwtWithRandom(
      {
        profile: oauth.profile,
        limits: LIMITS_V1,
        claims: { ...CLAIMS, client_id: 'client-123' },
        signing: { policy: AlgorithmPolicy.create('jws', ['RS256'], 'create'), key: oauth.signing },
      },
      { randomBytes: () => ({ ok: true, value: new Uint8Array(15) }) },
    );
    expect(shortRandom.ok).toBe(false);
    if (!shortRandom.ok) {
      expect(shortRandom.reason).toBe('randomness_unavailable');
    }

    const normal = profile('project-jwt-v1');
    const oversized = await createJwt({
      profile: normal.profile,
      limits: lowerLimits({ jwtInput: 10 }),
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: normal.signing },
    });
    expect(oversized.ok).toBe(false);
    if (!oversized.ok) {
      expect(oversized.reason).toBe('jwt_input_too_large');
    }
  });
  test('creates and validates project-jwt-v1', async () => {
    const fixture = profile('project-jwt-v1');
    const created = await createJwt({
      profile: fixture.profile,
      limits: LIMITS_V1,
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: fixture.signing },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const validated = await validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 });
    expect(validated.ok).toBe(true);
    if (validated.ok) {
      expect(validated.value.validatedAt).toBe(1_000n);
      expect(validated.value.issuer).toBe('https://issuer.example');
    }
  });

  test('rejects expiration equality at the claims stage', async () => {
    const fixture = profile('project-jwt-v1');
    const created = await createJwt({
      profile: fixture.profile,
      limits: LIMITS_V1,
      claims: { ...CLAIMS, exp: 1_000 },
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: fixture.signing },
    });
    expect(created.ok).toBe(false);
    if (!created.ok) {
      expect(created.category).toBe('expired_token');
    }
  });

  test('admits exactly one concurrent single-use validation', async () => {
    const used = new Set<string>();
    const replayStore: ReplayStore = {
      async admit(namespace, identifier) {
        const key = `${namespace}:${identifier}`;
        if (used.has(key)) {
          return 'already_present';
        }
        used.add(key);
        return 'admitted';
      },
    };
    const fixture = profile('project-single-use-jwt-v1', replayStore);
    const created = await createJwt({
      profile: fixture.profile,
      limits: LIMITS_V1,
      claims: { ...CLAIMS, jti: 'once' },
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: fixture.signing },
    });
    if (!created.ok) {
      throw new Error(created.reason);
    }

    const results = await Promise.all([
      validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 }),
      validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 }),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    const rejected = results.find((result) => !result.ok);
    expect(rejected?.ok).toBe(false);
    if (rejected && !rejected.ok) {
      expect(rejected.category).toBe('replay_detected');
    }
  });

  test('creates and validates the declared JWE to JWS chain with one clock read', async () => {
    const signing = keys();
    const encryption = encryptionKeys();
    let clockReads = 0;
    const configured = createJwtProfile({
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWE -> JWS -> claims',
      clock: {
        now: () => {
          clockReads += 1;
          return 1_000n;
        },
      },
      subject: () => true,
      verification: {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
        key: signing.verification,
        principalId: 'https://issuer.example',
      },
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: encryption.decryption }],
        principalId: 'recipient',
      },
    });
    if (!configured.ok) {
      throw new Error(configured.reason);
    }
    const created = await createJwt({
      profile: configured.profile,
      limits: LIMITS_V1,
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: signing.signing },
      encryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: [{ key: encryption.encryption }],
        random: systemRandom,
        nonceAllocator: allocator(),
      },
    });
    if (!created.ok) {
      throw new Error(created.reason);
    }
    clockReads = 0;
    const validated = await validateJwt(created.token, { profile: configured.profile, limits: LIMITS_V1 });
    expect(validated.ok).toBe(true);
    expect(clockReads).toBe(1);

    const exhausted = await validateJwt(created.token, {
      profile: configured.profile,
      limits: lowerLimits({ cryptographicAttempts: 2 }),
    });
    expect(exhausted.ok).toBe(false);
    if (!exhausted.ok) {
      expect(exhausted.category).toBe('resource_limit');
    }
  });

  test('rejects unsupported formats and wrong purpose types', async () => {
    const fixture = profile('project-jwt-v1');
    for (const token of ['a.b', 'a.b.c.d', 'a.b.c~disclosure', '{}']) {
      const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.stage).toBe('syntax');
      }
    }
    const wrongType = await validateJwt(await signed(fixture, JSON.stringify(CLAIMS), 'other+jwt'), {
      profile: fixture.profile,
      limits: LIMITS_V1,
    });
    expect(wrongType.ok).toBe(false);
    if (!wrongType.ok) {
      expect(wrongType.category).toBe('token_type_mismatch');
    }
  });

  test('projects NumericDate only for top-level registered claims', async () => {
    const fixture = profile('project-jwt-v1');
    // `exp` inside a custom claim is an ordinary JSON number that never passed
    // NumericDate validation. Converting it would throw on these lexemes, so
    // the payload is written literally to preserve the exponent form that
    // `JSON.stringify` would normalize away.
    const claims =
      `{"iss":"https://issuer.example","sub":"alice","aud":"api","iat":900,"exp":1100,` +
      `"meta":{"exp":1.5,"nbf":1e3,"iat":0.25},"tags":[{"exp":2.5}]}`;

    const result = await validateJwt(await signed(fixture, claims), {
      profile: fixture.profile,
      limits: LIMITS_V1,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      // The registered claims project to bigint; nested ones keep their lexeme.
      expect(result.value.claims['exp']).toBe(1_100n);
      const meta = result.value.claims['meta'] as Record<string, unknown>;
      expect(meta['exp']).toEqual({ lexeme: '1.5' });
      expect(meta['nbf']).toEqual({ lexeme: '1e3' });
    }
  });

  test('reports the missing claim before the token type for a multiply-invalid token', async () => {
    const fixture = profile('project-jwt-v1');
    // Both defects at once: empty claims and the wrong `typ`. The claim schema
    // pass precedes the type check, so the missing claim is the primary failure.
    const result = await validateJwt(await signed(fixture, '{}', 'other+jwt'), {
      profile: fixture.profile,
      limits: LIMITS_V1,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('required_claim_missing_or_invalid');
      expect(result.category).not.toBe('token_type_mismatch');
    }
  });

  test('rejects StringOrURI values that are not valid URIs', async () => {
    const fixture = profile('project-jwt-v1');
    // A colon makes the value a URI, and it must be validated as received.
    // WHATWG `URL` would repair each of these and accept them.
    for (const sub of ['https://example.com/a b', 'https://example.com/a\tb', 'https://example.com/café']) {
      const result = await validateJwt(await signed(fixture, JSON.stringify({ ...CLAIMS, sub })), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('string_or_uri_invalid');
      }
    }
  });

  test('accepts opaque subjects and non-HTTP URI schemes', async () => {
    const fixture = profile('project-jwt-v1');
    // No colon is an opaque string; a colon requires valid URI syntax, which
    // these satisfy without being HTTP URLs.
    for (const sub of ['alice', 'urn:ietf:params:oauth:client-id:1', 'mailto:alice@example.com']) {
      const result = await validateJwt(await signed(fixture, JSON.stringify({ ...CLAIMS, sub })), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      expect(result.ok).toBe(true);
    }
  });

  test('rejects duplicate claims and non-object claims', async () => {
    const fixture = profile('project-jwt-v1');
    for (const claims of ['{"iss":"a","iss":"b"}', '[]', 'null']) {
      const result = await validateJwt(await signed(fixture, claims), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.stage).toBe('claims_syntax');
      }
    }
  });

  test('rejects every excluded NumericDate representation', async () => {
    const fixture = profile('project-jwt-v1');
    for (const bad of ['-1', '-0', '1.0', '1e3', '"1000"', '9007199254740992']) {
      const claims = `{"iss":"https://issuer.example","sub":"alice","aud":"api","iat":900,"exp":${bad}}`;
      const result = await validateJwt(await signed(fixture, claims), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe('claim_validation_failure');
      }
    }
  });

  test('applies expiration, not-before, lifetime, and age boundaries', async () => {
    const fixture = profile('project-jwt-v1');
    const cases = [
      [{ ...CLAIMS, exp: 1_000 }, 'expired_token'],
      [{ ...CLAIMS, nbf: 1_001 }, 'token_not_yet_valid'],
      [{ ...CLAIMS, iat: 1_001 }, 'claim_validation_failure'],
      [{ ...CLAIMS, iat: 0, exp: 3_601 }, 'claim_validation_failure'],
    ] as const;
    for (const [claims, category] of cases) {
      const result = await validateJwt(await signed(fixture, JSON.stringify(claims)), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe(category);
      }
    }
  });

  test('does not call replay admission before all claims pass', async () => {
    let calls = 0;
    const fixture = profile('project-single-use-jwt-v1', {
      async admit() {
        calls += 1;
        return 'admitted';
      },
    });
    const token = await signed(fixture, JSON.stringify({ ...CLAIMS, aud: 'other', jti: 'unused' }));
    const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
    expect(result.ok).toBe(false);
    expect(calls).toBe(0);
  });

  test('fails closed when replay storage is unavailable and retains through exp plus skew', async () => {
    let retainUntil = 0n;
    const unavailable = profile('project-single-use-jwt-v1', {
      async admit(_namespace, _identifier, retain) {
        retainUntil = retain;
        return 'unavailable';
      },
    });
    const result = await validateJwt(await signed(unavailable, JSON.stringify({ ...CLAIMS, jti: 'once' })), {
      profile: unavailable.profile,
      limits: LIMITS_V1,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('backend_failure');
    }
    expect(retainUntil).toBe(1_100n);
  });

  test('returns a deeply immutable claims view without converting unknown decimals', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify({ ...CLAIMS, extension: { ratio: 1.5 } }));
    const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(Object.isFrozen(result.value.claims)).toBe(true);
      expect(Object.isFrozen(result.value.claims['extension'])).toBe(true);
      expect(result.value.claims['exp']).toBe(1_100n);
    }
  });
});

describe('OAuth access-token JWT profile', () => {
  const claims = { ...CLAIMS, client_id: 'client-123', jti: 'token-123', scope: 'read write' };

  test('creates and validates the RFC 9068 profile', async () => {
    const fixture = oauthProfile();
    const created = await createJwt({
      profile: fixture.profile,
      limits: LIMITS_V1,
      claims,
      signing: { policy: AlgorithmPolicy.create('jws', ['RS256'], 'create'), key: fixture.signing },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const validated = await validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 });
    expect(validated.ok).toBe(true);
    if (validated.ok) {
      expect(validated.value.profile).toBe('oauth-at-jwt-v1');
      expect(validated.value.claims['client_id']).toBe('client-123');
    }
  });

  test('requires the fixed type, an explicit lifetime, and RS256 support', () => {
    const pair = rsaKeys();
    const base = {
      name: 'oauth-at-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'at+jwt',
      chain: 'JWS -> claims' as const,
      maximumLifetime: 600,
      clock: { now: () => 1_000n },
      subject: () => true,
      verification: {
        policy: AlgorithmPolicy.create('jws', ['RS256'], 'receive'),
        key: pair.verification,
        principalId: 'https://issuer.example',
      },
    };

    expect(createJwtProfile({ ...base, type: 'application/other+jwt' }).ok).toBe(false);
    expect(createJwtProfile({ ...base, maximumLifetime: undefined }).ok).toBe(false);
    expect(
      createJwtProfile({
        ...base,
        verification: { ...base.verification, policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive') },
      }).ok,
    ).toBe(false);
  });

  test('requires client_id and jti and validates scope syntax', async () => {
    const fixture = oauthProfile();
    for (const invalid of [
      { ...claims, client_id: undefined },
      { ...claims, jti: undefined },
      { ...claims, scope: 'read  write' },
      { ...claims, scope: ['read'] },
    ]) {
      const token = await signed(fixture, JSON.stringify(invalid), 'APPLICATION/AT+JWT');
      const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.stage).toBe('claims_semantics');
      }
    }
  });

  test('generates a 128-bit jti when creating a token', async () => {
    const fixture = oauthProfile();
    const created = await createJwt({
      profile: fixture.profile,
      limits: LIMITS_V1,
      claims: { ...CLAIMS, client_id: 'client-123' },
      signing: { policy: AlgorithmPolicy.create('jws', ['RS256'], 'create'), key: fixture.signing },
    });
    if (!created.ok) {
      throw new Error(created.reason);
    }
    const validated = await validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 });
    expect(validated.ok).toBe(true);
    if (validated.ok) {
      expect(Buffer.from(validated.value.claims['jti'] as string, 'base64url')).toHaveLength(16);
    }
  });
});

describe('claim size limits', () => {
  test('bounds an optional jti in a profile that does not require one', async () => {
    // The cap applies wherever the claim appears, not only where the profile
    // demands it: an optional `jti` is still attacker-supplied and is still
    // carried into replay state.
    const fixture = profile('project-jwt-v1');
    const oversized = 'a'.repeat(LIMITS_V1.jti + 1);
    const token = await signed(fixture, JSON.stringify({ ...CLAIMS, jti: oversized }));

    const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
      expect(result.reason).toBe('jti_too_long');
    }
  });

  test('accepts an optional jti at exactly the limit', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify({ ...CLAIMS, jti: 'a'.repeat(LIMITS_V1.jti) }));

    expect((await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 })).ok).toBe(true);
  });
});
