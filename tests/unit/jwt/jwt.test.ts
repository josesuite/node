import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { createJwt, createJwtWithRandom } from '../../../src/jwt/create.ts';
import { createJwtProfile, isJwtProfile } from '../../../src/jwt/profile.ts';
import type { JwtProfileInput, ReplayStore } from '../../../src/jwt/types.ts';
import { validateJwt } from '../../../src/jwt/validate.ts';
import { encryptCompact } from '../../../src/jwe/compact.ts';
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

function encryptionKeys(fill = 7) {
  const material = { kty: 'oct', k: Buffer.alloc(32, fill).toString('base64url') };
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
    assert.strictEqual(clockResult.ok, false);
    if (!clockResult.ok) {
      assert.strictEqual(clockResult.reason, 'trusted_clock_invalid');
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
    assert.strictEqual(shortRandom.ok, false);
    if (!shortRandom.ok) {
      assert.strictEqual(shortRandom.reason, 'randomness_unavailable');
    }

    const normal = profile('project-jwt-v1');
    const oversized = await createJwt({
      profile: normal.profile,
      limits: lowerLimits({ jwtInput: 10 }),
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: normal.signing },
    });
    assert.strictEqual(oversized.ok, false);
    if (!oversized.ok) {
      assert.strictEqual(oversized.reason, 'jwt_input_too_large');
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
    assert.strictEqual(created.ok, true);
    if (!created.ok) {
      return;
    }

    const validated = await validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 });
    assert.strictEqual(validated.ok, true);
    if (validated.ok) {
      assert.strictEqual(validated.value.validatedAt, 1_000n);
      assert.strictEqual(validated.value.issuer, 'https://issuer.example');
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
    assert.strictEqual(created.ok, false);
    if (!created.ok) {
      assert.strictEqual(created.category, 'expired_token');
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
    assert.strictEqual(results.filter((result) => result.ok).length, 1);
    const rejected = results.find((result) => !result.ok);
    assert.strictEqual(rejected?.ok, false);
    if (rejected && !rejected.ok) {
      assert.strictEqual(rejected.category, 'replay_detected');
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
    const encryptionOptions = {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: encryption.encryption }],
      random: systemRandom,
      nonceAllocator: allocator(),
    };
    const created = await createJwt({
      profile: configured.profile,
      limits: LIMITS_V1,
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: signing.signing },
      encryption: encryptionOptions,
    });
    if (!created.ok) {
      throw new Error(created.reason);
    }
    for (const recipients of [[], [{ key: encryptionKeys(8).encryption }]]) {
      const rejected = await createJwt({
        profile: configured.profile,
        limits: LIMITS_V1,
        claims: CLAIMS,
        signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: signing.signing },
        encryption: { ...encryptionOptions, recipients },
      });
      assert.strictEqual(rejected.ok, false);
      if (!rejected.ok) {
        assert.strictEqual(rejected.reason, 'encryption_key_not_bound_to_profile');
      }
    }

    clockReads = 0;
    const validated = await validateJwt(created.token, { profile: configured.profile, limits: LIMITS_V1 });
    assert.strictEqual(validated.ok, true);
    assert.strictEqual(clockReads, 1);

    const exhausted = await validateJwt(created.token, {
      profile: configured.profile,
      limits: lowerLimits({ cryptographicAttempts: 2 }),
    });
    assert.strictEqual(exhausted.ok, false);
    if (!exhausted.ok) {
      assert.strictEqual(exhausted.category, 'resource_limit');
    }
  });

  test('rejects unsupported formats and wrong purpose types', async () => {
    const fixture = profile('project-jwt-v1');
    for (const token of ['a.b', 'a.b.c.d', 'a.b.c~disclosure', '{}']) {
      const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.stage, 'syntax');
      }
    }
    const wrongType = await validateJwt(await signed(fixture, JSON.stringify(CLAIMS), 'other+jwt'), {
      profile: fixture.profile,
      limits: LIMITS_V1,
    });
    assert.strictEqual(wrongType.ok, false);
    if (!wrongType.ok) {
      assert.strictEqual(wrongType.category, 'token_type_mismatch');
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
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      // The registered claims project to bigint; nested ones keep their lexeme.
      assert.strictEqual(result.value.claims['exp'], 1_100n);
      const meta = result.value.claims['meta'] as Record<string, unknown>;
      assert.deepStrictEqual(meta['exp'], { lexeme: '1.5' });
      assert.deepStrictEqual(meta['nbf'], { lexeme: '1e3' });
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
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'required_claim_missing_or_invalid');
      assert.notStrictEqual(result.category, 'token_type_mismatch');
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
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'string_or_uri_invalid');
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
      assert.strictEqual(result.ok, true);
    }
  });

  test('rejects duplicate claims and non-object claims', async () => {
    const fixture = profile('project-jwt-v1');
    for (const claims of ['{"iss":"a","iss":"b"}', '[]', 'null']) {
      const result = await validateJwt(await signed(fixture, claims), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.stage, 'claims_syntax');
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
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'claim_validation_failure');
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
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, category);
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
    assert.strictEqual(result.ok, false);
    assert.strictEqual(calls, 0);
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
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
    }
    assert.strictEqual(retainUntil, 1_100n);
  });

  test('returns a deeply immutable claims view without converting unknown decimals', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify({ ...CLAIMS, extension: { ratio: 1.5 } }));
    const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(Object.isFrozen(result.value.claims), true);
      assert.strictEqual(Object.isFrozen(result.value.claims['extension']), true);
      assert.strictEqual(result.value.claims['exp'], 1_100n);
    }
  });
});

describe('nested JWE to JWS chain', () => {
  function nested() {
    const signing = keys();
    const encryption = encryptionKeys();
    const configured = createJwtProfile({
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWE -> JWS -> claims',
      clock: { now: () => 1_000n },
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
    return { profile: configured.profile, signing, encryption };
  }

  /** Wraps arbitrary plaintext in the outer JWE, so the inner layer can be malformed on purpose. */
  async function wrap(
    fixture: ReturnType<typeof nested>,
    plaintext: Uint8Array,
    protectedHeader: Readonly<Record<string, string | boolean | string[]>> = { cty: 'JWT' },
  ) {
    const result = await encryptCompact(plaintext, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: fixture.encryption.encryption }],
      random: systemRandom,
      nonceAllocator: allocator(),
      limits: LIMITS_V1,
      protectedHeader,
    });
    if (!result.ok) {
      throw new Error(result.reason);
    }
    return result.token;
  }

  test('requires the nested content type to be present, protected, and application/jwt', async () => {
    // Inferring the nested type from the plaintext's shape would let the sender
    // decide how their own bytes are interpreted.
    const fixture = nested();
    const inner = new TextEncoder().encode('unused');

    for (const header of [{}, { cty: 'application/json' }, { cty: 'not a media type' }]) {
      const token = await wrap(fixture, inner, header);
      const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.stage, 'nested_layer');
        assert.strictEqual(result.category, 'token_type_mismatch');
        assert.strictEqual(result.reason, 'nested_cty_mismatch');
      }
    }
  });

  test('rejects a nested layer that is not valid UTF-8', async () => {
    // Fatal decoding rather than replacement characters: substituting would
    // alter the very token about to be verified.
    const fixture = nested();
    const token = await wrap(fixture, new Uint8Array([0xff, 0xfe, 0xfd]));

    const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'nested_layer');
      assert.strictEqual(result.category, 'invalid_encoding');
      assert.strictEqual(result.reason, 'inner_jwt_invalid_utf8');
    }
  });

  test('requires the nested layer to be a compact JWS', async () => {
    const fixture = nested();

    for (const inner of ['a.b', 'a.b.c.d.e', 'a.b.c~disclosure', '{}']) {
      const token = await wrap(fixture, new TextEncoder().encode(inner));
      const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.stage, 'nested_layer');
        assert.strictEqual(result.reason, 'inner_layer_must_be_compact_jws');
      }
    }
  });

  test('rejects a signed token where the profile declares an encrypted chain', async () => {
    // The profile fixes the structure, so a bare JWS cannot stand in for the
    // JWE the configuration requires.
    const fixture = nested();
    const bare = await signCompact(new TextEncoder().encode(JSON.stringify(CLAIMS)), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: fixture.signing.signing,
      limits: LIMITS_V1,
      protectedHeader: { typ: 'project+jwt' },
    });
    if (!bare.ok) {
      throw new Error(bare.reason);
    }

    const result = await validateJwt(bare.token, { profile: fixture.profile, limits: LIMITS_V1 });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'jwt_chain_mismatch');
    }
  });

  test('requires a replicated outer claim to be protected and to agree exactly', async () => {
    // A replica is readable before decryption, so a disagreeing one would let
    // the two layers describe different tokens to different readers.
    const fixture = nested();
    const innerToken = await signCompact(new TextEncoder().encode(JSON.stringify(CLAIMS)), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: fixture.signing.signing,
      limits: LIMITS_V1,
      protectedHeader: { typ: 'project+jwt' },
    });
    if (!innerToken.ok) {
      throw new Error(innerToken.reason);
    }
    const inner = new TextEncoder().encode(innerToken.token);

    const agreeing = await wrap(fixture, inner, { cty: 'JWT', iss: CLAIMS.iss, aud: CLAIMS.aud });
    assert.strictEqual((await validateJwt(agreeing, { profile: fixture.profile, limits: LIMITS_V1 })).ok, true);

    for (const [name, replica] of [
      ['iss', 'https://attacker.example'],
      ['sub', 'mallory'],
      ['aud', 'other-api'],
    ] as const) {
      const token = await wrap(fixture, inner, { cty: 'JWT', [name]: replica });
      const result = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'claim_validation_failure');
        assert.strictEqual(result.reason, `replicated_${name}_mismatch`);
      }
    }
  });

  test('accepts a replicated audience in either permitted encoding', async () => {
    // A bare string and a single-element array denote the same audience, so the
    // replica must compare as a set rather than by JSON shape.
    const fixture = nested();
    const innerToken = await signCompact(new TextEncoder().encode(JSON.stringify({ ...CLAIMS, aud: ['api'] })), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: fixture.signing.signing,
      limits: LIMITS_V1,
      protectedHeader: { typ: 'project+jwt' },
    });
    if (!innerToken.ok) {
      throw new Error(innerToken.reason);
    }
    const inner = new TextEncoder().encode(innerToken.token);

    const token = await wrap(fixture, inner, { cty: 'JWT', aud: 'api' });

    assert.strictEqual((await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 })).ok, true);
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
    assert.strictEqual(created.ok, true);
    if (!created.ok) {
      return;
    }

    const validated = await validateJwt(created.token, { profile: fixture.profile, limits: LIMITS_V1 });
    assert.strictEqual(validated.ok, true);
    if (validated.ok) {
      assert.strictEqual(validated.value.profile, 'oauth-at-jwt-v1');
      assert.strictEqual(validated.value.claims['client_id'], 'client-123');
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

    assert.strictEqual(createJwtProfile({ ...base, type: 'application/other+jwt' }).ok, false);
    assert.strictEqual(createJwtProfile({ ...base, maximumLifetime: undefined }).ok, false);
    assert.strictEqual(
      createJwtProfile({
        ...base,
        verification: { ...base.verification, policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive') },
      }).ok,
      false,
    );
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
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.stage, 'claims_semantics');
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
    assert.strictEqual(validated.ok, true);
    if (validated.ok) {
      assert.strictEqual(Buffer.from(validated.value.claims['jti'] as string, 'base64url').length, 16);
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

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'jti_too_long');
    }
  });

  test('accepts an optional jti at exactly the limit', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify({ ...CLAIMS, jti: 'a'.repeat(LIMITS_V1.jti) }));

    assert.strictEqual((await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 })).ok, true);
  });
});

describe('audience matching across both permitted encodings', () => {
  async function validateWithAudience(fixture: ReturnType<typeof profile>, aud: unknown) {
    const claims = JSON.stringify({ ...CLAIMS, aud });
    return await validateJwt(await signed(fixture, claims), { profile: fixture.profile, limits: LIMITS_V1 });
  }

  test('accepts the configured audience as a bare string or as an array member', async () => {
    // RFC 7519 permits both spellings for the same meaning.
    const fixture = profile('project-jwt-v1');

    for (const aud of ['api', ['api'], ['api', 'other'], ['other', 'api']]) {
      assert.strictEqual((await validateWithAudience(fixture, aud)).ok, true);
    }
  });

  test('rejects an audience list that does not contain the configured value', async () => {
    const fixture = profile('project-jwt-v1');

    for (const aud of ['other', ['other'], ['other', 'third']]) {
      const result = await validateWithAudience(fixture, aud);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'audience_mismatch');
      }
    }
  });

  test('rejects malformed audience encodings before any mismatch is considered', async () => {
    // Structural defects, not the wrong recipient: an empty or duplicated list
    // makes the intended audience set ambiguous rather than merely unmatched.
    const fixture = profile('project-jwt-v1');

    for (const aud of [[], ['api', 'api'], ['api', 1], ['api', ''], [['api']], 1, null, {}]) {
      const result = await validateWithAudience(fixture, aud);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'claim_validation_failure');
        assert.strictEqual(result.reason, 'required_claim_missing_or_invalid');
      }
    }
  });
});

describe('JWT profile configuration', () => {
  function baseInput(): JwtProfileInput {
    const pair = keys();
    return {
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWS -> claims',
      clock: { now: () => 1_000n },
      subject: () => true,
      verification: {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
        key: pair.verification,
        principalId: 'https://issuer.example',
      },
    };
  }

  function rejects(reason: string, overrides: Partial<Record<keyof JwtProfileInput, unknown>>): void {
    const result = createJwtProfile({ ...baseInput(), ...overrides } as JwtProfileInput);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, reason);
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.stage, 'configuration');
    }
  }

  test('rejects unregistered profile names', () => {
    for (const name of ['', 'project-jwt-v2', 'PROJECT-JWT-V1', 'oauth-at-jwt']) {
      rejects('unsupported_jwt_profile', { name });
    }
  });

  test('requires a non-empty issuer and audience within the identifier limit', () => {
    rejects('expected_issuer_required', { issuer: '' });
    rejects('expected_audience_required', { audience: '' });

    const long = 'a'.repeat(LIMITS_V1.identifier + 1);
    rejects('expected_identifier_too_long', { issuer: long });
    rejects('expected_identifier_too_long', { audience: long });
  });

  test('requires an explicit media type that is not the generic application/jwt', () => {
    for (const type of ['', 'not a media type', 'application/']) {
      rejects('expected_type_invalid', { type });
    }
    // The generic type carries no distinguishing information, so it is refused
    // in both the bare and fully qualified spellings.
    rejects('expected_type_invalid', { type: 'JWT' });
    rejects('expected_type_invalid', { type: 'application/jwt' });
  });

  test('rejects an unknown chain and mismatched decryption policy', () => {
    rejects('invalid_jwt_chain', { chain: 'JWE -> claims' });
    rejects('decryption_policy_required', { chain: 'JWE -> JWS -> claims' });

    const encryption = encryptionKeys();
    rejects('unexpected_decryption_policy', {
      chain: 'JWS -> claims',
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: encryption.decryption }],
        principalId: 'recipient',
      },
    });
  });

  test('binds the verification principal to the issuer', () => {
    const input = baseInput();
    rejects('verification_principal_must_match_issuer', {
      verification: { ...input.verification, principalId: 'https://other.example' },
    });
  });

  test('refuses the unencoded payload mode for every JWT profile', () => {
    const input = baseInput();
    rejects('unencoded_payload_not_available_for_jwt', {
      verification: { ...input.verification, unencodedPayload: true },
    });
  });

  test('requires a subject validator function', () => {
    for (const subject of [undefined, null, true, 'alice', {}]) {
      rejects('subject_validator_required', { subject });
    }
  });

  test('caps clock skew at five minutes and rejects non-integral values', () => {
    for (const skew of [-1, 301, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
      rejects('invalid_clock_skew', { skew });
    }

    for (const skew of [undefined, 0, 300]) {
      const result = createJwtProfile({ ...baseInput(), skew } as JwtProfileInput);
      assert.strictEqual(result.ok, true);
      if (result.ok) {
        assert.strictEqual(result.profile.skew, BigInt(skew ?? 0));
      }
    }
  });

  test('requires a replay store for the single-use profile', () => {
    rejects('replay_store_required', { name: 'project-single-use-jwt-v1' });
  });

  test('requires RS256 support and a bounded lifetime for the OAuth profile', () => {
    const rsa = rsaKeys();
    const oauth = {
      name: 'oauth-at-jwt-v1',
      type: 'at+jwt',
      maximumLifetime: 600,
      verification: {
        policy: AlgorithmPolicy.create('jws', ['RS256'], 'receive'),
        key: rsa.verification,
        principalId: 'https://issuer.example',
      },
    };

    rejects('oauth_access_token_type_required', { ...oauth, type: 'project+jwt' });

    // The profile is defined over RS256, so neither a policy that omits it nor a
    // key bound to a different algorithm can satisfy it.
    const es = keys();
    rejects('oauth_rs256_support_required', {
      ...oauth,
      verification: { ...oauth.verification, policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive') },
    });
    rejects('oauth_rs256_support_required', {
      ...oauth,
      verification: { ...oauth.verification, key: es.verification },
    });

    rejects('oauth_maximum_lifetime_required', { ...oauth, maximumLifetime: undefined });
  });

  test('rejects a non-positive maximum lifetime and fixes it outside the OAuth profile', () => {
    const rsa = rsaKeys();
    const oauth = {
      name: 'oauth-at-jwt-v1',
      type: 'at+jwt',
      verification: {
        policy: AlgorithmPolicy.create('jws', ['RS256'], 'receive'),
        key: rsa.verification,
        principalId: 'https://issuer.example',
      },
    };

    for (const maximumLifetime of [0, -1, 1.5]) {
      rejects('invalid_maximum_lifetime', { ...oauth, maximumLifetime });
    }

    rejects('fixed_maximum_lifetime', { maximumLifetime: 600 });
  });

  test('brands only profiles built here, and namespaces replay by profile identity', () => {
    const result = createJwtProfile(baseInput());
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    assert.strictEqual(isJwtProfile(result.profile), true);
    assert.strictEqual(result.profile.maximumLifetime, 3_600n);
    assert.deepStrictEqual(JSON.parse(result.profile.replayNamespace), [
      'project-jwt-v1',
      1,
      'https://issuer.example',
      'api',
    ]);

    // A copy carries the same fields but not the brand, so validation cannot be
    // bypassed with a profile-shaped literal.
    assert.strictEqual(isJwtProfile({ ...result.profile }), false);
  });
});

describe('JWT creation binding and claim serialization', () => {
  function create(fixture: ReturnType<typeof profile>, overrides: Record<string, unknown> = {}) {
    return createJwt({
      profile: fixture.profile,
      limits: LIMITS_V1,
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: fixture.signing },
      ...overrides,
    } as Parameters<typeof createJwt>[0]);
  }

  test('rejects a profile that was not built by createJwtProfile', async () => {
    const fixture = profile('project-jwt-v1');
    const result = await create(fixture, { profile: { ...fixture.profile } });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'invalid_jwt_profile');
    }
  });

  test('rejects a signing key that the profile would not verify with', async () => {
    const fixture = profile('project-jwt-v1');
    // A different key pair of the same algorithm: the binding is on key
    // identity, not merely on the algorithm agreeing.
    const other = keys();
    const result = await create(fixture, {
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: other.signing },
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'signing_key_not_bound_to_profile');
    }
  });

  test('rejects a chain that disagrees with the presence of encryption options', async () => {
    const fixture = profile('project-jwt-v1');
    const encryption = encryptionKeys();
    const result = await create(fixture, {
      encryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
        contentAlgorithm: 'A128GCM',
        recipients: [{ principalId: 'recipient', key: encryption.encryption }],
        nonces: allocator(),
      },
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'creation_chain_mismatch');
    }
  });

  test('rejects claims that have no faithful JSON serialization', async () => {
    const fixture = profile('project-jwt-v1');

    // Each of these would be dropped or silently coerced by `JSON.stringify`,
    // producing a token whose claims differ from what the caller supplied.
    const unserializable: unknown[] = [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      -1n,
      9_007_199_254_740_992n,
      undefined,
      () => 1,
      Symbol('claim'),
    ];

    for (const value of unserializable) {
      const result = await create(fixture, { claims: { ...CLAIMS, extra: value } });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'claims_not_json_serializable');
      }
    }
  });

  test('serializes nested claims deterministically regardless of key order', async () => {
    const fixture = profile('project-jwt-v1');
    const extra = { list: [1, 'two', true, null], nested: { b: 2n, a: 'x' } };

    const first = await create(fixture, { claims: { ...CLAIMS, extra } });
    const second = await create(fixture, {
      claims: { ...CLAIMS, extra: { nested: { a: 'x', b: 2n }, list: [1, 'two', true, null] } },
    });

    assert.strictEqual(first.ok, true);
    assert.strictEqual(second.ok, true);
    if (first.ok && second.ok) {
      // Only the payload segment is compared: ECDSA signatures are randomized,
      // so equal claim bytes do not imply equal tokens.
      assert.strictEqual(first.token.split('.')[1], second.token.split('.')[1]);
    }
  });

  test('reports a clock that throws separately from one that returns an invalid value', async () => {
    const throwing = profile('project-jwt-v1', undefined, {
      now: () => {
        throw new Error('clock offline');
      },
    });
    const result = await create(throwing);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
      assert.strictEqual(result.reason, 'trusted_clock_unavailable');
    }

    const wrongType = profile('project-jwt-v1', undefined, { now: () => 1_000 as unknown as bigint });
    const typeResult = await create(wrongType);
    assert.strictEqual(typeResult.ok, false);
    if (!typeResult.ok) {
      assert.strictEqual(typeResult.reason, 'trusted_clock_invalid');
    }
  });

  test('fails closed when the randomness source throws while minting a jti', async () => {
    const store: ReplayStore = { admit: () => Promise.resolve('admitted') };
    const fixture = profile('project-single-use-jwt-v1', store);
    const result = await createJwtWithRandom(
      {
        profile: fixture.profile,
        limits: LIMITS_V1,
        claims: CLAIMS,
        signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: fixture.signing },
      },
      {
        randomBytes: () => {
          throw new Error('entropy unavailable');
        },
      },
    );
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
      assert.strictEqual(result.reason, 'randomness_unavailable');
    }
  });
});

function assertReason(result: Awaited<ReturnType<typeof validateJwt>>, reason: string): void {
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, reason);
  }
}

describe('JWT claim semantics', () => {
  async function validated(fixture: ReturnType<typeof profile>, claims: Record<string, unknown>) {
    return validateJwt(await signed(fixture, JSON.stringify(claims)), {
      profile: fixture.profile,
      limits: LIMITS_V1,
    });
  }

  test('rejects present-but-malformed string claims rather than treating them as absent', async () => {
    const fixture = profile('project-jwt-v1');

    for (const name of ['iss', 'sub', 'jti'] as const) {
      for (const value of ['', 1, null, true, [], {}]) {
        assertReason(await validated(fixture, { ...CLAIMS, [name]: value }), `${name}_invalid`);
      }
    }
  });

  test('rejects present-but-malformed temporal claims', async () => {
    const fixture = profile('project-jwt-v1');

    for (const name of ['exp', 'nbf', 'iat'] as const) {
      for (const value of ['900', null, true, [], {}, -1]) {
        assertReason(await validated(fixture, { ...CLAIMS, [name]: value }), `${name}_invalid`);
      }
    }
  });

  test('enforces identifier and jti size limits at the claims stage', async () => {
    const fixture = profile('project-jwt-v1');
    const long = `https://issuer.example/${'a'.repeat(LIMITS_V1.identifier)}`;

    for (const claims of [{ iss: long }, { sub: long }, { aud: long }]) {
      const result = await validated(fixture, { ...CLAIMS, ...claims });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'resource_limit');
        assert.strictEqual(result.reason, 'identifier_too_long');
      }
    }

    // The cap applies even though `jti` is optional for this profile.
    const oversizedJti = await validated(fixture, { ...CLAIMS, jti: 'j'.repeat(LIMITS_V1.jti + 1) });
    assert.strictEqual(oversizedJti.ok, false);
    if (!oversizedJti.ok) {
      assert.strictEqual(oversizedJti.category, 'resource_limit');
      assert.strictEqual(oversizedJti.reason, 'jti_too_long');
    }
  });

  test('reports a subject validator that throws as a backend failure, not a rejection', async () => {
    const pair = keys();
    const result = createJwtProfile({
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWS -> claims',
      clock: { now: () => 1_000n },
      subject: () => {
        throw new Error('directory unavailable');
      },
      verification: {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
        key: pair.verification,
        principalId: 'https://issuer.example',
      },
    });
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    const fixture = { profile: result.profile, signing: pair.signing };
    const validation = await validated(fixture, CLAIMS);
    assert.strictEqual(validation.ok, false);
    if (!validation.ok) {
      assert.strictEqual(validation.category, 'backend_failure');
      assert.strictEqual(validation.stage, 'context_admission');
      assert.strictEqual(validation.reason, 'subject_validator_failed');
    }
  });

  test('rejects a validity window that never opens', async () => {
    // Skew is what separates this from `token_not_yet_valid`: it must be wide
    // enough for `nbf` to pass the not-yet-valid check while still landing at or
    // after `exp`, which describes a token usable at no instant.
    const pair = keys();
    const created = createJwtProfile({
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWS -> claims',
      clock: { now: () => 1_000n },
      skew: 300,
      subject: () => true,
      verification: {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
        key: pair.verification,
        principalId: 'https://issuer.example',
      },
    });
    assert.strictEqual(created.ok, true);
    if (!created.ok) {
      return;
    }

    const fixture = { profile: created.profile, signing: pair.signing };
    assertReason(await validated(fixture, { ...CLAIMS, nbf: 1_100, exp: 1_100 }), 'nbf_not_before_exp');
  });

  test('rejects an issuance time in the future', async () => {
    const fixture = profile('project-jwt-v1');
    assertReason(await validated(fixture, { ...CLAIMS, iat: 1_001 }), 'iat_invalid');
  });

  test('caps the claimed lifetime and the token age independently of expiry', async () => {
    const fixture = profile('project-jwt-v1');
    // Unexpired at `now`, but the issuer claims a lifetime beyond the profile cap.
    assertReason(await validated(fixture, { ...CLAIMS, iat: 900, exp: 900 + 3_601 }), 'lifetime_invalid');

    // Within the claimed lifetime, but minted far enough in the past that the
    // token's actual age exceeds the cap.
    const old = profile('project-jwt-v1', undefined, { now: () => 10_000n });
    assertReason(await validated(old, { ...CLAIMS, iat: 1, exp: 20_000 }), 'lifetime_invalid');
  });

  test('requires client_id within limits for the OAuth profile', async () => {
    const fixture = oauthProfile();
    const claims = { ...CLAIMS, jti: 'token-1' };

    const oauthSigned = async (value: Record<string, unknown>) =>
      validateJwt(
        await (async () => {
          const result = await signCompact(new TextEncoder().encode(JSON.stringify(value)), {
            policy: AlgorithmPolicy.create('jws', ['RS256'], 'create'),
            key: fixture.signing,
            limits: LIMITS_V1,
            protectedHeader: { typ: 'at+jwt' },
          });
          if (!result.ok) {
            throw new Error(result.reason);
          }
          return result.token;
        })(),
        { profile: fixture.profile, limits: LIMITS_V1 },
      );

    assertReason(await oauthSigned(claims), 'client_id_missing_or_invalid');

    const tooLong = await oauthSigned({ ...claims, client_id: 'c'.repeat(LIMITS_V1.identifier + 1) });
    assert.strictEqual(tooLong.ok, false);
    if (!tooLong.ok) {
      assert.strictEqual(tooLong.category, 'resource_limit');
      assert.strictEqual(tooLong.reason, 'client_id_too_long');
    }
  });

  test('rejects an issuer the profile was not configured for', async () => {
    const fixture = profile('project-jwt-v1');
    const result = await validated(fixture, { ...CLAIMS, iss: 'https://attacker.example' });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'issuer_mismatch');
      assert.strictEqual(result.reason, 'issuer_mismatch');
    }
  });

  test('rejects a subject the validator declines', async () => {
    const pair = keys();
    const created = createJwtProfile({
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWS -> claims',
      clock: { now: () => 1_000n },
      subject: (_issuer, subject) => subject === 'bob',
      verification: {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
        key: pair.verification,
        principalId: 'https://issuer.example',
      },
    });
    assert.strictEqual(created.ok, true);
    if (!created.ok) {
      return;
    }

    const fixture = { profile: created.profile, signing: pair.signing };
    assertReason(await validated(fixture, CLAIMS), 'subject_rejected');
    assert.strictEqual((await validated(fixture, { ...CLAIMS, sub: 'bob' })).ok, true);
  });

  test('caps token age through the expiry and lifetime checks that precede it', async () => {
    // The age cap itself is defence in depth and cannot be reached on its own:
    // an unexpired token satisfies `now < exp + skew`, and a valid lifetime
    // bounds `exp - iat`, which together already bound `now - iat`. These are
    // the two checks that enforce it in practice.
    const fixture = profile('project-jwt-v1', undefined, { now: () => 100_000n });
    assertReason(await validated(fixture, { ...CLAIMS, iat: 90_000, exp: 100_500 }), 'lifetime_invalid');
    assertReason(await validated(fixture, { ...CLAIMS, iat: 99_000, exp: 99_500 }), 'token_expired');
  });
});

describe('JWT validation structure and admission', () => {
  test('rejects a profile that was not built by createJwtProfile', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify(CLAIMS));
    const result = await validateJwt(token, { profile: { ...fixture.profile }, limits: LIMITS_V1 });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'invalid_jwt_profile');
    }
  });

  test('reports a clock that throws separately from one that returns an invalid value', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify(CLAIMS));

    const throwing = profile('project-jwt-v1', undefined, {
      now: () => {
        throw new Error('clock offline');
      },
    });
    const unavailable = await validateJwt(token, { profile: throwing.profile, limits: LIMITS_V1 });
    assert.strictEqual(unavailable.ok, false);
    if (!unavailable.ok) {
      assert.strictEqual(unavailable.category, 'backend_failure');
      assert.strictEqual(unavailable.reason, 'trusted_clock_unavailable');
    }

    for (const now of [() => 1_000 as unknown as bigint, () => -1n]) {
      const invalid = profile('project-jwt-v1', undefined, { now });
      const result = await validateJwt(token, { profile: invalid.profile, limits: LIMITS_V1 });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'trusted_clock_invalid');
      }
    }
  });

  test('rejects limits that were never lowered from the baseline', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify(CLAIMS));
    // Limits arrive as a plain structural value, so a caller can present one
    // that raises a bound above the baseline rather than lowering it.
    const raised = { ...LIMITS_V1, jwtInput: LIMITS_V1.jwtInput + 1 };

    const result = await validateJwt(token, { profile: fixture.profile, limits: raised });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'limit_jwtInput_exceeds_baseline');
    }

    const created = await createJwt({
      profile: fixture.profile,
      limits: raised,
      claims: CLAIMS,
      signing: { policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'), key: fixture.signing },
    });
    assert.strictEqual(created.ok, false);
    if (!created.ok) {
      assert.strictEqual(created.reason, 'limit_jwtInput_exceeds_baseline');
    }
  });

  test('refuses a JWS that marks its payload unencoded', async () => {
    const fixture = profile('project-jwt-v1');
    // A JWT payload is always Base64url-encoded JSON; an unencoded one could
    // carry a period and change how the token's own components split. The JWT
    // profile never enables the mode, so the signature layer refuses the token
    // first and the JWT-level `b64` check behind it is defence in depth.
    // The unencoded profile permits only printable ASCII, which excludes the
    // `//` of the usual issuer URL; the payload-encoding check runs before any
    // claim validation, so the claim values here are immaterial.
    const claims = new TextEncoder().encode(JSON.stringify({ ...CLAIMS, iss: 'issuer' }));
    const result = await signCompact(claims, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: fixture.signing,
      limits: LIMITS_V1,
      protectedHeader: { typ: 'project+jwt' },
      unencoded: true,
      detached: true,
    });
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    const [header, , signature] = result.token.split('.');
    const token = `${header}.${Buffer.from(claims).toString('base64url')}.${signature}`;
    const validation = await validateJwt(token, { profile: fixture.profile, limits: LIMITS_V1 });
    assert.strictEqual(validation.ok, false);
    if (!validation.ok) {
      assert.strictEqual(validation.reason, 'unencoded_payload_not_accepted');
    }
  });

  test('binds the signing key to the claimed issuer at the two reachable enforcement points', async () => {
    // Without this binding any trusted key could mint a token for any issuer.
    // The inner `key_issuer_mismatch` guard is defence in depth and cannot be
    // reached: the profile fixes the verification principal to the issuer, and
    // the claims stage has already refused any other `iss`. These are the two
    // checks that enforce the binding in practice.
    const fixture = profile('project-jwt-v1');
    const mismatch = await validateJwt(
      await signed(fixture, JSON.stringify({ ...CLAIMS, iss: 'https://attacker.example' })),
      { profile: fixture.profile, limits: LIMITS_V1 },
    );
    assert.strictEqual(mismatch.ok, false);
    if (!mismatch.ok) {
      assert.strictEqual(mismatch.category, 'issuer_mismatch');
    }

    const pair = keys();
    const configured = createJwtProfile({
      name: 'project-jwt-v1',
      issuer: 'https://issuer.example',
      audience: 'api',
      type: 'project+jwt',
      chain: 'JWS -> claims',
      clock: { now: () => 1_000n },
      subject: () => true,
      verification: {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
        key: pair.verification,
        principalId: 'https://other.example',
      },
    });
    assert.strictEqual(configured.ok, false);
    if (!configured.ok) {
      assert.strictEqual(configured.reason, 'verification_principal_must_match_issuer');
    }
  });

  test('rejects a token larger than the configured input limit', async () => {
    const fixture = profile('project-jwt-v1');
    const token = await signed(fixture, JSON.stringify(CLAIMS));
    const result = await validateJwt(token, { profile: fixture.profile, limits: lowerLimits({ jwtInput: 16 }) });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'jwt_too_large');
    }
  });

  test('rejects a chain that disagrees with the presented serialization', async () => {
    const fixture = profile('project-jwt-v1');
    // A JWE presented where the profile expects a JWS: five components rather
    // than three, refused on structure before any cryptography runs.
    const result = await validateJwt('a.b.c.d.e', { profile: fixture.profile, limits: LIMITS_V1 });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'jwt_chain_mismatch');
    }
  });

  test('rejects claims that parse as JSON but are not an object', async () => {
    const fixture = profile('project-jwt-v1');
    for (const payload of ['[]', '"claims"', '42', 'null', 'true']) {
      const result = await validateJwt(await signed(fixture, payload), {
        profile: fixture.profile,
        limits: LIMITS_V1,
      });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'claims_must_be_object');
      }
    }
  });

  test('projects claims with a null prototype and NumericDate only at the top level', async () => {
    const fixture = profile('project-jwt-v1');
    const claims = { ...CLAIMS, nbf: 900, meta: { exp: 5, note: 'x' }, tags: ['a', 1, null], flag: true };
    const result = await validateJwt(await signed(fixture, JSON.stringify(claims)), {
      profile: fixture.profile,
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    const view = result.value.claims;
    assert.strictEqual(Object.getPrototypeOf(view), null);
    for (const name of ['exp', 'nbf', 'iat'] as const) {
      assert.strictEqual(typeof view[name], 'bigint');
    }
    assert.strictEqual(view['flag'], true);
    // A nested `exp` never passed NumericDate validation, so it stays an
    // unconverted JSON number alongside the other non-temporal values.
    const meta = view['meta'] as Record<string, unknown>;
    assert.deepStrictEqual(meta['exp'], { lexeme: '5' });
    assert.deepStrictEqual(view['tags'], ['a', { lexeme: '1' }, null]);
  });

  test('reports a replay store that throws or cannot confirm uniqueness as unavailable', async () => {
    const claims = JSON.stringify({ ...CLAIMS, jti: 'token-1' });

    const throwing = profile('project-single-use-jwt-v1', {
      admit: () => {
        throw new Error('store offline');
      },
    });
    const thrown = await validateJwt(await signed(throwing, claims), {
      profile: throwing.profile,
      limits: LIMITS_V1,
    });
    assert.strictEqual(thrown.ok, false);
    if (!thrown.ok) {
      assert.strictEqual(thrown.category, 'backend_failure');
      assert.strictEqual(thrown.reason, 'replay_store_unavailable');
    }

    // Anything other than a definite admission fails closed rather than being
    // treated as a pass.
    const indefinite = profile('project-single-use-jwt-v1', {
      admit: () => Promise.resolve('unavailable'),
    });
    const result = await validateJwt(await signed(indefinite, claims), {
      profile: indefinite.profile,
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
      assert.strictEqual(result.reason, 'replay_store_unavailable');
    }
  });
});
