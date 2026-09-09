import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';
import { parseCompact } from '../../../src/jws/compact.ts';
import { signCompact } from '../../../src/jws/sign.ts';
import { verifyCompact } from '../../../src/jws/verify.ts';
import { availableCurves } from '../../helpers/runtime.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function key(jwk: Record<string, unknown>, algorithm: string, operation: 'sign' | 'verify'): UsableKey {
  const result = importKey(object(jwk), { algorithm, operation });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

function ecPair(algorithm = 'ES256', curve = 'P-256') {
  const generated = generateKeyPairSync('ec', { namedCurve: curve });
  const priv = generated.privateKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
  const pub = generated.publicKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
  return {
    signing: key(priv, algorithm, 'sign'),
    verification: key(pub, algorithm, 'verify'),
  };
}

function octKey(algorithm: string, bytes: number) {
  const jwk = { kty: 'oct', k: randomBytes(bytes).toString('base64url') };
  return {
    signing: key(jwk, algorithm, 'sign'),
    verification: key(jwk, algorithm, 'verify'),
  };
}

const PAYLOAD = new TextEncoder().encode('{"sub":"alice"}');

async function signWith(k: UsableKey, algorithm: string, payload = PAYLOAD, extra = {}) {
  const result = await signCompact(payload, {
    policy: AlgorithmPolicy.create('jws', [algorithm], 'create'),
    key: k,
    limits: LIMITS_V1,
    ...extra,
  });
  if (!result.ok) {
    throw new Error(`sign failed: ${result.reason}`);
  }
  return result.token;
}

async function verifyWith(token: string, k: UsableKey, algorithm: string, extra = {}) {
  return await verifyCompact(token, {
    policy: AlgorithmPolicy.create('jws', [algorithm], 'receive'),
    key: k,
    principalId: 'signer-a',
    limits: LIMITS_V1,
    ...extra,
  });
}

describe('compact structure', () => {
  test('parses exactly three components', () => {
    const result = parseCompact('aGVhZGVy.cGF5bG9hZA.c2ln', LIMITS_V1.joseInput);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.parts.protectedComponent, 'aGVhZGVy');
      assert.strictEqual(result.parts.payloadComponent, 'cGF5bG9hZA');
      assert.strictEqual(result.parts.signatureComponent, 'c2ln');
    }
  });

  test('accepts an empty payload component for detached form', () => {
    const result = parseCompact('aGVhZGVy..c2ln', LIMITS_V1.joseInput);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.parts.payloadComponent, '');
    }
  });

  test('rejects wrong component counts', () => {
    assert.strictEqual(parseCompact('a.b', LIMITS_V1.joseInput).ok, false);
    assert.strictEqual(parseCompact('abc', LIMITS_V1.joseInput).ok, false);

    const extra = parseCompact('a.b.c.d', LIMITS_V1.joseInput);
    assert.strictEqual(extra.ok, false);
    if (!extra.ok) {
      assert.strictEqual(extra.reason, 'too_many_components');
    }
  });

  test('rejects an absent protected header or empty signature', () => {
    const noHeader = parseCompact('.cGF5.c2ln', LIMITS_V1.joseInput);
    assert.strictEqual(noHeader.ok, false);
    if (!noHeader.ok) {
      assert.strictEqual(noHeader.category, 'invalid_header');
    }

    // An empty signature is the shape an unsecured object takes.
    const noSignature = parseCompact('aGVhZGVy.cGF5.', LIMITS_V1.joseInput);
    assert.strictEqual(noSignature.ok, false);
    if (!noSignature.ok) {
      assert.strictEqual(noSignature.reason, 'empty_signature');
    }
  });

  test('bounds the whole input', () => {
    const result = parseCompact('a.b.c', 4);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }
  });
});

describe('round trips', () => {
  test('verifies an ES256 signature', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256');
    const result = await verifyWith(token, verification, 'ES256');

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), '{"sub":"alice"}');
      assert.strictEqual(result.principalId, 'signer-a');
      assert.strictEqual(result.isSharedSecret, false);
    }
  });

  test('verifies an HS256 MAC and marks it as a shared secret', async () => {
    const { signing, verification } = octKey('HS256', 32);
    const result = await verifyWith(await signWith(signing, 'HS256'), verification, 'HS256');

    assert.strictEqual(result.ok, true);
    // A MAC establishes the shared-secret domain, not which holder produced it.
    if (result.ok) {
      assert.strictEqual(result.isSharedSecret, true);
    }
  });

  test('verifies RSA PKCS#1 and PSS signatures', async () => {
    const generated = generateKeyPairSync('rsa', { modulusLength: 3072 });
    const priv = generated.privateKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
    const pub = generated.publicKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;

    for (const algorithm of ['RS256', 'PS256']) {
      const token = await signWith(key(priv, algorithm, 'sign'), algorithm);
      assert.strictEqual((await verifyWith(token, key(pub, algorithm, 'verify'), algorithm)).ok, true);
    }
  });

  test('round trips an empty payload', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', new Uint8Array());
    const result = await verifyWith(token, verification, 'ES256');

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.payload.length, 0);
    }
  });

  test('round trips on every ECDSA curve this runtime provides', async () => {
    const byCurve: Readonly<Record<string, string>> = {
      'P-256': 'ES256',
      'P-384': 'ES384',
      'P-521': 'ES512',
      secp256k1: 'ES256K',
    };

    for (const curve of availableCurves(Object.keys(byCurve))) {
      const algorithm = byCurve[curve]!;
      const { signing, verification } = ecPair(algorithm, curve);
      assert.strictEqual((await verifyWith(await signWith(signing, algorithm), verification, algorithm)).ok, true);
    }
  });
});

describe('project-owned fixtures', () => {
  test('verifies an independently serialized HMAC JWS', async () => {
    const verification = key(
      {
        kty: 'oct',
        k: 'cHJvamVjdC1vd25lZC1obWFjLWZpeHR1cmUta2V5LTMyYnl0ZXMhIQ',
      },
      'HS256',
      'verify',
    );
    const token = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6InByb2plY3QrandzIn0',
      'eyJpc3MiOiJpbnRlcm5hbCIsInN1YiI6ImFsaWNlIiwiYWRtaW4iOnRydWV9',
      'nL-Ov1o8Avp4Uc4Riwv45TsV8CMK5YyKzM98PU4365o',
    ].join('.');

    const result = await verifyWith(token, verification, 'HS256');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), '{"iss":"internal","sub":"alice","admin":true}');
    }
  });
});

describe('tampering is detected', () => {
  test('a modified payload fails verification', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256');
    const [header, , signature] = token.split('.');
    const tampered = `${header}.${Buffer.from('{"sub":"mallory"}').toString('base64url')}.${signature}`;

    const result = await verifyWith(tampered, verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'signature_verification_failure');
      assert.strictEqual(result.stage, 'cryptographic');
    }
  });

  test('a modified protected header fails verification', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, {
      protectedHeader: { cty: 'application/json' },
    });
    const [, payload, signature] = token.split('.');
    const rewritten = Buffer.from(JSON.stringify({ alg: 'ES256', cty: 'text/plain' })).toString('base64url');

    const result = await verifyWith(`${rewritten}.${payload}.${signature}`, verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'signature_verification_failure');
    }
  });

  test('a signature from a different key fails', async () => {
    const a = ecPair();
    const b = ecPair();
    const result = await verifyWith(await signWith(a.signing, 'ES256'), b.verification, 'ES256');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'signature_verification_failure');
    }
  });
});

describe('kid filtering', () => {
  function namedPair(kid: string) {
    const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const priv = generated.privateKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
    const pub = generated.publicKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
    return {
      signing: key({ ...priv, kid }, 'ES256', 'sign'),
      verification: key({ ...pub, kid }, 'ES256', 'verify'),
    };
  }

  test('a matching kid verifies', async () => {
    const alice = namedPair('alice');
    const token = await signWith(alice.signing, 'ES256', PAYLOAD, { protectedHeader: { kid: 'alice' } });

    const result = await verifyWith(token, alice.verification, 'ES256');
    assert.strictEqual(result.ok, true);
  });

  test('an unmatched kid resolves nothing rather than using the configured key', async () => {
    // The signature would verify under this key. Ignoring the unmatched hint is
    // exactly the fallback that would accept a token naming a key the caller
    // never configured.
    const alice = namedPair('alice');
    const token = await signWith(alice.signing, 'ES256', PAYLOAD, { protectedHeader: { kid: 'other' } });

    const result = await verifyWith(token, alice.verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'key_resolution_failure');
      assert.strictEqual(result.reason, 'kid_does_not_match_configured_key');
    }
  });

  test('a kid is filtered even when the configured key carries none', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, { protectedHeader: { kid: 'named' } });

    const result = await verifyWith(token, verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'kid_does_not_match_configured_key');
    }
  });

  test('an absent kid leaves the configured key eligible', async () => {
    const alice = namedPair('alice');
    const token = await signWith(alice.signing, 'ES256');

    const result = await verifyWith(token, alice.verification, 'ES256');
    assert.strictEqual(result.ok, true);
  });

  test('a truncated MAC does not verify', async () => {
    const { signing, verification } = octKey('HS256', 32);
    const token = await signWith(signing, 'HS256');
    const [header, payload, signature] = token.split('.');
    const shortened = Buffer.from(signature!, 'base64url').subarray(0, 16).toString('base64url');

    const result = await verifyWith(`${header}.${payload}.${shortened}`, verification, 'HS256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'signature_verification_failure');
    }
  });
});

describe('algorithm and key confusion', () => {
  test('a token naming an algorithm outside the policy is refused', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256');

    const result = await verifyCompact(token, {
      policy: AlgorithmPolicy.create('jws', ['RS256'], 'receive'),
      key: verification,
      principalId: 'signer-a',
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      // Policy is decided before any key work happens.
      assert.strictEqual(result.stage, 'header');
    }
  });

  test('a key bound to another algorithm is refused', async () => {
    const { signing } = ecPair();
    const es384 = ecPair('ES384', 'P-384');
    const token = await signWith(signing, 'ES256');

    const result = await verifyCompact(token, {
      policy: AlgorithmPolicy.create('jws', ['ES256', 'ES384'], 'receive'),
      key: es384.verification,
      principalId: 'signer-a',
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
      assert.strictEqual(result.stage, 'key_resolution');
    }
  });

  test('an unsecured token is rejected before any key work', async () => {
    // `none` carries no signature, so the structure alone is refused.
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    const { verification } = ecPair();
    const result = await verifyWith(`${header}.${Buffer.from('x').toString('base64url')}.`, verification, 'ES256');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'syntax');
    }
  });

  test('a prohibited algorithm with a forged signature is still refused', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    const { verification } = ecPair();
    const token = `${header}.${Buffer.from('x').toString('base64url')}.AAAA`;

    const result = await verifyWith(token, verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'prohibited_algorithm');
    }
  });

  test('a verification key cannot be used for signing', async () => {
    const { verification } = ecPair();
    const result = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: verification,
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
    }
  });
});

describe('header validation during verification', () => {
  test('requires a protected algorithm', async () => {
    const { verification } = ecPair();
    const header = Buffer.from(JSON.stringify({ kid: 'k' })).toString('base64url');
    const result = await verifyWith(`${header}.cGF5.c2ln`, verification, 'ES256');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
      assert.strictEqual(result.reason, 'alg_missing');
    }
  });

  test('rejects a duplicate member in the protected header', async () => {
    const { verification } = ecPair();
    const header = Buffer.from('{"alg":"ES256","alg":"none"}').toString('base64url');
    const result = await verifyWith(`${header}.cGF5.c2ln`, verification, 'ES256');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      // A duplicate is malformed input, decided before the discarded value
      // could name a prohibited algorithm.
      assert.strictEqual(result.category, 'malformed_input');
      assert.strictEqual(result.stage, 'syntax');
    }
  });

  test('rejects an unsupported critical extension', async () => {
    const { verification } = ecPair();
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', ext: 'v', crit: ['ext'] })).toString('base64url');

    const result = await verifyWith(`${header}.cGF5.c2ln`, verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_critical_parameter');
    }
  });

  test('ignores an unknown noncritical parameter', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, {
      protectedHeader: { 'x-vendor': 'anything' },
    });
    assert.strictEqual((await verifyWith(token, verification, 'ES256')).ok, true);
  });

  test('a JWE content-encryption name in a JWS does not dispatch a backend', async () => {
    // The parameter belongs to another context, so it is an ignorable unknown
    // rather than an algorithm selector here.
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, {
      protectedHeader: { enc: 'A128GCM' },
    });
    assert.strictEqual((await verifyWith(token, verification, 'ES256')).ok, true);
  });

  test('rejects malformed Base64url in the header or signature', async () => {
    const { verification } = ecPair();
    const result = await verifyWith('not!base64.cGF5.c2ln', verification, 'ES256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_encoding');
    }
  });
});

describe('detached and unencoded payloads', () => {
  test('round trips a detached payload', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, { detached: true });
    assert.strictEqual(token.split('.')[1], '');

    const result = await verifyWith(token, verification, 'ES256', { detachedPayload: PAYLOAD });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), '{"sub":"alice"}');
    }
  });

  test('detached verification fails against different external content', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, { detached: true });

    const result = await verifyWith(token, verification, 'ES256', {
      detachedPayload: new TextEncoder().encode('{"sub":"mallory"}'),
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'signature_verification_failure');
    }
  });

  test('returns the payload authenticated, not later writes to the caller buffer', async () => {
    const { signing, verification } = ecPair();
    const original = new TextEncoder().encode('{"sub":"alice"}');
    const token = await signWith(signing, 'ES256', original, { detached: true });

    // The caller keeps this array and overwrites it while verification is still
    // awaiting the provider. A success must report the bytes the signature
    // covered; returning the mutated buffer would report unauthenticated bytes.
    const supplied = new Uint8Array(original);
    const pending = verifyWith(token, verification, 'ES256', { detachedPayload: supplied });
    supplied.fill(0x78);

    const result = await pending;
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), '{"sub":"alice"}');
    }
  });

  test('supplying both an embedded and an external payload is refused', async () => {
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256');

    const result = await verifyWith(token, verification, 'ES256', { detachedPayload: PAYLOAD });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'ambiguous_payload_source');
    }
  });

  test('rejects a correctly signed inline unencoded payload outside the accepted profile', async () => {
    // Built outside the library, so creation's profile check cannot mask the
    // question: a consumer must apply the same restriction the producer does,
    // otherwise acceptance depends on which side assembled the object.
    const secret = randomBytes(32);
    const verification = key({ kty: 'oct', k: secret.toString('base64url') }, 'HS256', 'verify');

    for (const payload of ['line1\nline2', 'café']) {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', b64: false, crit: ['b64'] })).toString('base64url');
      const signingInput = Buffer.concat([Buffer.from(`${header}.`, 'ascii'), Buffer.from(payload, 'utf8')]);
      const signature = createHmac('sha256', secret).update(signingInput).digest('base64url');

      const result = await verifyWith(`${header}.${payload}.${signature}`, verification, 'HS256', {
        unencodedPayload: true,
      });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'policy_violation');
        assert.strictEqual(result.reason, 'payload_character_not_permitted');
      }
    }
  });

  test('accepts a printable-boundary inline unencoded payload', async () => {
    const secret = randomBytes(32);
    const verification = key({ kty: 'oct', k: secret.toString('base64url') }, 'HS256', 'verify');

    // U+0020 and U+007E are the ends of the accepted range and stay valid.
    const payload = ' ~!{}[] ';
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', b64: false, crit: ['b64'] })).toString('base64url');
    const signingInput = Buffer.concat([Buffer.from(`${header}.`, 'ascii'), Buffer.from(payload, 'utf8')]);
    const signature = createHmac('sha256', secret).update(signingInput).digest('base64url');

    const result = await verifyWith(`${header}.${payload}.${signature}`, verification, 'HS256', {
      unencodedPayload: true,
    });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), payload);
    }
  });

  test('round trips an unencoded payload marked critical', async () => {
    const { signing, verification } = ecPair();
    const text = new TextEncoder().encode('plain text payload');
    const token = await signWith(signing, 'ES256', text, { unencoded: true });

    // The payload travels literally, not Base64url-encoded.
    assert.strictEqual(token.split('.')[1], 'plain text payload');

    const result = await verifyWith(token, verification, 'ES256', { unencodedPayload: true });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), 'plain text payload');
    }
  });

  test('refuses an inline unencoded payload containing a period', async () => {
    const { signing } = ecPair();
    const result = await signCompact(new TextEncoder().encode('has.period'), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: signing,
      limits: LIMITS_V1,
      unencoded: true,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'payload_character_not_permitted');
    }
  });

  test('refuses non-ASCII inline unencoded content', async () => {
    const { signing } = ecPair();
    const result = await signCompact(new TextEncoder().encode('héllo'), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: signing,
      limits: LIMITS_V1,
      unencoded: true,
    });
    assert.strictEqual(result.ok, false);
  });

  test('an unencoded payload not marked critical is refused on verification', async () => {
    const { verification } = ecPair();
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', b64: false })).toString('base64url');
    const result = await verifyWith(`${header}.plain.c2ln`, verification, 'ES256');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'b64_not_critical');
    }
  });
});

describe('creation guards', () => {
  test('refuses a caller header that would override the algorithm', async () => {
    const { signing } = ecPair();
    for (const name of ['alg', 'b64', 'crit']) {
      const result = await signCompact(PAYLOAD, {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
        key: signing,
        limits: LIMITS_V1,
        protectedHeader: { [name]: 'x' },
      });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'invalid_header');
      }
    }
  });

  test('refuses a wrong-type recognized header', async () => {
    // A recognized parameter's JSON type is fixed, and a producer emitting the
    // wrong one builds an object its corresponding consumer rejects.
    const { signing } = ecPair();
    const result = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: signing,
      limits: LIMITS_V1,
      protectedHeader: { typ: ['not', 'a', 'string'] },
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
      assert.strictEqual(result.reason, 'header_typ_wrong_type');
    }
  });

  test('preserves a protected header named __proto__', async () => {
    const { signing } = ecPair();
    const token = await signWith(signing, 'ES256', PAYLOAD, {
      protectedHeader: { ['__proto__']: 'value' },
    });
    const [protectedComponent] = token.split('.');

    assert.deepStrictEqual(JSON.parse(Buffer.from(protectedComponent!, 'base64url').toString()), {
      ['__proto__']: 'value',
      alg: 'ES256',
    });
  });

  test('refuses to create with an algorithm outside the policy', async () => {
    const { signing } = ecPair();
    const result = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['RS256'], 'create'),
      key: signing,
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
    }
  });

  test('bounds the payload size', async () => {
    const { signing } = ecPair();
    const result = await signCompact(new Uint8Array(LIMITS_V1.payload + 1), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: signing,
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }
  });

  test('refuses a private key bound to verification', async () => {
    const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateJwk = generated.privateKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
    const result = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: key(privateJwk, 'ES256', 'verify'),
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'key_operation_mismatch');
    }
  });

  test('bounds the protected header size', async () => {
    const { signing } = ecPair();
    const result = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: signing,
      limits: lowerLimits({ headerSource: 1 }),
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'header_too_large');
    }
  });
});

describe('resource limits reach the whole operation', () => {
  test('accounts cryptographic attempts without a caller-supplied budget', async () => {
    // A standalone call owns its budget. Accounting only when an enclosing
    // operation passes one in would leave every direct call unbounded.
    const { signing, verification } = ecPair();
    const token = await signWith(signing, 'ES256');

    const result = await verifyCompact(token, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      key: verification,
      principalId: 'alice',
      limits: lowerLimits({ cryptographicAttempts: 0 }),
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'cryptographic_attempt_budget_exceeded');
    }
  });
});
