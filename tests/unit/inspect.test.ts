import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { AlgorithmPolicy } from '../../src/policy/algorithms.ts';
import { encodeBase64url } from '../../src/internal/encoding/base64url.ts';
import { systemRandom } from '../../src/internal/crypto/random.ts';
import { generateKeyPair, generateSecret } from '../../src/key/generate.ts';
import { inspectUnverifiedHeader } from '../../src/inspect.ts';
import { encryptCompact } from '../../src/jwe/compact.ts';
import { signCompact } from '../../src/jws/sign.ts';
import { verifyCompact } from '../../src/jws/verify.ts';
import { LIMITS_V1, lowerLimits } from '../../src/policy/limits.ts';

const encoder = new TextEncoder();

/** Builds a syntactically valid compact JWS around an arbitrary header object. */
function tokenWithHeader(header: unknown): string {
  const encoded = encodeBase64url(encoder.encode(JSON.stringify(header)));
  return `${encoded}.${encodeBase64url(encoder.encode('payload'))}.${encodeBase64url(new Uint8Array([1, 2, 3]))}`;
}

/** Builds a compact JWS from a raw protected component, valid or not. */
function tokenWithComponent(component: string): string {
  return `${component}.${encodeBase64url(encoder.encode('payload'))}.${encodeBase64url(new Uint8Array([1, 2, 3]))}`;
}

describe('unverified header inspection', () => {
  test('reads the protected header of a compact JWS', () => {
    const result = inspectUnverifiedHeader(tokenWithHeader({ alg: 'ES256', kid: 'key-1' }), {
      serialization: 'jws-compact',
    });

    assert.ok(result.ok);
    assert.strictEqual(result.header.unverifiedAlgorithm, 'ES256');
    assert.strictEqual(result.header.unverifiedKeyId, 'key-1');
    assert.deepStrictEqual({ ...result.header.unverifiedParameters }, { alg: 'ES256', kid: 'key-1' });
  });

  test('reports `enc` only for an encrypted object', async () => {
    // CBC-HMAC rather than GCM: it needs no durable nonce allocator, so the
    // fixture stays about inspection rather than about nonce provisioning.
    const secret = generateSecret({ algorithm: 'dir', contentAlgorithms: ['A128CBC-HS256'] });
    assert.ok(secret.ok);

    const encrypted = await encryptCompact(encoder.encode('secret'), {
      recipients: [{ key: secret.key }],
      contentAlgorithm: 'A128CBC-HS256',
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
      limits: LIMITS_V1,
      random: systemRandom,
    });
    assert.ok(encrypted.ok);

    const jwe = inspectUnverifiedHeader(encrypted.token, { serialization: 'jwe-compact' });
    assert.ok(jwe.ok);
    assert.strictEqual(jwe.header.unverifiedAlgorithm, 'dir');
    assert.strictEqual(jwe.header.unverifiedContentAlgorithm, 'A128CBC-HS256');

    // The same member name in a signed object names nothing, so it is not
    // reported as a content algorithm there.
    const jws = inspectUnverifiedHeader(tokenWithHeader({ alg: 'ES256', enc: 'A256GCM' }), {
      serialization: 'jws-compact',
    });
    assert.ok(jws.ok);
    assert.strictEqual(jws.header.unverifiedContentAlgorithm, undefined);
  });

  test('inspects a structurally valid token whose signature does not verify', async () => {
    const keys = await generateKeyPair({ algorithm: 'ES256' });
    assert.ok(keys.ok);

    const signed = await signCompact(encoder.encode('hello'), {
      key: keys.keys.privateKey,
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      limits: LIMITS_V1,
    });
    assert.ok(signed.ok);

    const tampered = `${signed.token.slice(0, -4)}AAAA`;
    const inspected = inspectUnverifiedHeader(tampered, { serialization: 'jws-compact' });
    assert.ok(inspected.ok);
    assert.strictEqual(inspected.header.unverifiedAlgorithm, 'ES256');

    // Inspection succeeding says nothing about the signature: the same token
    // must still fail verification.
    const verified = await verifyCompact(tampered, {
      key: keys.keys.publicKey,
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      limits: LIMITS_V1,
      principalId: 'signer',
    });
    assert.strictEqual(verified.ok, false);
  });

  test('requires the serialization the caller configured', () => {
    const jws = tokenWithHeader({ alg: 'ES256' });

    const asJwe = inspectUnverifiedHeader(jws, { serialization: 'jwe-compact' });
    assert.strictEqual(asJwe.ok, false);
    assert.strictEqual(asJwe.category, 'malformed_input');
    assert.strictEqual(asJwe.reason, 'compact_component_count');

    const asJws = inspectUnverifiedHeader(`${jws}.extra.parts`, { serialization: 'jws-compact' });
    assert.strictEqual(asJws.ok, false);
    assert.strictEqual(asJws.reason, 'too_many_components');
  });

  test('rejects wrong component counts and empty required components', () => {
    const header = encodeBase64url(encoder.encode(JSON.stringify({ alg: 'ES256' })));

    for (const [token, reason] of [
      [header, 'missing_separator'],
      [`${header}.payload`, 'missing_separator'],
      [`.payload.${header}`, 'empty_protected_header'],
      [`${header}.payload.`, 'empty_signature'],
    ] as const) {
      const result = inspectUnverifiedHeader(token, { serialization: 'jws-compact' });
      assert.strictEqual(result.ok, false, token);
      assert.strictEqual(result.reason, reason);
    }
  });

  test('rejects a header that is not strict Base64url', () => {
    for (const component of ['not base64url', 'AAAA=', 'eyJhbGciOiJFUzI1NiJ9\n', 'a+/b']) {
      const result = inspectUnverifiedHeader(tokenWithComponent(component), { serialization: 'jws-compact' });
      assert.strictEqual(result.ok, false, component);
      assert.strictEqual(result.category, 'invalid_encoding');
      assert.strictEqual(result.reason, 'protected_header_invalid_base64url');
    }
  });

  test('rejects malformed JSON, invalid UTF-8, and duplicate members', () => {
    const malformed = inspectUnverifiedHeader(tokenWithComponent(encodeBase64url(encoder.encode('{'))), {
      serialization: 'jws-compact',
    });
    assert.strictEqual(malformed.ok, false);
    assert.strictEqual(malformed.category, 'malformed_input');

    // A lone 0xFF inside a string value: structurally valid JSON, invalid UTF-8.
    const invalidUtf8 = inspectUnverifiedHeader(
      tokenWithComponent(encodeBase64url(new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]))),
      { serialization: 'jws-compact' },
    );
    assert.strictEqual(invalidUtf8.ok, false);
    assert.strictEqual(invalidUtf8.category, 'invalid_encoding');
    assert.strictEqual(invalidUtf8.reason, 'protected_header_invalid_encoding');

    // A repeated member has no single value, so it is refused rather than
    // resolved to whichever occurrence happens to come last.
    const duplicate = inspectUnverifiedHeader(
      tokenWithComponent(encodeBase64url(encoder.encode('{"alg":"ES256","alg":"HS256"}'))),
      { serialization: 'jws-compact' },
    );
    assert.strictEqual(duplicate.ok, false);
    assert.strictEqual(duplicate.reason, 'protected_header_duplicate_member');
  });

  test('rejects a header that is not a JSON object', () => {
    for (const value of ['[]', '"alg"', '3', 'null', 'true']) {
      const result = inspectUnverifiedHeader(tokenWithComponent(encodeBase64url(encoder.encode(value))), {
        serialization: 'jws-compact',
      });
      assert.strictEqual(result.ok, false, value);
      assert.strictEqual(result.category, 'invalid_header');
      assert.strictEqual(result.reason, 'header_not_an_object');
    }
  });

  test('applies the configured input and header limits', () => {
    const token = tokenWithHeader({ alg: 'ES256' });

    const inputLimited = inspectUnverifiedHeader(token, {
      serialization: 'jws-compact',
      limits: lowerLimits({ joseInput: 4 }),
    });
    assert.strictEqual(inputLimited.ok, false);
    assert.strictEqual(inputLimited.category, 'resource_limit');
    assert.strictEqual(inputLimited.reason, 'input_too_large');

    const headerLimited = inspectUnverifiedHeader(token, {
      serialization: 'jws-compact',
      limits: lowerLimits({ headerSource: 4 }),
    });
    assert.strictEqual(headerLimited.ok, false);
    assert.strictEqual(headerLimited.category, 'resource_limit');
    assert.strictEqual(headerLimited.reason, 'protected_header_too_large');
  });

  test('rejects limits that were never lowered from the baseline', () => {
    const inflated = { ...LIMITS_V1, headerSource: LIMITS_V1.headerSource + 1 };

    const result = inspectUnverifiedHeader(tokenWithHeader({ alg: 'ES256' }), {
      serialization: 'jws-compact',
      limits: inflated,
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.category, 'policy_violation');
    assert.strictEqual(result.reason, 'limit_headerSource_exceeds_baseline');
  });
});
