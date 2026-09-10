import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { AlgorithmPolicy } from '../../src/policy/algorithms.ts';
import { encodeBase64url } from '../../src/internal/encoding/base64url.ts';
import { systemRandom } from '../../src/internal/crypto/random.ts';
import { generateSecret } from '../../src/key/generate.ts';
import { inspectUnverifiedHeader } from '../../src/inspect.ts';
import { encryptCompact } from '../../src/jwe/compact.ts';
import { LIMITS_V1 } from '../../src/policy/limits.ts';

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
});
