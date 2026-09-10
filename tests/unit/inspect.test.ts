import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { encodeBase64url } from '../../src/internal/encoding/base64url.ts';
import { inspectUnverifiedHeader } from '../../src/inspect.ts';

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
});
