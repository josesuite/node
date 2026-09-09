import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createHash, generateKeyPairSync } from 'node:crypto';

import { computeThumbprint, parseThumbprintUri, toThumbprintUri } from '../../../src/jwk/thumbprint.ts';
import { importKeyBytes, type UsableKey } from '../../../src/key/import.ts';

const PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

function imported(jwk: JsonWebKey): UsableKey {
  const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(jwk)), {
    algorithm: 'ES256',
    operation: 'verify',
  });
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return result.key;
}

function thumbprint(key: UsableKey): string {
  const result = computeThumbprint(key);
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return result.thumbprint;
}

describe('JWK thumbprints', () => {
  test('matches the project-owned EC thumbprint fixture', () => {
    const jwk = {
      crv: 'P-256',
      kty: 'EC',
      x: 'TXjWYQ1z2Ilp5N1_9jwxjL5JEuoQQA7uXVCK2W-rcXY',
      y: '_Bu3lmQ-2g3DHHI3ZFRc9q_r8o3eczxG28BXpOyfG_Y',
    };
    const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(jwk)), {
      algorithm: 'ES256',
      operation: 'verify',
    });

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(computeThumbprint(result.key), {
        ok: true,
        thumbprint: '99-b758gQbn1jNcqVGqkjMvv8Oz0cnsxKoA1QF1EG9M',
      });
    }
  });

  test('hashes the validated canonical public projection', () => {
    const privateJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
    const { d: _d, ...publicJwk } = privateJwk;
    const canonical = `{"crv":"${publicJwk.crv}","kty":"EC","x":"${publicJwk.x}","y":"${publicJwk.y}"}`;

    assert.strictEqual(thumbprint(imported(privateJwk)), thumbprint(imported(publicJwk)));
    assert.strictEqual(thumbprint(imported(publicJwk)), createHash('sha256').update(canonical).digest('base64url'));
  });

  test('ignores metadata already excluded from imported identity', () => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    assert.strictEqual(
      thumbprint(imported(jwk)),
      thumbprint(imported({ ...jwk, kid: 'renamed', use: 'sig' } as JsonWebKey)),
    );
  });

  test('rejects a caller-assembled key record', () => {
    const forged = { keyType: 'oct', identity: { kty: 'oct', k: new Uint8Array(32) } } as UsableKey;
    assert.deepStrictEqual(computeThumbprint(forged), { ok: false, reason: 'key_not_imported' });
  });

  test('accepts only canonical 32-byte digest URI values', () => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const digest = thumbprint(imported(jwk));
    const encoded = toThumbprintUri(digest);
    assert.strictEqual(encoded.ok, true);
    if (!encoded.ok || encoded.uri === undefined) {
      throw new Error('expected URI');
    }
    assert.deepStrictEqual(parseThumbprintUri(encoded.uri), { ok: true, thumbprint: digest });
    assert.strictEqual(parseThumbprintUri(`${PREFIX}${digest.slice(0, 42)}B`).ok, false);
    assert.strictEqual(toThumbprintUri(`${digest.slice(0, 42)}B`).ok, false);
    assert.strictEqual(parseThumbprintUri(`${PREFIX}${digest.slice(0, 42)}=`).ok, false);
  });
});
