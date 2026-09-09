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

  test('rejects a URI under any other hash label', () => {
    // Only SHA-256 is accepted, which is narrower than the registry permits,
    // and the whole string must match rather than just the prefix.
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const digest = thumbprint(imported(jwk));

    for (const uri of [
      `urn:ietf:params:oauth:jwk-thumbprint:sha-512:${digest}`,
      `urn:ietf:params:oauth:jwk-thumbprint:${digest}`,
      digest,
      `prefix:${PREFIX}${digest}`,
    ]) {
      assert.strictEqual(parseThumbprintUri(uri).ok, false);
    }
  });

  test('hashes the required members for every supported key type', () => {
    // The member set and its lexicographic order are part of the definition:
    // an implementation that hashes a different projection produces an
    // identifier no other implementation agrees with.
    const rsa = generateKeyPairSync('rsa', { modulusLength: 3072 }).publicKey.export({ format: 'jwk' });
    const rsaKey = importKeyBytes(new TextEncoder().encode(JSON.stringify(rsa)), {
      algorithm: 'RS256',
      operation: 'verify',
    });
    assert.strictEqual(rsaKey.ok, true);
    if (rsaKey.ok) {
      assert.strictEqual(
        thumbprint(rsaKey.key),
        createHash('sha256').update(`{"e":"${rsa.e}","kty":"RSA","n":"${rsa.n}"}`).digest('base64url'),
      );
    }

    const k = Buffer.alloc(32, 1).toString('base64url');
    const octKey = importKeyBytes(new TextEncoder().encode(JSON.stringify({ kty: 'oct', k })), {
      algorithm: 'HS256',
      operation: 'verify',
    });
    assert.strictEqual(octKey.ok, true);
    if (octKey.ok) {
      assert.strictEqual(
        thumbprint(octKey.key),
        createHash('sha256').update(`{"k":"${k}","kty":"oct"}`).digest('base64url'),
      );
    }

    // An OKP thumbprint omits `y`, unlike EC; including it would give the same
    // key two identifiers.
    const okp = generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' });
    const okpKey = importKeyBytes(new TextEncoder().encode(JSON.stringify(okp)), {
      algorithm: 'ECDH-ES',
      operation: 'deriveKey',
      contentAlgorithms: ['A128GCM'],
    });
    assert.strictEqual(okpKey.ok, true);
    if (okpKey.ok) {
      assert.strictEqual(
        thumbprint(okpKey.key),
        createHash('sha256').update(`{"crv":"${okp.crv}","kty":"OKP","x":"${okp.x}"}`).digest('base64url'),
      );
    }
  });
});
