import { describe, expect, test } from 'bun:test';
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
  test('hashes the validated canonical public projection', () => {
    const privateJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
    const { d: _d, ...publicJwk } = privateJwk;
    const canonical = `{"crv":"${publicJwk.crv}","kty":"EC","x":"${publicJwk.x}","y":"${publicJwk.y}"}`;

    expect(thumbprint(imported(privateJwk))).toBe(thumbprint(imported(publicJwk)));
    expect(thumbprint(imported(publicJwk))).toBe(createHash('sha256').update(canonical).digest('base64url'));
  });

  test('ignores metadata already excluded from imported identity', () => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    expect(thumbprint(imported(jwk))).toBe(thumbprint(imported({ ...jwk, kid: 'renamed', use: 'sig' } as JsonWebKey)));
  });

  test('rejects a caller-assembled key record', () => {
    const forged = { keyType: 'oct', identity: { kty: 'oct', k: new Uint8Array(32) } } as UsableKey;
    expect(computeThumbprint(forged)).toEqual({ ok: false, reason: 'key_not_imported' });
  });

  test('accepts only canonical 32-byte digest URI values', () => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const digest = thumbprint(imported(jwk));
    const encoded = toThumbprintUri(digest);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok || encoded.uri === undefined) {
      throw new Error('expected URI');
    }
    expect(parseThumbprintUri(encoded.uri)).toEqual({ ok: true, thumbprint: digest });
    expect(parseThumbprintUri(`${PREFIX}${digest.slice(0, 42)}B`).ok).toBe(false);
    expect(toThumbprintUri(`${digest.slice(0, 42)}B`).ok).toBe(false);
    expect(parseThumbprintUri(`${PREFIX}${digest.slice(0, 42)}=`).ok).toBe(false);
  });
});
