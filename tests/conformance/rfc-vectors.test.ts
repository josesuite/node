/**
 * Known-answer vectors published in the JOSE RFCs.
 *
 * Their expected values are fixed by the standards rather than generated here,
 * so they detect signing-input, canonicalization, and encoding differences that
 * a self-consistent round trip cannot. Vectors are evaluated under project
 * policy, which is stricter than the RFCs.
 */

import { describe, expect, test } from 'bun:test';

import { computeThumbprint, toThumbprintUri } from '../../src/jwk/thumbprint.ts';
import { verifyCompact } from '../../src/jws/verify.ts';
import { importKeyBytes, type UsableKey } from '../../src/key/import.ts';
import { AlgorithmPolicy } from '../../src/policy/algorithms.ts';
import { LIMITS_V1 } from '../../src/policy/limits.ts';
import { flipBit } from '../helpers/runtime.ts';

interface ImportOverrides {
  readonly receiveOnly?: boolean;
}

function importJwk(
  jwk: Record<string, unknown>,
  algorithm: string,
  operation: 'sign' | 'verify',
  overrides: ImportOverrides = {},
): UsableKey {
  const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(jwk)), {
    algorithm,
    operation,
    ...overrides,
  });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

describe('RFC 7515 Appendix A.1 HMAC vector', () => {
  const KEY = {
    kty: 'oct',
    k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
  };
  const TOKEN = [
    'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
    'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  ].join('.');

  test('verifies the published token and returns its exact payload octets', async () => {
    const result = await verifyCompact(TOKEN, {
      policy: AlgorithmPolicy.create('jws', ['HS256'], 'receive'),
      key: importJwk(KEY, 'HS256', 'verify'),
      principalId: 'joe',
      limits: LIMITS_V1,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      // The vector's header and payload carry literal CRLFs and interior
      // spacing, so reserializing either would change the signing input.
      expect(new TextDecoder().decode(result.payload)).toBe(
        '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}',
      );
      expect(result.isSharedSecret).toBe(true);
    }
  });

  test('rejects the published token when one signature octet is altered', async () => {
    const [header, payload, signature] = TOKEN.split('.');
    const flipped = flipBit(new Uint8Array(Buffer.from(signature!, 'base64url')));

    const result = await verifyCompact(`${header}.${payload}.${Buffer.from(flipped).toString('base64url')}`, {
      policy: AlgorithmPolicy.create('jws', ['HS256'], 'receive'),
      key: importJwk(KEY, 'HS256', 'verify'),
      principalId: 'joe',
      limits: LIMITS_V1,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('signature_verification_failure');
    }
  });
});

describe('RFC 7638 Section 3.1 thumbprint vector', () => {
  const RSA = {
    kty: 'RSA',
    n:
      '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3okn' +
      'jhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6q' +
      'MQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awap' +
      'JzKnqDKgw',
    e: 'AQAB',
    alg: 'RS256',
    kid: '2011-04-29',
  };

  test('reproduces the published SHA-256 thumbprint', () => {
    // The vector's modulus is 2048 bits, which project policy admits only for
    // receive-only use; changing it would no longer be the published vector.
    const key = importJwk(RSA, 'RS256', 'verify', { receiveOnly: true });

    expect(computeThumbprint(key)).toEqual({
      ok: true,
      thumbprint: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
    });
  });

  test('excludes alg and kid from the hashed representation', () => {
    const withMetadata = importJwk(RSA, 'RS256', 'verify', { receiveOnly: true });
    const { alg: _alg, kid: _kid, ...required } = RSA;
    const withoutMetadata = importJwk(required, 'RS256', 'verify', { receiveOnly: true });

    expect(computeThumbprint(withMetadata)).toEqual(computeThumbprint(withoutMetadata));
  });
});

describe('RFC 9278 thumbprint URI vector', () => {
  test('wraps the RFC 7638 digest in the published URI form', () => {
    const digest = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    expect(toThumbprintUri(digest)).toMatchObject({
      ok: true,
      uri: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${digest}`,
    });
  });
});

describe('project-owned oct thumbprint fixture', () => {
  test('pins the canonical member order for octet sequences', () => {
    const key = importJwk({ kty: 'oct', k: 'am9zZXN1aXRlLXRodW1icHJpbnQtZml4dHVyZS0zMmI' }, 'HS256', 'verify');

    expect(computeThumbprint(key)).toEqual({
      ok: true,
      thumbprint: 'rKtDP-WPyAj7uvyhmS4zoFynXlUjVXdoqezCQ_8mM4U',
    });
  });
});
