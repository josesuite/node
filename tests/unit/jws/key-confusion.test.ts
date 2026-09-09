/**
 * Regressions for key-substitution attacks: an asymmetric public key replayed
 * as a MAC secret, and a token carrying its own verification key.
 *
 * Both are foreclosed by construction, so these assert the construction itself
 * rather than a code path that could be reached another way.
 */

import { describe, expect, test } from 'bun:test';
import { createHmac, generateKeyPairSync } from 'node:crypto';

import { signCompact } from '../../../src/jws/sign.ts';
import { verifyCompact } from '../../../src/jws/verify.ts';
import { importKeyBytes, type UsableKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

const PAYLOAD = new TextEncoder().encode('{"sub":"privileged"}');

function importJwk(jwk: unknown, algorithm: string, operation: 'sign' | 'verify'): UsableKey {
  const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(jwk)), { algorithm, operation });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

function rsaPair() {
  const generated = generateKeyPairSync('rsa', { modulusLength: 3072 });
  return {
    publicJwk: generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    privateJwk: generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>,
  };
}

function ecPair() {
  const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicJwk: generated.publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    privateJwk: generated.privateKey.export({ format: 'jwk' }) as Record<string, unknown>,
  };
}

describe('an asymmetric public key is not usable as a MAC secret', () => {
  test('an RSA public JWK cannot be imported for HS256', () => {
    const { publicJwk } = rsaPair();
    const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(publicJwk)), {
      algorithm: 'HS256',
      operation: 'verify',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('incompatible_key');
      expect(result.reason).toBe('key_type_not_eligible_for_algorithm');
    }
  });

  test('an EC public JWK cannot be imported for HS256', () => {
    const { publicJwk } = ecPair();
    const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(publicJwk)), {
      algorithm: 'HS256',
      operation: 'verify',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('incompatible_key');
    }
  });

  test('an HS256 token MACed with the public key is refused by the RS256-bound key', async () => {
    // Both algorithms are allowlisted so that the rejection comes from the key's
    // algorithm binding rather than from the policy happening to exclude HS256.
    const { publicJwk } = rsaPair();
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const payload = Buffer.from(PAYLOAD).toString('base64url');
    const forged = createHmac('sha256', Buffer.from(JSON.stringify(publicJwk)))
      .update(`${header}.${payload}`)
      .digest('base64url');

    const result = await verifyCompact(`${header}.${payload}.${forged}`, {
      policy: AlgorithmPolicy.create('jws', ['RS256', 'HS256'], 'receive'),
      key: importJwk(publicJwk, 'RS256', 'verify'),
      principalId: 'issuer',
      limits: LIMITS_V1,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('incompatible_key');
      // Decided before any MAC is computed over attacker-chosen bytes.
      expect(result.stage).toBe('key_resolution');
    }
  });
});

describe('a token cannot supply its own verification key', () => {
  test('an embedded jwk header does not displace the configured key', async () => {
    // The object is validly self-signed and carries its matching public key, so
    // only the configured key deciding keeps it from verifying.
    const forger = ecPair();
    const configured = ecPair();

    const token = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: importJwk(forger.privateJwk, 'ES256', 'sign'),
      limits: LIMITS_V1,
      protectedHeader: { jwk: forger.publicJwk as never },
    });
    if (!token.ok) {
      throw new Error(`sign failed: ${token.reason}`);
    }

    const result = await verifyCompact(token.token, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      key: importJwk(configured.publicJwk, 'ES256', 'verify'),
      principalId: 'configured-signer',
      limits: LIMITS_V1,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('signature_verification_failure');
    }
  });

  test('an embedded x5c chain does not displace the configured key', async () => {
    const forger = ecPair();
    const configured = ecPair();
    const certificate = Buffer.from(new Uint8Array(32).fill(1)).toString('base64');

    const token = await signCompact(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: importJwk(forger.privateJwk, 'ES256', 'sign'),
      limits: LIMITS_V1,
      protectedHeader: { x5c: [certificate] },
    });
    if (!token.ok) {
      throw new Error(`sign failed: ${token.reason}`);
    }

    const result = await verifyCompact(token.token, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      key: importJwk(configured.publicJwk, 'ES256', 'verify'),
      principalId: 'configured-signer',
      limits: LIMITS_V1,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('signature_verification_failure');
    }
  });
});
