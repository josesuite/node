import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';

import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { encryptCompact } from '../../../src/jwe/compact.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
import { decryptKeyContainer } from '../../../src/jwk/decrypt.ts';
import { importKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

function object(value: Record<string, unknown>): JsonObject {
  const parsed = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!parsed.ok || parsed.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return parsed.value;
}

function wrappingKeys() {
  const jwk = { kty: 'oct', k: Buffer.alloc(32, 9).toString('base64url') };
  const encryption = importKey(object(jwk), {
    algorithm: 'A256KW',
    operation: 'wrapKey',
    contentAlgorithms: ['A128GCM'],
  });
  const decryption = importKey(object(jwk), {
    algorithm: 'A256KW',
    operation: 'unwrapKey',
    contentAlgorithms: ['A128GCM'],
  });
  if (!encryption.ok || !decryption.ok) {
    throw new Error('key import failed');
  }
  return { encryption: encryption.key, decryption: decryption.key };
}

function allocator(): NonceAllocator {
  return { reserve: () => Promise.resolve<NonceResult>({ ok: true, reservation: { nonce: composeNonce(1, 1n)! } }) };
}

describe('encrypted key containers', () => {
  test('decrypts and imports only the caller-selected JWK type', async () => {
    const wrapping = wrappingKeys();
    const publicJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const encrypted = await encryptCompact(new TextEncoder().encode(JSON.stringify(publicJwk)), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: wrapping.encryption }],
      protectedHeader: { cty: 'jwk+json' },
      random: systemRandom,
      nonceAllocator: allocator(),
      limits: LIMITS_V1,
    });
    if (!encrypted.ok) {
      throw new Error(encrypted.reason);
    }
    const result = await decryptKeyContainer(encrypted.token, {
      type: 'jwk+json',
      limits: LIMITS_V1,
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
        principalId: 'recipient',
      },
      jwk: { namespace: 'issuer-keys', principalId: 'issuer', import: { algorithm: 'ES256', operation: 'verify' } },
    });
    expect(result.ok).toBe(true);
    if (result.ok && result.type === 'jwk+json') {
      expect(result.key.algorithm).toBe('ES256');
      expect(result.principalId).toBe('issuer');
    }
  });

  test('rejects a conflicting JWT content type', async () => {
    const wrapping = wrappingKeys();
    const encrypted = await encryptCompact(new TextEncoder().encode('{}'), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: wrapping.encryption }],
      protectedHeader: { cty: 'JWT' },
      random: systemRandom,
      nonceAllocator: allocator(),
      limits: LIMITS_V1,
    });
    if (!encrypted.ok) {
      throw new Error(encrypted.reason);
    }
    const result = await decryptKeyContainer(encrypted.token, {
      type: 'jwk+json',
      limits: LIMITS_V1,
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
        principalId: 'recipient',
      },
      jwk: { namespace: 'keys', principalId: 'issuer', import: { algorithm: 'ES256', operation: 'verify' } },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('token_type_mismatch');
    }
  });
});
