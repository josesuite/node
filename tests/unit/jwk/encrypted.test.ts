import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
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
    assert.strictEqual(result.ok, true);
    if (result.ok && result.type === 'jwk+json') {
      assert.strictEqual(result.key.algorithm, 'ES256');
      assert.strictEqual(result.principalId, 'issuer');
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
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'token_type_mismatch');
    }
  });

  test('clears the decrypted document when the content type is rejected', async () => {
    // The plaintext is an owned decrypted private-key document. A content-type
    // rejection is still a post-decryption exit, so it must not leave that
    // document in memory.
    const wrapping = wrappingKeys();
    const secret = JSON.stringify({ kty: 'oct', k: Buffer.alloc(32, 7).toString('base64url') });
    const encrypted = await encryptCompact(new TextEncoder().encode(secret), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: wrapping.encryption }],
      // Omitted `cty` is rejected unless the caller bound the type externally.
      random: systemRandom,
      nonceAllocator: allocator(),
      limits: LIMITS_V1,
    });
    if (!encrypted.ok) {
      throw new Error(encrypted.reason);
    }

    const cleared: boolean[] = [];
    const fill = Uint8Array.prototype.fill;
    // The plaintext is allocated inside decryption and never surfaces on a
    // rejection, so the clearing is observed at the prototype. Recording the
    // buffer's state at the moment it is zeroed is what distinguishes clearing
    // the real document from zeroing something already empty.
    // oxlint-disable-next-line no-extend-native
    Uint8Array.prototype.fill = function (this: Uint8Array, ...args: Parameters<typeof fill>) {
      if (args[0] === 0 && this.length === secret.length) {
        cleared.push(this.some((byte) => byte !== 0));
      }
      return fill.apply(this, args) as Uint8Array;
    };

    try {
      const result = await decryptKeyContainer(encrypted.token, {
        type: 'jwk+json',
        limits: LIMITS_V1,
        decryption: {
          keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
          contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
          recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
          principalId: 'recipient',
        },
        jwk: { namespace: 'keys', principalId: 'issuer', import: { algorithm: 'HS256', operation: 'verify' } },
      });

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'key_container_cty_required');
      }
    } finally {
      // oxlint-disable-next-line no-extend-native
      Uint8Array.prototype.fill = fill;
    }

    // The document was populated when it was cleared, proving the clearing ran
    // on the real plaintext and not on an already-empty buffer.
    assert.ok(cleared.includes(true));
  });
});
