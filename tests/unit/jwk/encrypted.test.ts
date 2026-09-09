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

/** Encrypts an arbitrary document so the decrypted container can be malformed on purpose. */
async function sealed(document: string, contentType = 'jwk-set+json') {
  const wrapping = wrappingKeys();
  const encrypted = await encryptCompact(new TextEncoder().encode(document), {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
    contentAlgorithm: 'A128GCM',
    recipients: [{ key: wrapping.encryption }],
    protectedHeader: { cty: contentType },
    random: systemRandom,
    nonceAllocator: allocator(),
    limits: LIMITS_V1,
  });
  if (!encrypted.ok) {
    throw new Error(encrypted.reason);
  }
  return { token: encrypted.token, wrapping };
}

function jwksOptions(
  wrapping: ReturnType<typeof wrappingKeys>,
  bindings: readonly { principalId: string; options: { algorithm: string; operation: 'verify' } }[],
) {
  return {
    type: 'jwk-set+json' as const,
    limits: LIMITS_V1,
    decryption: {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
      recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
      principalId: 'recipient',
    },
    jwks: { namespace: 'issuer-keys', bindings },
  };
}

const BINDING = { principalId: 'issuer', options: { algorithm: 'ES256', operation: 'verify' as const } };

describe('encrypted key containers', () => {
  test('forwards outer JWE failures before parsing key material', async () => {
    const wrapping = wrappingKeys();
    const result = await decryptKeyContainer('not-a-jwe', {
      type: 'jwk+json',
      limits: LIMITS_V1,
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
        principalId: 'recipient',
      },
      jwk: { namespace: 'keys', principalId: 'issuer', import: BINDING.options },
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'syntax');
      assert.strictEqual(result.category, 'malformed_input');
    }
  });

  test('rejects a container binding that does not match its declared type', async () => {
    const wrapping = wrappingKeys();
    const result = await decryptKeyContainer('unused', {
      type: 'jwk+json',
      limits: LIMITS_V1,
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
        principalId: 'recipient',
      },
      jwks: { namespace: 'keys', bindings: [] },
    });

    assert.deepStrictEqual(result, {
      ok: false,
      stage: 'configuration',
      category: 'policy_violation',
      reason: 'key_container_binding_mismatch',
    });
  });

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

  test('decrypts and snapshots a public JWK set', async () => {
    const wrapping = wrappingKeys();
    const publicJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const encrypted = await encryptCompact(new TextEncoder().encode(JSON.stringify({ keys: [publicJwk] })), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: wrapping.encryption }],
      protectedHeader: { cty: 'jwk-set+json' },
      random: systemRandom,
      nonceAllocator: allocator(),
      limits: LIMITS_V1,
    });
    if (!encrypted.ok) {
      throw new Error(encrypted.reason);
    }

    const result = await decryptKeyContainer(encrypted.token, {
      type: 'jwk-set+json',
      limits: LIMITS_V1,
      decryption: {
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
        contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
        recipients: [{ principalId: 'recipient', key: wrapping.decryption }],
        principalId: 'recipient',
      },
      jwks: {
        namespace: 'issuer-keys',
        bindings: [{ principalId: 'issuer', options: { algorithm: 'ES256', operation: 'verify' } }],
      },
    });

    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }
    assert.strictEqual(result.type, 'jwk-set+json');
    assert.strictEqual(result.snapshot.namespace, 'issuer-keys');
    assert.strictEqual(result.snapshot.entries.length, 1);
    assert.strictEqual(result.snapshot.entries[0]!.principalId, 'issuer');
  });

  test('rejects a key set carrying private or symmetric material', async () => {
    // A published verification set must never contain a private component; the
    // check is by member presence, so a private key cannot hide behind its `kty`.
    const privateJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
    const secret = { kty: 'oct', k: Buffer.alloc(32, 3).toString('base64url') };

    for (const entry of [privateJwk, secret]) {
      const { token, wrapping } = await sealed(JSON.stringify({ keys: [entry] }));

      const result = await decryptKeyContainer(token, jwksOptions(wrapping, [BINDING]));

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'invalid_key');
        assert.strictEqual(result.reason, 'public_jwks_contains_private_material');
      }
    }
  });

  test('refuses a binding count that does not match the key set', async () => {
    // Bindings are positional; a mismatch would pair keys with the wrong
    // principal rather than leaving one unbound.
    const publicJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const { token, wrapping } = await sealed(JSON.stringify({ keys: [publicJwk] }));

    const result = await decryptKeyContainer(token, jwksOptions(wrapping, [BINDING, BINDING]));

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'configuration');
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'jwks_binding_count_mismatch');
    }
  });

  test('rejects a key set whose entries are not objects', async () => {
    const { token, wrapping } = await sealed(JSON.stringify({ keys: ['not-an-object'] }));

    const result = await decryptKeyContainer(token, jwksOptions(wrapping, [BINDING]));

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_key');
      assert.strictEqual(result.reason, 'key_entry_not_an_object');
    }
  });

  test('rejects a container with a missing or non-array keys member', async () => {
    for (const document of ['{}', '{"keys":{}}', '{"keys":"a"}']) {
      const { token, wrapping } = await sealed(document);

      const result = await decryptKeyContainer(token, jwksOptions(wrapping, []));

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'invalid_key');
        assert.strictEqual(result.reason, 'keys_missing_or_invalid');
      }
    }
  });

  test('rejects a container whose plaintext is not a JSON object', async () => {
    for (const document of ['[]', '"text"', '42']) {
      const { token, wrapping } = await sealed(document);

      const result = await decryptKeyContainer(token, jwksOptions(wrapping, []));

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'invalid_key');
        assert.strictEqual(result.reason, 'key_container_not_object');
      }
    }
  });

  test('rejects a container whose plaintext is not valid JSON', async () => {
    const { token, wrapping } = await sealed('{"keys":[');

    const result = await decryptKeyContainer(token, jwksOptions(wrapping, []));

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'claims_syntax');
      assert.strictEqual(result.reason, 'key_container_invalid_json');
    }
  });

  test('reports a key that fails snapshot construction', async () => {
    // The entry is a well-formed public JWK, but its curve cannot serve the
    // algorithm the binding names.
    const publicJwk = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'jwk' });
    const { token, wrapping } = await sealed(JSON.stringify({ keys: [publicJwk] }));

    const result = await decryptKeyContainer(token, jwksOptions(wrapping, [BINDING]));

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'claims_semantics');
    }
  });

  test('accepts an omitted content type only when the transport bound it', async () => {
    const publicJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const wrapping = wrappingKeys();
    const encrypted = await encryptCompact(new TextEncoder().encode(JSON.stringify({ keys: [publicJwk] })), {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
      contentAlgorithm: 'A128GCM',
      recipients: [{ key: wrapping.encryption }],
      random: systemRandom,
      nonceAllocator: allocator(),
      limits: LIMITS_V1,
    });
    if (!encrypted.ok) {
      throw new Error(encrypted.reason);
    }

    const unbound = await decryptKeyContainer(encrypted.token, jwksOptions(wrapping, [BINDING]));
    assert.strictEqual(unbound.ok, false);
    if (!unbound.ok) {
      assert.strictEqual(unbound.reason, 'key_container_cty_required');
    }

    const bound = await decryptKeyContainer(encrypted.token, {
      ...jwksOptions(wrapping, [BINDING]),
      contentTypeExternallyBound: true,
    });
    assert.strictEqual(bound.ok, true);
  });
});
