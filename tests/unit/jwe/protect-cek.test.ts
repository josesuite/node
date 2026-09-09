import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { GCMKW_IV_BYTES } from '../../../src/algorithms/jwe/aes-gcm-kw.ts';
import type { BackendResult, RandomSource } from '../../../src/internal/crypto/backend.ts';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { encodeBase64url } from '../../../src/internal/encoding/base64url.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { protectCek } from '../../../src/jwe/protect-cek.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';
import { supportsCurve } from '../../helpers/runtime.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function key(
  jwk: Record<string, unknown>,
  algorithm: string,
  operation: 'wrapKey' | 'deriveKey' | 'encrypt',
): UsableKey {
  const result = importKey(object(jwk), {
    algorithm,
    operation,
    // `dir` binds the key to exactly one content algorithm; the wrapping modes
    // may protect any of them.
    contentAlgorithms: algorithm === 'dir' ? ['A128GCM'] : ['A128GCM', 'A128CBC-HS256'],
  });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

function octKey(bytes: number, algorithm: string, operation: 'wrapKey' | 'encrypt' = 'wrapKey'): UsableKey {
  return key({ kty: 'oct', k: encodeBase64url(new Uint8Array(randomBytes(bytes))) }, algorithm, operation);
}

/** A CSPRNG stand-in, so exhaustion and short reads are reachable deterministically. */
function stubRandom(behaviour: () => BackendResult<Uint8Array>): RandomSource {
  return { randomBytes: behaviour };
}

describe('CEK protection guards', () => {
  test('refuses an empty recipient set', async () => {
    const result = await protectCek('A128GCM', 16, [], systemRandom);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'no_recipients');
    }
  });

  test('refuses a record that key import did not produce', async () => {
    // A hand-assembled record carries no validated material; dispatching on it
    // would use whatever the caller happened to put in `material`.
    const forged = {
      keyType: 'oct',
      algorithm: 'A128KW',
      operation: 'wrapKey',
      material: new Uint8Array(16),
    } as unknown as UsableKey;

    const result = await protectCek('A128GCM', 16, [{ key: forged }], systemRandom);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
      assert.strictEqual(result.reason, 'key_not_imported');
    }
  });

  test('binds a direct-mode key only at the size its content algorithm requires', () => {
    // Padding or truncating would let one configured key serve several `enc`
    // values. Import refuses the mismatch, so protection never sees one.
    const oversized = importKey(object({ kty: 'oct', k: encodeBase64url(new Uint8Array(randomBytes(32))) }), {
      algorithm: 'dir',
      operation: 'encrypt',
      contentAlgorithms: ['A128GCM'],
    });

    assert.strictEqual(oversized.ok, false);
    if (!oversized.ok) {
      assert.strictEqual(oversized.reason, 'direct_key_size_mismatch');
    }
  });

  test('refuses a content algorithm the direct mode does not recognize', async () => {
    // The key is bound to a real `enc`, but protection is asked for another
    // one; the CEK must not be handed over for an algorithm it was not sized for.
    const result = await protectCek('A128CBC', 16, [{ key: octKey(16, 'dir', 'encrypt') }], systemRandom);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_algorithm');
      assert.strictEqual(result.reason, 'unsupported_content_algorithm');
    }
  });

  test('returns the configured key without claiming ownership in direct mode', async () => {
    // The CEK belongs to the caller's configuration here, so the encrypt path
    // must not clear it as if this call had generated it.
    const result = await protectCek('A128GCM', 16, [{ key: octKey(16, 'dir', 'encrypt') }], systemRandom);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.ownsCek, false);
      assert.strictEqual(result.cek.length, 16);
      assert.deepStrictEqual(result.recipients, [
        { encryptedKey: undefined, ephemeralPublicKey: undefined, gcmKw: undefined },
      ]);
    }
  });

  test('treats a failed CSPRNG read as a backend failure', async () => {
    const result = await protectCek(
      'A128GCM',
      16,
      [{ key: octKey(16, 'A128KW') }],
      stubRandom(() => ({ ok: false, failure: 'operation_failed' })),
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
      assert.strictEqual(result.reason, 'randomness_unavailable');
    }
  });

  test('treats a throwing CSPRNG as a backend failure', async () => {
    const result = await protectCek(
      'A128GCM',
      16,
      [{ key: octKey(16, 'A128KW') }],
      stubRandom(() => {
        throw new Error('entropy pool unavailable');
      }),
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
      assert.strictEqual(result.reason, 'randomness_unavailable');
    }
  });

  test('refuses a CSPRNG that returns fewer bytes than the CEK needs', async () => {
    // A short read must never be padded into a full-size CEK: the shortfall
    // would be predictable zero bytes.
    const result = await protectCek(
      'A128GCM',
      16,
      [{ key: octKey(16, 'A128KW') }],
      stubRandom(() => ({ ok: true, value: new Uint8Array(8) })),
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'backend_failure');
      assert.strictEqual(result.reason, 'randomness_unavailable');
    }
  });

  test('requires a wrapping nonce of the exact size for GCM key wrapping', async () => {
    // The wrapping key has its own nonce budget, separate from the content
    // key's; a missing or wrong-width IV must not be silently substituted.
    const gcmKey = octKey(16, 'A128GCMKW');

    for (const nonces of [[], [new Uint8Array(GCMKW_IV_BYTES - 1)], [new Uint8Array(GCMKW_IV_BYTES + 1)]]) {
      const result = await protectCek('A128GCM', 16, [{ key: gcmKey }], systemRandom, nonces);

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'policy_violation');
        assert.strictEqual(result.reason, 'wrapping_nonce_required');
      }
    }
  });

  test('refuses to bind a password-derived key for creation', () => {
    // Receive-only: creation would rest the object's security on password
    // strength without a reviewed policy or a fresh random salt. Import is the
    // reachable enforcement point, so protection's own guard is defence in depth.
    const result = importKey(object({ kty: 'oct', k: encodeBase64url(new Uint8Array(randomBytes(16))) }), {
      algorithm: 'PBES2-HS256+A128KW',
      operation: 'wrapKey',
      contentAlgorithms: ['A128GCM'],
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'algorithm_receive_only');
    }
  });

  test('rejects a mismatched key type at import, before protection can dispatch', () => {
    // The per-mode key-type guards inside protection are defence in depth. The
    // reachable enforcement point is import, which is what these assertions
    // pin: a key bound to a mode its type cannot serve never exists.
    const symmetric = { kty: 'oct', k: encodeBase64url(new Uint8Array(randomBytes(16))) };
    const mismatches: readonly (readonly [string, 'wrapKey' | 'deriveKey' | 'encrypt'])[] = [
      ['RSA-OAEP-256', 'wrapKey'],
      ['ECDH-ES', 'deriveKey'],
      ['ECDH-ES+A128KW', 'deriveKey'],
    ];

    for (const [algorithm, operation] of mismatches) {
      const result = importKey(object(symmetric), { algorithm, operation, contentAlgorithms: ['A128GCM'] });

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'incompatible_key');
        assert.strictEqual(result.reason, 'key_type_not_eligible_for_algorithm');
      }
    }
  });

  test('refuses a signing curve for agreement', async () => {
    // secp256k1 is an EC key, so it satisfies the key-type check and does bind
    // to ECDH-ES at import. Agreement itself is what rejects the curve, so this
    // guard carries the whole separation between signing and agreement use.
    if (!supportsCurve('secp256k1')) {
      return;
    }
    const pair = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const jwk = pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const imported = importKey(object(jwk), {
      algorithm: 'ECDH-ES',
      operation: 'deriveKey',
      contentAlgorithms: ['A128GCM'],
    });
    assert.strictEqual(imported.ok, true);
    if (!imported.ok) {
      return;
    }

    const result = await protectCek('A128GCM', 16, [{ key: imported.key }], systemRandom);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
      assert.strictEqual(result.reason, 'curve_not_usable_for_agreement');
    }
  });

  test('gives each recipient its own encrypted key under a shared CEK', async () => {
    const first = octKey(16, 'A128KW');
    const second = octKey(16, 'A128KW');

    const result = await protectCek('A128GCM', 16, [{ key: first }, { key: second }], systemRandom);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.ownsCek, true);
      assert.strictEqual(result.recipients.length, 2);
      const [a, b] = result.recipients;
      assert.notStrictEqual(a!.encryptedKey, undefined);
      assert.notStrictEqual(b!.encryptedKey, undefined);
      // Distinct wrapping keys must not produce the same wrapped bytes.
      assert.notDeepStrictEqual(a!.encryptedKey, b!.encryptedKey);
    }
  });

  test('protects a CEK with RSA transport and GCM key wrapping', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 3072 }).publicKey.export({ format: 'jwk' });
    const transport = await protectCek(
      'A128GCM',
      16,
      [{ key: key(rsa as Record<string, unknown>, 'RSA-OAEP-256', 'wrapKey') }],
      systemRandom,
    );
    assert.strictEqual(transport.ok, true);
    if (transport.ok) {
      assert.strictEqual(transport.recipients[0]!.encryptedKey!.length, 384);
    }

    const nonce = new Uint8Array(GCMKW_IV_BYTES).fill(1);
    const wrapped = await protectCek('A128GCM', 16, [{ key: octKey(16, 'A128GCMKW') }], systemRandom, [nonce]);
    assert.strictEqual(wrapped.ok, true);
    if (wrapped.ok) {
      assert.deepStrictEqual(wrapped.recipients[0]!.gcmKw!.iv, nonce);
      assert.strictEqual(wrapped.recipients[0]!.gcmKw!.tag.length, 16);
    }
  });

  test('derives direct and wrapping keys through ECDH', async () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicJwk = pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;

    const direct = await protectCek('A128GCM', 16, [{ key: key(publicJwk, 'ECDH-ES', 'deriveKey') }], systemRandom);
    assert.strictEqual(direct.ok, true);
    if (direct.ok) {
      assert.strictEqual(direct.cek.length, 16);
      assert.strictEqual(direct.recipients[0]!.ephemeralPublicKey!.kty, 'EC');
      assert.strictEqual(direct.recipients[0]!.encryptedKey, undefined);
    }

    const wrapping = await protectCek(
      'A128GCM',
      16,
      [{ key: key(publicJwk, 'ECDH-ES+A128KW', 'deriveKey') }],
      systemRandom,
    );
    assert.strictEqual(wrapping.ok, true);
    if (wrapping.ok) {
      assert.strictEqual(wrapping.recipients[0]!.encryptedKey!.length, 24);
      assert.strictEqual(wrapping.recipients[0]!.ephemeralPublicKey!.kty, 'EC');
    }
  });
});
