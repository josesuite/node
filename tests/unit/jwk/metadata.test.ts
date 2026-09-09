import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { checkBinding, readKeyMetadata } from '../../../src/key/operations.ts';
import type { KeyOperation } from '../../../src/key/types.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function read(value: Record<string, unknown>) {
  return readKeyMetadata(object(value));
}

function metadata(value: Record<string, unknown>) {
  const result = read(value);
  if (!result.ok) {
    throw new Error(`expected success, got ${result.reason}`);
  }
  return result.metadata;
}

describe('reading optional metadata', () => {
  test('treats every member as optional', () => {
    const result = metadata({ kty: 'oct' });
    assert.strictEqual(result.use, undefined);
    assert.strictEqual(result.keyOps, undefined);
    assert.strictEqual(result.alg, undefined);
    assert.strictEqual(result.kid, undefined);
  });

  test('reads well-formed metadata', () => {
    const result = metadata({
      kty: 'EC',
      use: 'sig',
      key_ops: ['sign', 'verify'],
      alg: 'ES256',
      kid: 'key-1',
    });
    assert.strictEqual(result.use, 'sig');
    assert.deepStrictEqual([...result.keyOps!], ['sign', 'verify']);
    assert.strictEqual(result.alg, 'ES256');
    assert.strictEqual(result.kid, 'key-1');
  });

  test('distinguishes an absent key_ops from a present empty one', () => {
    // An empty array is a deliberate statement that no operation is permitted,
    // which is not the same as saying nothing about operations at all.
    assert.strictEqual(metadata({ kty: 'oct' }).keyOps, undefined);
    assert.strictEqual(metadata({ kty: 'oct', key_ops: [] }).keyOps?.size, 0);
  });

  test('ignores unrecognized members rather than treating them as options', () => {
    const result = metadata({ kty: 'oct', 'x-vendor': { anything: true }, crit: ['x'] });
    assert.strictEqual(result.alg, undefined);
  });
});

describe('rejecting malformed metadata', () => {
  test('validates recognized certificate hints without fetching them', () => {
    assert.strictEqual(read({ x5c: [] }).ok, false);
    assert.strictEqual(read({ x5c: [1] }).ok, false);
    assert.strictEqual(read({ x5c: ['not base64'] }).ok, false);
    assert.strictEqual(read({ x5t: 'A'.repeat(26) }).ok, false);
    assert.strictEqual(read({ 'x5t#S256': 'A'.repeat(42) }).ok, false);
    assert.strictEqual(read({ x5u: 1 }).ok, false);
    assert.strictEqual(read({ x5c: ['MAA='], x5t: Buffer.alloc(20).toString('base64url') }).ok, true);
  });
  test('rejects wrong types', () => {
    const cases: readonly [Record<string, unknown>, string][] = [
      [{ kty: 'oct', use: 1 }, 'use_not_a_string'],
      [{ kty: 'oct', key_ops: 'sign' }, 'key_ops_not_an_array'],
      [{ kty: 'oct', key_ops: [1] }, 'key_ops_entry_not_a_string'],
      [{ kty: 'oct', alg: [] }, 'alg_not_a_string'],
      [{ kty: 'oct', kid: 5 }, 'kid_not_a_string'],
    ];

    for (const [jwk, reason] of cases) {
      const result = read(jwk);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, reason);
        assert.strictEqual(result.category, 'invalid_key');
      }
    }
  });

  test('rejects an unrecognized use rather than ignoring the restriction', () => {
    const result = read({ kty: 'oct', use: 'signing' });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'use_unrecognized');
    }
  });

  test('rejects unrecognized and duplicate operations', () => {
    const unknown = read({ kty: 'oct', key_ops: ['deriveBits'] });
    assert.strictEqual(unknown.ok, false);
    if (!unknown.ok) {
      assert.strictEqual(unknown.reason, 'key_ops_unrecognized');
    }

    const duplicate = read({ kty: 'oct', key_ops: ['sign', 'sign'] });
    assert.strictEqual(duplicate.ok, false);
    if (!duplicate.ok) {
      assert.strictEqual(duplicate.reason, 'key_ops_duplicate');
    }
  });

  test('rejects mixed signing and encryption purposes at import', () => {
    // A key that contradicts itself about its own purpose is never admitted,
    // rather than admitted and refused per operation later.
    const conflicts: readonly Record<string, unknown>[] = [
      { kty: 'oct', use: 'sig', key_ops: ['encrypt'] },
      { kty: 'oct', use: 'sig', key_ops: ['wrapKey'] },
      { kty: 'oct', use: 'sig', key_ops: ['deriveKey'] },
      { kty: 'oct', use: 'enc', key_ops: ['sign'] },
      { kty: 'oct', use: 'enc', key_ops: ['verify'] },
      { kty: 'oct', use: 'sig', key_ops: ['sign', 'decrypt'] },
    ];

    for (const jwk of conflicts) {
      const result = read(jwk);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'use_and_key_ops_conflict');
        assert.strictEqual(result.category, 'invalid_key');
      }
    }
  });

  test('accepts consistent use and key_ops combinations', () => {
    assert.strictEqual(read({ kty: 'oct', use: 'sig', key_ops: ['sign', 'verify'] }).ok, true);
    assert.strictEqual(read({ kty: 'oct', use: 'enc', key_ops: ['wrapKey', 'unwrapKey'] }).ok, true);
    assert.strictEqual(read({ kty: 'oct', use: 'enc', key_ops: ['deriveKey'] }).ok, true);
    // An empty array conflicts with nothing; it simply permits nothing.
    assert.strictEqual(read({ kty: 'oct', use: 'sig', key_ops: [] }).ok, true);
  });

  test('bounds identifier lengths', () => {
    const longAlg = read({ kty: 'oct', alg: 'A'.repeat(65) });
    assert.strictEqual(longAlg.ok, false);
    if (!longAlg.ok) {
      assert.strictEqual(longAlg.category, 'resource_limit');
    }

    const longKid = read({ kty: 'oct', kid: 'k'.repeat(257) });
    assert.strictEqual(longKid.ok, false);
    if (!longKid.ok) {
      assert.strictEqual(longKid.category, 'resource_limit');
    }

    assert.strictEqual(read({ kty: 'oct', alg: 'A'.repeat(64), kid: 'k'.repeat(256) }).ok, true);
  });
});

describe('binding metadata to trusted configuration', () => {
  test('accepts a key whose metadata agrees with the binding', () => {
    const result = checkBinding(
      metadata({ kty: 'EC', alg: 'ES256', use: 'sig', key_ops: ['verify'] }),
      'ES256',
      'verify',
    );
    assert.strictEqual(result.ok, true);
  });

  test('absent metadata neither grants nor blocks permission', () => {
    // The trusted binding alone decides; silence is not permission, but it is
    // also not a restriction the key itself imposes.
    assert.strictEqual(checkBinding(metadata({ kty: 'oct' }), 'HS256', 'verify').ok, true);
  });

  test('rejects a key whose alg disagrees with the binding', () => {
    const result = checkBinding(metadata({ kty: 'EC', alg: 'ES384' }), 'ES256', 'verify');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'alg_binding_mismatch');
    }
  });

  test('rejects an operation the key does not permit', () => {
    const result = checkBinding(metadata({ kty: 'EC', key_ops: ['verify'] }), 'ES256', 'sign');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'operation_not_permitted');
    }
  });

  test('rejects an operation incompatible with the declared use', () => {
    const result = checkBinding(metadata({ kty: 'oct', use: 'enc' }), 'HS256', 'sign');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'use_not_compatible');
    }
  });

  test('an empty key_ops permits no operation at all', () => {
    for (const operation of ['sign', 'verify', 'encrypt', 'decrypt'] as const) {
      const result = checkBinding(metadata({ kty: 'oct', key_ops: [] }), 'HS256', operation satisfies KeyOperation);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'operation_not_permitted');
      }
    }
  });

  test('metadata narrows but never widens the trusted binding', () => {
    // Even though the key advertises both operations, asking for one outside
    // the configured binding still fails on the algorithm check.
    const both = metadata({ kty: 'oct', key_ops: ['sign', 'verify'], alg: 'HS256' });
    assert.strictEqual(checkBinding(both, 'HS256', 'sign').ok, true);
    assert.strictEqual(checkBinding(both, 'HS512', 'sign').ok, false);
  });
});
