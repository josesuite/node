import { describe, expect, test } from 'bun:test';

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
    expect(result.use).toBeUndefined();
    expect(result.keyOps).toBeUndefined();
    expect(result.alg).toBeUndefined();
    expect(result.kid).toBeUndefined();
  });

  test('reads well-formed metadata', () => {
    const result = metadata({
      kty: 'EC',
      use: 'sig',
      key_ops: ['sign', 'verify'],
      alg: 'ES256',
      kid: 'key-1',
    });
    expect(result.use).toBe('sig');
    expect([...result.keyOps!]).toEqual(['sign', 'verify']);
    expect(result.alg).toBe('ES256');
    expect(result.kid).toBe('key-1');
  });

  test('distinguishes an absent key_ops from a present empty one', () => {
    // An empty array is a deliberate statement that no operation is permitted,
    // which is not the same as saying nothing about operations at all.
    expect(metadata({ kty: 'oct' }).keyOps).toBeUndefined();
    expect(metadata({ kty: 'oct', key_ops: [] }).keyOps?.size).toBe(0);
  });

  test('ignores unrecognized members rather than treating them as options', () => {
    const result = metadata({ kty: 'oct', 'x-vendor': { anything: true }, crit: ['x'] });
    expect(result.alg).toBeUndefined();
  });
});

describe('rejecting malformed metadata', () => {
  test('validates recognized certificate hints without fetching them', () => {
    expect(read({ x5c: [] }).ok).toBe(false);
    expect(read({ x5c: [1] }).ok).toBe(false);
    expect(read({ x5c: ['not base64'] }).ok).toBe(false);
    expect(read({ x5t: 'A'.repeat(26) }).ok).toBe(false);
    expect(read({ 'x5t#S256': 'A'.repeat(42) }).ok).toBe(false);
    expect(read({ x5u: 1 }).ok).toBe(false);
    expect(read({ x5c: ['MAA='], x5t: Buffer.alloc(20).toString('base64url') }).ok).toBe(true);
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
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(reason);
        expect(result.category).toBe('invalid_key');
      }
    }
  });

  test('rejects an unrecognized use rather than ignoring the restriction', () => {
    const result = read({ kty: 'oct', use: 'signing' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('use_unrecognized');
    }
  });

  test('rejects unrecognized and duplicate operations', () => {
    const unknown = read({ kty: 'oct', key_ops: ['deriveBits'] });
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) {
      expect(unknown.reason).toBe('key_ops_unrecognized');
    }

    const duplicate = read({ kty: 'oct', key_ops: ['sign', 'sign'] });
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) {
      expect(duplicate.reason).toBe('key_ops_duplicate');
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
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('use_and_key_ops_conflict');
        expect(result.category).toBe('invalid_key');
      }
    }
  });

  test('accepts consistent use and key_ops combinations', () => {
    expect(read({ kty: 'oct', use: 'sig', key_ops: ['sign', 'verify'] }).ok).toBe(true);
    expect(read({ kty: 'oct', use: 'enc', key_ops: ['wrapKey', 'unwrapKey'] }).ok).toBe(true);
    expect(read({ kty: 'oct', use: 'enc', key_ops: ['deriveKey'] }).ok).toBe(true);
    // An empty array conflicts with nothing; it simply permits nothing.
    expect(read({ kty: 'oct', use: 'sig', key_ops: [] }).ok).toBe(true);
  });

  test('bounds identifier lengths', () => {
    const longAlg = read({ kty: 'oct', alg: 'A'.repeat(65) });
    expect(longAlg.ok).toBe(false);
    if (!longAlg.ok) {
      expect(longAlg.category).toBe('resource_limit');
    }

    const longKid = read({ kty: 'oct', kid: 'k'.repeat(257) });
    expect(longKid.ok).toBe(false);
    if (!longKid.ok) {
      expect(longKid.category).toBe('resource_limit');
    }

    expect(read({ kty: 'oct', alg: 'A'.repeat(64), kid: 'k'.repeat(256) }).ok).toBe(true);
  });
});

describe('binding metadata to trusted configuration', () => {
  test('accepts a key whose metadata agrees with the binding', () => {
    const result = checkBinding(
      metadata({ kty: 'EC', alg: 'ES256', use: 'sig', key_ops: ['verify'] }),
      'ES256',
      'verify',
    );
    expect(result.ok).toBe(true);
  });

  test('absent metadata neither grants nor blocks permission', () => {
    // The trusted binding alone decides; silence is not permission, but it is
    // also not a restriction the key itself imposes.
    expect(checkBinding(metadata({ kty: 'oct' }), 'HS256', 'verify').ok).toBe(true);
  });

  test('rejects a key whose alg disagrees with the binding', () => {
    const result = checkBinding(metadata({ kty: 'EC', alg: 'ES384' }), 'ES256', 'verify');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('alg_binding_mismatch');
    }
  });

  test('rejects an operation the key does not permit', () => {
    const result = checkBinding(metadata({ kty: 'EC', key_ops: ['verify'] }), 'ES256', 'sign');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('operation_not_permitted');
    }
  });

  test('rejects an operation incompatible with the declared use', () => {
    const result = checkBinding(metadata({ kty: 'oct', use: 'enc' }), 'HS256', 'sign');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('use_not_compatible');
    }
  });

  test('an empty key_ops permits no operation at all', () => {
    for (const operation of ['sign', 'verify', 'encrypt', 'decrypt'] as const) {
      const result = checkBinding(metadata({ kty: 'oct', key_ops: [] }), 'HS256', operation satisfies KeyOperation);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('operation_not_permitted');
      }
    }
  });

  test('metadata narrows but never widens the trusted binding', () => {
    // Even though the key advertises both operations, asking for one outside
    // the configured binding still fails on the algorithm check.
    const both = metadata({ kty: 'oct', key_ops: ['sign', 'verify'], alg: 'HS256' });
    expect(checkBinding(both, 'HS256', 'sign').ok).toBe(true);
    expect(checkBinding(both, 'HS512', 'sign').ok).toBe(false);
  });
});
