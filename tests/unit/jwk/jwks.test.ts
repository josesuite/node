import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import {
  buildSnapshot,
  buildSnapshotBytes,
  distinctPrincipals,
  readJwksEntries,
  type SnapshotInput,
} from '../../../src/jwk/jwks.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

function object(value: unknown): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function ecJwk(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    format: 'jwk',
  }) as unknown as Record<string, unknown>;
  return { ...jwk, ...extra };
}

function octJwk(bytes: Uint8Array, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { kty: 'oct', k: Buffer.from(bytes).toString('base64url'), ...extra };
}

const VERIFY_EC = { algorithm: 'ES256', operation: 'verify' } as const;
const VERIFY_HS = { algorithm: 'HS256', operation: 'verify' } as const;

function input(
  jwk: Record<string, unknown>,
  principalId: string,
  options: SnapshotInput['options'] = VERIFY_EC,
): SnapshotInput {
  return { jwk: object(jwk), principalId, options };
}

describe('reading a JWK Set container', () => {
  test('accepts a well-formed set', () => {
    const result = readJwksEntries(object({ keys: [ecJwk(), ecJwk()] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.keys).toHaveLength(2);
    }
  });

  test('accepts an empty set that resolves no key', () => {
    const result = readJwksEntries(object({ keys: [] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.keys).toHaveLength(0);
    }
  });

  test('rejects a missing or mistyped keys member', () => {
    const missing = readJwksEntries(object({}));
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.reason).toBe('keys_missing');
    }

    const mistyped = readJwksEntries(object({ keys: {} }));
    expect(mistyped.ok).toBe(false);
    if (!mistyped.ok) {
      expect(mistyped.reason).toBe('keys_not_an_array');
    }
  });

  test('rejects a non-object entry rather than skipping it', () => {
    const result = readJwksEntries(object({ keys: [ecJwk(), 'not-a-key'] }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('key_entry_not_an_object');
    }
  });

  test('ignores unknown members of the container', () => {
    expect(readJwksEntries(object({ keys: [], 'x-vendor': 1 })).ok).toBe(true);
  });

  test('bounds the number of keys', () => {
    const keys = Array.from({ length: LIMITS_V1.jwksKeys + 1 }, () => ({ kty: 'oct', k: 'AA' }));
    const result = readJwksEntries(object({ keys }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
    }
  });
});

describe('snapshot construction', () => {
  test('builds directly from bounded duplicate-rejecting JWKS bytes', () => {
    const result = buildSnapshotBytes(
      'issuer-a',
      new TextEncoder().encode(JSON.stringify({ keys: [ecJwk({ kid: 'raw' })] })),
      [{ principalId: 'party-a', options: VERIFY_EC }],
    );
    expect(result.ok).toBe(true);
    expect(buildSnapshotBytes('issuer-a', new TextEncoder().encode('{"keys":[],"keys":[]}'), []).ok).toBe(false);
  });

  test('applies caller limits throughout raw snapshot construction', () => {
    const result = buildSnapshotBytes(
      'issuer-a',
      new TextEncoder().encode(JSON.stringify({ keys: [ecJwk()] })),
      [{ principalId: 'party-a', options: VERIFY_EC }],
      { ...LIMITS_V1, jwksKeys: 0 },
    );

    expect(result).toEqual({ ok: false, category: 'resource_limit', reason: 'too_many_keys' });
  });

  test('builds a snapshot from valid entries', () => {
    const result = buildSnapshot('issuer-a', [
      input(ecJwk({ kid: 'k1' }), 'signer-a'),
      input(ecJwk({ kid: 'k2' }), 'signer-b'),
    ]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.snapshot.entries).toHaveLength(2);
      expect(result.snapshot.namespace).toBe('issuer-a');
      expect(result.snapshot.entries[0]!.kid).toBe('k1');
      expect([...distinctPrincipals(result.snapshot)].toSorted()).toEqual(['signer-a', 'signer-b']);
    }
  });

  test('accepts keys without an identifier', () => {
    const result = buildSnapshot('issuer-a', [input(ecJwk(), 'signer-a')]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.snapshot.entries[0]!.kid).toBeUndefined();
    }
  });

  test('rejects duplicate identifiers, since order must not break the tie', () => {
    const result = buildSnapshot('issuer-a', [
      input(ecJwk({ kid: 'same' }), 'signer-a'),
      input(ecJwk({ kid: 'same' }), 'signer-b'),
    ]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('duplicate_kid');
      expect(result.index).toBe(1);
    }
  });

  test('publishes nothing when any single entry fails to import', () => {
    // A partly valid set is never installed, so one bad key rejects the whole
    // proposed snapshot rather than yielding a smaller usable one.
    const result = buildSnapshot('issuer-a', [
      input(ecJwk(), 'signer-a'),
      input({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }, 'signer-b'),
      input(ecJwk(), 'signer-c'),
    ]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.index).toBe(1);
    }
  });

  test('counts one principal once regardless of how many keys it holds', () => {
    // A principal may own rotation keys; that must not inflate a distinct
    // signer count.
    const result = buildSnapshot('issuer-a', [
      input(ecJwk({ kid: 'current' }), 'signer-a'),
      input(ecJwk({ kid: 'previous' }), 'signer-a'),
    ]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(distinctPrincipals(result.snapshot).size).toBe(1);
    }
  });
});

describe('one principal per key', () => {
  test('rejects identical key material bound to two principals', () => {
    // A signature under a shared key would have no determinate signer, so
    // "require signer A" could not be answered.
    const shared = ecJwk();
    const result = buildSnapshot('issuer-a', [
      input({ ...shared, kid: 'a' }, 'signer-a'),
      input({ ...shared, kid: 'b' }, 'signer-b'),
    ]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('shared_key_material_across_principals');
    }
  });

  test('permits identical material under one principal', () => {
    const shared = ecJwk();
    const result = buildSnapshot('issuer-a', [
      input({ ...shared, kid: 'a' }, 'signer-a'),
      input({ ...shared, kid: 'b' }, 'signer-a'),
    ]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(distinctPrincipals(result.snapshot).size).toBe(1);
    }
  });

  test('identifier differences do not make one key into two', () => {
    // Identity is key material, never the label attached to it.
    const shared = ecJwk();
    const result = buildSnapshot('issuer-a', [
      input({ ...shared, kid: 'name-one' }, 'signer-a'),
      input({ ...shared, kid: 'name-two' }, 'signer-b'),
    ]);
    expect(result.ok).toBe(false);
  });

  test('does not treat an operation alias as different key material', () => {
    const shared = octJwk(new Uint8Array(32).fill(1));
    const result = buildSnapshot('issuer-a', [
      input(shared, 'party-a', { algorithm: 'HS256', operation: 'verify' }),
      input(shared, 'party-b', { algorithm: 'HS256', operation: 'sign' }),
    ]);
    expect(result.ok).toBe(false);
  });
});

describe('HMAC authentication-domain distinctness', () => {
  test('rejects equivalent HMAC keys assigned to different principals', () => {
    // These have different secret octets but one authentication capability,
    // so treating them as two domains would overcount independent parties.
    const short = new Uint8Array(32).fill(3);
    const zeroExtended = new Uint8Array(64);
    zeroExtended.set(short);

    const result = buildSnapshot('issuer-a', [
      input(octJwk(short, { kid: 'a' }), 'party-a', VERIFY_HS),
      input(octJwk(zeroExtended, { kid: 'b' }), 'party-b', VERIFY_HS),
    ]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('equivalent_hmac_domains_across_principals');
    }
  });

  test('rejects a long key and its hash across principals', () => {
    const long = new Uint8Array(100).fill(5);
    const hashed = new Uint8Array(createHash('sha256').update(long).digest());

    const result = buildSnapshot('issuer-a', [
      input(octJwk(long, { kid: 'a' }), 'party-a', VERIFY_HS),
      input(octJwk(hashed, { kid: 'b' }), 'party-b', VERIFY_HS),
    ]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('equivalent_hmac_domains_across_principals');
    }
  });

  test('permits equivalent keys mapped to one principal', () => {
    // Aliases of one capability may coexist; they simply count once.
    const short = new Uint8Array(32).fill(3);
    const zeroExtended = new Uint8Array(64);
    zeroExtended.set(short);

    const result = buildSnapshot('issuer-a', [
      input(octJwk(short, { kid: 'a' }), 'party-a', VERIFY_HS),
      input(octJwk(zeroExtended, { kid: 'b' }), 'party-a', VERIFY_HS),
    ]);
    expect(result.ok).toBe(true);
  });

  test('permits genuinely independent HMAC keys', () => {
    const result = buildSnapshot('issuer-a', [
      input(octJwk(new Uint8Array(32).fill(1), { kid: 'a' }), 'party-a', VERIFY_HS),
      input(octJwk(new Uint8Array(32).fill(2), { kid: 'b' }), 'party-b', VERIFY_HS),
    ]);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(distinctPrincipals(result.snapshot).size).toBe(2);
    }
  });

  test('does not apply the equivalence rule across different algorithms', () => {
    // The preprocessing depends on the configured hash, so keys bound to
    // different algorithms are not compared as one domain.
    const short = new Uint8Array(48).fill(4);
    const padded = new Uint8Array(128);
    padded.set(short);

    const result = buildSnapshot('issuer-a', [
      input(octJwk(short, { kid: 'a' }), 'party-a', { algorithm: 'HS256', operation: 'verify' }),
      input(octJwk(padded, { kid: 'b' }), 'party-b', { algorithm: 'HS384', operation: 'verify' }),
    ]);
    expect(result.ok).toBe(true);
  });
});
