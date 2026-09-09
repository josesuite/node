import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import {
  exportEcPublicJwk,
  exportOctPublicJwk,
  exportOkpPublicJwk,
  exportRsaPublicJwk,
} from '../../../src/jwk/export.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { validateEcMaterial, validateOkpMaterial, validateRsaPublic } from '../../../src/key/validation.ts';
import { deriveEcPublicPoint, deriveOkpPublicKey, validateEcPointOnCurve } from '../../../src/internal/crypto/node.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

/** Members that must never appear in an exported public key. */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'];

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function expectNoPrivateMembers(exported: Readonly<Record<string, string>>): void {
  for (const member of PRIVATE_MEMBERS) {
    assert.strictEqual(Object.hasOwn(exported, member), false);
  }
}

describe('RSA public export', () => {
  const jwk = generateKeyPairSync('rsa', { modulusLength: 3072 }).privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;

  const material = (() => {
    const result = validateRsaPublic(object(jwk), { receiveOnly: false });
    if (!result.ok) {
      throw new Error('fixture');
    }
    return result.material;
  })();

  test('emits only the public members', () => {
    const exported = exportRsaPublicJwk(material);
    assert.deepStrictEqual(Object.keys(exported).toSorted(), ['e', 'kty', 'n']);
    assert.strictEqual(exported['kty'], 'RSA');
    expectNoPrivateMembers(exported);
  });

  test('preserves the public values exactly', () => {
    const exported = exportRsaPublicJwk(material);
    assert.strictEqual(exported['n'], jwk['n']!);
    assert.strictEqual(exported['e'], jwk['e']!);
  });

  test('does not carry CRT parameters through from the source key', () => {
    // A copy-and-delete implementation would leak these; reconstruction cannot.
    const exported = exportRsaPublicJwk(material);
    for (const crt of ['p', 'q', 'dp', 'dq', 'qi']) {
      assert.notStrictEqual(jwk[crt], undefined);
      assert.strictEqual(Object.hasOwn(exported, crt), false);
    }
  });
});

describe('EC public export', () => {
  const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;

  const material = (() => {
    const result = validateEcMaterial(object(jwk), 'P-256', deriveEcPublicPoint, validateEcPointOnCurve);
    if (!result.ok) {
      throw new Error('fixture');
    }
    return result.material;
  })();

  test('emits only the public members', () => {
    const exported = exportEcPublicJwk(material);
    assert.deepStrictEqual(Object.keys(exported).toSorted(), ['crv', 'kty', 'x', 'y']);
    expectNoPrivateMembers(exported);
    assert.strictEqual(exported['x'], jwk['x']!);
    assert.strictEqual(exported['y'], jwk['y']!);
  });

  test('round trips back through validation', () => {
    const exported = exportEcPublicJwk(material);
    const revalidated = validateEcMaterial(object(exported), 'P-256', deriveEcPublicPoint, validateEcPointOnCurve);
    assert.strictEqual(revalidated.ok, true);
    if (revalidated.ok) {
      assert.strictEqual(revalidated.material.d, undefined);
    }
  });
});

describe('OKP public export', () => {
  const jwk = generateKeyPairSync('x25519').privateKey.export({ format: 'jwk' }) as unknown as Record<string, string>;

  const material = (() => {
    const result = validateOkpMaterial(object(jwk), 'X25519', deriveOkpPublicKey, () => 'validator_unavailable');
    if (!result.ok) {
      throw new Error('fixture');
    }
    return result.material;
  })();

  test('emits only the public members', () => {
    const exported = exportOkpPublicJwk(material);
    assert.deepStrictEqual(Object.keys(exported).toSorted(), ['crv', 'kty', 'x']);
    expectNoPrivateMembers(exported);
    assert.strictEqual(exported['x'], jwk['x']!);
  });
});

describe('metadata handling', () => {
  const material = (() => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
      format: 'jwk',
    }) as unknown as Record<string, string>;
    const result = validateEcMaterial(object(jwk), 'P-256', deriveEcPublicPoint, validateEcPointOnCurve);
    if (!result.ok) {
      throw new Error('fixture');
    }
    return result.material;
  })();

  test('includes only the metadata explicitly supplied', () => {
    const exported = exportEcPublicJwk(material, { kid: 'key-1', alg: 'ES256', use: 'sig' });
    assert.strictEqual(exported['kid'], 'key-1');
    assert.strictEqual(exported['alg'], 'ES256');
    assert.strictEqual(exported['use'], 'sig');
  });

  test('omits absent metadata rather than emitting undefined', () => {
    const exported = exportEcPublicJwk(material, { kid: 'key-1' });
    assert.strictEqual(Object.hasOwn(exported, 'alg'), false);
    assert.strictEqual(Object.hasOwn(exported, 'use'), false);
  });

  test('does not copy unexpected properties from the metadata object', () => {
    const hostile = { kid: 'key-1', d: 'leaked', 'x-vendor': 'v' } as Record<string, string>;
    const exported = exportEcPublicJwk(material, hostile);
    assert.strictEqual(Object.hasOwn(exported, 'd'), false);
    assert.strictEqual(Object.hasOwn(exported, 'x-vendor'), false);
  });

  test('returns a frozen object so a caller cannot add members to it', () => {
    const exported = exportEcPublicJwk(material);
    assert.strictEqual(Object.isFrozen(exported), true);
  });
});

describe('symmetric keys', () => {
  test('have no public representation', () => {
    // Every octet of a symmetric key is secret, so there is nothing publishable
    // and an empty or partial object would be misleading.
    assert.throws(() => exportOctPublicJwk(), TypeError);
  });
});
