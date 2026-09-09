import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { deriveEcPublicPoint, deriveOkpPublicKey } from '../../../src/internal/crypto/node.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { validateEcMaterial, validateOkpMaterial } from '../../../src/key/validation.ts';
import type { EcCurve, OkpCurve } from '../../../src/key/types.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';
import { availableCurves } from '../../helpers/runtime.ts';
import { validateEcPointOnCurve } from '../../../src/internal/crypto/node.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function ecJwk(curve: string): Record<string, string> {
  return generateKeyPairSync('ec', { namedCurve: curve }).privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;
}

function okpJwk(curve: string): Record<string, string> {
  return generateKeyPairSync(curve.toLowerCase() as 'ed25519').privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;
}

function validateEc(jwk: Record<string, unknown>, curve: EcCurve) {
  return validateEcMaterial(object(jwk), curve, deriveEcPublicPoint, validateEcPointOnCurve);
}

function validateOkp(jwk: Record<string, unknown>, curve: OkpCurve) {
  return validateOkpMaterial(object(jwk), curve, deriveOkpPublicKey, () => 'validator_unavailable');
}

const EC_CURVES = availableCurves(['P-256', 'P-384', 'P-521', 'secp256k1']) as readonly EcCurve[];
const OKP_CURVES = availableCurves(['X25519', 'X448']) as readonly OkpCurve[];

describe('EC key material', () => {
  test('accepts a valid public and private key on each available curve', () => {
    for (const curve of EC_CURVES) {
      const jwk = ecJwk(curve);
      assert.strictEqual(validateEc(jwk, curve).ok, true);

      const { d: _d, ...publicOnly } = jwk;
      const result = validateEc(publicOnly, curve);
      assert.strictEqual(result.ok, true);
      if (result.ok) {
        assert.strictEqual(result.material.d, undefined);
      }
    }
  });

  test('rejects a private key whose public point does not match the scalar', () => {
    // The provider imports this pairing without complaint, so the check has to
    // happen here.
    const a = ecJwk('P-256');
    const b = ecJwk('P-256');
    const result = validateEc({ ...a, x: b['x']!, y: b['y']! }, 'P-256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'public_private_mismatch');
    }
  });

  test('rejects coordinates that are not on the curve', () => {
    const jwk = ecJwk('P-256');
    const offCurve = Buffer.alloc(32, 9).toString('base64url');
    const result = validateEc({ kty: 'EC', crv: 'P-256', x: offCurve, y: offCurve }, 'P-256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'point_not_on_curve');
    }
    // The genuine key on the same curve still passes.
    assert.strictEqual(validateEc(jwk, 'P-256').ok, true);
  });

  test('requires exact coordinate widths and does not accept stripped padding', () => {
    const jwk = ecJwk('P-256');
    const stripped = Buffer.from(jwk['x']!, 'base64url').subarray(1).toString('base64url');
    const result = validateEc({ ...jwk, x: stripped }, 'P-256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'x_wrong_length');
    }
  });

  test('rejects an out-of-range private scalar', () => {
    const jwk = ecJwk('P-256');
    const zero = Buffer.alloc(32).toString('base64url');
    const result = validateEc({ ...jwk, d: zero }, 'P-256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'private_scalar_invalid');
    }
  });

  test('rejects a key whose coordinates belong to a different curve', () => {
    if (!EC_CURVES.includes('P-384')) {
      return;
    }
    const p384 = ecJwk('P-384');
    // P-384 coordinates are the wrong width for P-256, caught before any
    // curve arithmetic runs.
    const result = validateEc(p384, 'P-256');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'x_wrong_length');
    }
  });

  test('rejects missing and malformed members', () => {
    const jwk = ecJwk('P-256');
    const { x: _x, ...withoutX } = jwk;
    assert.strictEqual(validateEc(withoutX, 'P-256').ok, false);

    const padded = validateEc({ ...jwk, y: `${jwk['y']!}=` }, 'P-256');
    assert.strictEqual(padded.ok, false);
    if (!padded.ok) {
      assert.strictEqual(padded.category, 'invalid_encoding');
    }
  });
});

describe('OKP key material', () => {
  test('accepts valid public and private keys on each available curve', () => {
    for (const curve of OKP_CURVES) {
      const jwk = okpJwk(curve);
      assert.strictEqual(validateOkp(jwk, curve).ok, true);

      const { d: _d, ...publicOnly } = jwk;
      assert.strictEqual(validateOkp(publicOnly, curve).ok, true);
    }
  });

  test('rejects a private key whose public component does not match', () => {
    for (const curve of OKP_CURVES) {
      const a = okpJwk(curve);
      const b = okpJwk(curve);
      const result = validateOkp({ ...a, x: b['x']! }, curve);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'public_private_mismatch');
      }
    }
  });

  test('applies point validation only to the signing curve it is defined for', () => {
    // An X25519 public value is an agreement input, not an Edwards point, so
    // the Ed25519 checks must not be applied to it.
    if (!OKP_CURVES.includes('X25519')) {
      return;
    }
    const jwk = okpJwk('X25519');
    assert.strictEqual(validateOkp(jwk, 'X25519').ok, true);
  });

  test('requires exact key lengths', () => {
    const jwk = okpJwk('X25519');
    const short = Buffer.from(jwk['x']!, 'base64url').subarray(1).toString('base64url');
    const result = validateOkp({ ...jwk, x: short }, 'X25519');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'x_wrong_length');
    }

    const shortD = Buffer.from(jwk['d']!, 'base64url').subarray(1).toString('base64url');
    const dResult = validateOkp({ ...jwk, d: shortD }, 'X25519');
    assert.strictEqual(dResult.ok, false);
    if (!dResult.ok) {
      assert.strictEqual(dResult.reason, 'd_wrong_length');
    }
  });

  test("rejects a non-canonical X25519 public alias as a private key's projection", () => {
    if (!OKP_CURVES.includes('X25519')) {
      return;
    }
    const jwk = okpJwk('X25519');
    const alias = Buffer.from(jwk['x']!, 'base64url');
    // The high bit is ignored when processing a peer's value, so this alias is
    // an equivalent public value; as a private key's stated projection it must
    // still be rejected, so one private key has exactly one identity.
    alias[31] = alias[31]! | 0x80;

    const result = validateOkp({ ...jwk, x: alias.toString('base64url') }, 'X25519');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'public_private_mismatch');
    }
  });
});
