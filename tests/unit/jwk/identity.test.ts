import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createHash } from 'node:crypto';

import {
  type KeyIdentity,
  mayIndexByThumbprint,
  representationImpliesHolderIdentity,
  sameHmacDomain,
  sameKeyMaterial,
} from '../../../src/key/identity.ts';

function bytes(...values: number[]): Uint8Array {
  return new Uint8Array(values);
}

const RSA: KeyIdentity = { kty: 'RSA', n: bytes(1, 2, 3), e: bytes(1, 0, 1) };
const EC: KeyIdentity = { kty: 'EC', crv: 'P-256', x: bytes(1), y: bytes(2) };
const OKP: KeyIdentity = { kty: 'OKP', crv: 'Ed25519', x: bytes(1) };
const AKP: KeyIdentity = { kty: 'AKP', alg: 'ML-DSA-44', pub: bytes(1) };
const OCT: KeyIdentity = { kty: 'oct', k: bytes(1, 2, 3, 4) };

describe('key material equality', () => {
  test('equal material compares equal for every key type', () => {
    assert.strictEqual(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2, 3), e: bytes(1, 0, 1) }), true);
    assert.strictEqual(sameKeyMaterial(EC, { kty: 'EC', crv: 'P-256', x: bytes(1), y: bytes(2) }), true);
    assert.strictEqual(sameKeyMaterial(OKP, { kty: 'OKP', crv: 'Ed25519', x: bytes(1) }), true);
    assert.strictEqual(sameKeyMaterial(AKP, { kty: 'AKP', alg: 'ML-DSA-44', pub: bytes(1) }), true);
    assert.strictEqual(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3, 4) }), true);
  });

  test('any differing compared member makes two distinct keys', () => {
    assert.strictEqual(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2, 4), e: bytes(1, 0, 1) }), false);
    assert.strictEqual(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2, 3), e: bytes(3) }), false);
    assert.strictEqual(sameKeyMaterial(EC, { kty: 'EC', crv: 'P-256', x: bytes(9), y: bytes(2) }), false);
    assert.strictEqual(sameKeyMaterial(EC, { kty: 'EC', crv: 'P-256', x: bytes(1), y: bytes(9) }), false);
    assert.strictEqual(sameKeyMaterial(OKP, { kty: 'OKP', crv: 'Ed25519', x: bytes(9) }), false);
    assert.strictEqual(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3, 5) }), false);
  });

  test('different key types are never equal', () => {
    assert.strictEqual(sameKeyMaterial(RSA, EC), false);
    assert.strictEqual(sameKeyMaterial(EC, OKP), false);
    assert.strictEqual(sameKeyMaterial(OKP, AKP), false);
    assert.strictEqual(sameKeyMaterial(OCT, RSA), false);
  });

  test('discriminators compare case-sensitively without alias expansion', () => {
    assert.strictEqual(sameKeyMaterial(EC, { kty: 'EC', crv: 'p-256', x: bytes(1), y: bytes(2) }), false);
    assert.strictEqual(sameKeyMaterial(OKP, { kty: 'OKP', crv: 'ed25519', x: bytes(1) }), false);
  });

  test('post-quantum keys compare their algorithm, which fixes the parameter set', () => {
    // The algorithm determines how the public value is interpreted, so two keys
    // with identical bytes but different parameter sets are different keys.
    assert.strictEqual(sameKeyMaterial(AKP, { kty: 'AKP', alg: 'ML-DSA-65', pub: bytes(1) }), false);
  });

  test('length differences are handled without reading past either value', () => {
    assert.strictEqual(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3) }), false);
    assert.strictEqual(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3, 4, 5) }), false);
    assert.strictEqual(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2), e: bytes(1, 0, 1) }), false);
  });

  test('equality ignores how a key was labelled', () => {
    // Identity is built from the compared members only, so two records that
    // differ in metadata cannot reach this function looking different.
    const a: KeyIdentity = { kty: 'EC', crv: 'P-384', x: bytes(7), y: bytes(8) };
    const b: KeyIdentity = { kty: 'EC', crv: 'P-384', x: bytes(7), y: bytes(8) };
    assert.strictEqual(sameKeyMaterial(a, b), true);
  });
});

describe('representation identity versus holder identity', () => {
  test('agreement curves do not establish holder identity from public bytes', () => {
    // Several publicly computable values produce the same shared secrets, so
    // unequal representations are not proof of distinct holders.
    assert.strictEqual(representationImpliesHolderIdentity({ kty: 'OKP', crv: 'X25519', x: bytes(1) }), false);
    assert.strictEqual(representationImpliesHolderIdentity({ kty: 'OKP', crv: 'X448', x: bytes(1) }), false);
  });

  test('signing and other key types do establish it', () => {
    assert.strictEqual(representationImpliesHolderIdentity(OKP), true);
    assert.strictEqual(representationImpliesHolderIdentity(RSA), true);
    assert.strictEqual(representationImpliesHolderIdentity(EC), true);
    assert.strictEqual(representationImpliesHolderIdentity(OCT), true);
  });
});

describe('thumbprint indexing', () => {
  test('is unavailable for symmetric keys', () => {
    // A symmetric thumbprint is derived from the secret, so publishing or
    // indexing by it would expose secret-derived data.
    assert.strictEqual(mayIndexByThumbprint('oct'), false);
    assert.strictEqual(mayIndexByThumbprint('RSA'), true);
    assert.strictEqual(mayIndexByThumbprint('EC'), true);
    assert.strictEqual(mayIndexByThumbprint('OKP'), true);
    assert.strictEqual(mayIndexByThumbprint('AKP'), true);
  });
});

describe('HMAC authentication-domain equivalence', () => {
  test('identical keys share a domain', () => {
    const key = new Uint8Array(32).fill(7);
    assert.strictEqual(sameHmacDomain(key, new Uint8Array(32).fill(7), 'HS256'), true);
  });

  test('a short key and its zero-extended alias are one capability', () => {
    // Key preprocessing pads to the block size, so these two distinct byte
    // strings produce the same effective key and cannot be separate principals.
    const short = new Uint8Array(32).fill(3);
    const extended = new Uint8Array(64);
    extended.set(short);

    assert.strictEqual(sameHmacDomain(short, extended, 'HS256'), true);
    // The raw octets differ, which is exactly why byte comparison is not enough.
    assert.strictEqual(sameKeyMaterial({ kty: 'oct', k: short }, { kty: 'oct', k: extended }), false);
  });

  test('a key longer than the block size is equivalent to its hash', () => {
    const long = new Uint8Array(200).fill(5);
    const hashed = new Uint8Array(createHash('sha256').update(long).digest());

    assert.strictEqual(sameHmacDomain(long, hashed, 'HS256'), true);
    assert.strictEqual(sameKeyMaterial({ kty: 'oct', k: long }, { kty: 'oct', k: hashed }), false);
  });

  test('unrelated keys do not share a domain', () => {
    assert.strictEqual(sameHmacDomain(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 'HS256'), false);
  });

  test('uses the block size of the configured algorithm', () => {
    // SHA-384 and SHA-512 use a 128-octet block, so a 64-octet key pads
    // differently there than under SHA-256.
    const short = new Uint8Array(48).fill(4);
    const paddedTo64 = new Uint8Array(64);
    paddedTo64.set(short);
    const paddedTo128 = new Uint8Array(128);
    paddedTo128.set(short);

    assert.strictEqual(sameHmacDomain(short, paddedTo64, 'HS256'), true);
    assert.strictEqual(sameHmacDomain(short, paddedTo128, 'HS256'), false);
    assert.strictEqual(sameHmacDomain(short, paddedTo128, 'HS384'), true);
    assert.strictEqual(sameHmacDomain(short, paddedTo128, 'HS512'), true);
  });

  test("a long key crosses the hash threshold at the algorithm's block size", () => {
    const key = new Uint8Array(100).fill(6);
    // Under SHA-256 the 64-octet block means this key is hashed first; under
    // SHA-384 the 128-octet block means it is padded instead.
    const sha256Hash = new Uint8Array(createHash('sha256').update(key).digest());
    const padded = new Uint8Array(128);
    padded.set(key);

    assert.strictEqual(sameHmacDomain(key, sha256Hash, 'HS256'), true);
    assert.strictEqual(sameHmacDomain(key, padded, 'HS384'), true);
  });

  test('refuses an algorithm with no defined preprocessing', () => {
    const key = new Uint8Array(32).fill(1);
    // AES key wrapping has no HMAC preprocessing, so no domain claim is made.
    assert.strictEqual(sameHmacDomain(key, key, 'A128KW'), false);
    assert.strictEqual(sameHmacDomain(key, key, 'ES256'), false);
  });

  test("does not mutate the caller's key material", () => {
    // The comparison clears its own derived blocks; the inputs must survive.
    const a = new Uint8Array(32).fill(9);
    const b = new Uint8Array(32).fill(9);
    assert.strictEqual(sameHmacDomain(a, b, 'HS256'), true);
    assert.deepStrictEqual(
      [...a],
      Array.from({ length: 32 }, () => 9),
    );
    assert.deepStrictEqual(
      [...b],
      Array.from({ length: 32 }, () => 9),
    );
  });
});
