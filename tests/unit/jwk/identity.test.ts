import { describe, expect, test } from 'bun:test';
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
    expect(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2, 3), e: bytes(1, 0, 1) })).toBe(true);
    expect(sameKeyMaterial(EC, { kty: 'EC', crv: 'P-256', x: bytes(1), y: bytes(2) })).toBe(true);
    expect(sameKeyMaterial(OKP, { kty: 'OKP', crv: 'Ed25519', x: bytes(1) })).toBe(true);
    expect(sameKeyMaterial(AKP, { kty: 'AKP', alg: 'ML-DSA-44', pub: bytes(1) })).toBe(true);
    expect(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3, 4) })).toBe(true);
  });

  test('any differing compared member makes two distinct keys', () => {
    expect(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2, 4), e: bytes(1, 0, 1) })).toBe(false);
    expect(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2, 3), e: bytes(3) })).toBe(false);
    expect(sameKeyMaterial(EC, { kty: 'EC', crv: 'P-256', x: bytes(9), y: bytes(2) })).toBe(false);
    expect(sameKeyMaterial(EC, { kty: 'EC', crv: 'P-256', x: bytes(1), y: bytes(9) })).toBe(false);
    expect(sameKeyMaterial(OKP, { kty: 'OKP', crv: 'Ed25519', x: bytes(9) })).toBe(false);
    expect(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3, 5) })).toBe(false);
  });

  test('different key types are never equal', () => {
    expect(sameKeyMaterial(RSA, EC)).toBe(false);
    expect(sameKeyMaterial(EC, OKP)).toBe(false);
    expect(sameKeyMaterial(OKP, AKP)).toBe(false);
    expect(sameKeyMaterial(OCT, RSA)).toBe(false);
  });

  test('discriminators compare case-sensitively without alias expansion', () => {
    expect(sameKeyMaterial(EC, { kty: 'EC', crv: 'p-256', x: bytes(1), y: bytes(2) })).toBe(false);
    expect(sameKeyMaterial(OKP, { kty: 'OKP', crv: 'ed25519', x: bytes(1) })).toBe(false);
  });

  test('post-quantum keys compare their algorithm, which fixes the parameter set', () => {
    // The algorithm determines how the public value is interpreted, so two keys
    // with identical bytes but different parameter sets are different keys.
    expect(sameKeyMaterial(AKP, { kty: 'AKP', alg: 'ML-DSA-65', pub: bytes(1) })).toBe(false);
  });

  test('length differences are handled without reading past either value', () => {
    expect(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3) })).toBe(false);
    expect(sameKeyMaterial(OCT, { kty: 'oct', k: bytes(1, 2, 3, 4, 5) })).toBe(false);
    expect(sameKeyMaterial(RSA, { kty: 'RSA', n: bytes(1, 2), e: bytes(1, 0, 1) })).toBe(false);
  });

  test('equality ignores how a key was labelled', () => {
    // Identity is built from the compared members only, so two records that
    // differ in metadata cannot reach this function looking different.
    const a: KeyIdentity = { kty: 'EC', crv: 'P-384', x: bytes(7), y: bytes(8) };
    const b: KeyIdentity = { kty: 'EC', crv: 'P-384', x: bytes(7), y: bytes(8) };
    expect(sameKeyMaterial(a, b)).toBe(true);
  });
});

describe('representation identity versus holder identity', () => {
  test('agreement curves do not establish holder identity from public bytes', () => {
    // Several publicly computable values produce the same shared secrets, so
    // unequal representations are not proof of distinct holders.
    expect(representationImpliesHolderIdentity({ kty: 'OKP', crv: 'X25519', x: bytes(1) })).toBe(false);
    expect(representationImpliesHolderIdentity({ kty: 'OKP', crv: 'X448', x: bytes(1) })).toBe(false);
  });

  test('signing and other key types do establish it', () => {
    expect(representationImpliesHolderIdentity(OKP)).toBe(true);
    expect(representationImpliesHolderIdentity(RSA)).toBe(true);
    expect(representationImpliesHolderIdentity(EC)).toBe(true);
    expect(representationImpliesHolderIdentity(OCT)).toBe(true);
  });
});

describe('thumbprint indexing', () => {
  test('is unavailable for symmetric keys', () => {
    // A symmetric thumbprint is derived from the secret, so publishing or
    // indexing by it would expose secret-derived data.
    expect(mayIndexByThumbprint('oct')).toBe(false);
    expect(mayIndexByThumbprint('RSA')).toBe(true);
    expect(mayIndexByThumbprint('EC')).toBe(true);
    expect(mayIndexByThumbprint('OKP')).toBe(true);
    expect(mayIndexByThumbprint('AKP')).toBe(true);
  });
});

describe('HMAC authentication-domain equivalence', () => {
  test('identical keys share a domain', () => {
    const key = new Uint8Array(32).fill(7);
    expect(sameHmacDomain(key, new Uint8Array(32).fill(7), 'HS256')).toBe(true);
  });

  test('a short key and its zero-extended alias are one capability', () => {
    // Key preprocessing pads to the block size, so these two distinct byte
    // strings produce the same effective key and cannot be separate principals.
    const short = new Uint8Array(32).fill(3);
    const extended = new Uint8Array(64);
    extended.set(short);

    expect(sameHmacDomain(short, extended, 'HS256')).toBe(true);
    // The raw octets differ, which is exactly why byte comparison is not enough.
    expect(sameKeyMaterial({ kty: 'oct', k: short }, { kty: 'oct', k: extended })).toBe(false);
  });

  test('a key longer than the block size is equivalent to its hash', () => {
    const long = new Uint8Array(200).fill(5);
    const hashed = new Uint8Array(createHash('sha256').update(long).digest());

    expect(sameHmacDomain(long, hashed, 'HS256')).toBe(true);
    expect(sameKeyMaterial({ kty: 'oct', k: long }, { kty: 'oct', k: hashed })).toBe(false);
  });

  test('unrelated keys do not share a domain', () => {
    expect(sameHmacDomain(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 'HS256')).toBe(false);
  });

  test('uses the block size of the configured algorithm', () => {
    // SHA-384 and SHA-512 use a 128-octet block, so a 64-octet key pads
    // differently there than under SHA-256.
    const short = new Uint8Array(48).fill(4);
    const paddedTo64 = new Uint8Array(64);
    paddedTo64.set(short);
    const paddedTo128 = new Uint8Array(128);
    paddedTo128.set(short);

    expect(sameHmacDomain(short, paddedTo64, 'HS256')).toBe(true);
    expect(sameHmacDomain(short, paddedTo128, 'HS256')).toBe(false);
    expect(sameHmacDomain(short, paddedTo128, 'HS384')).toBe(true);
    expect(sameHmacDomain(short, paddedTo128, 'HS512')).toBe(true);
  });

  test("a long key crosses the hash threshold at the algorithm's block size", () => {
    const key = new Uint8Array(100).fill(6);
    // Under SHA-256 the 64-octet block means this key is hashed first; under
    // SHA-384 the 128-octet block means it is padded instead.
    const sha256Hash = new Uint8Array(createHash('sha256').update(key).digest());
    const padded = new Uint8Array(128);
    padded.set(key);

    expect(sameHmacDomain(key, sha256Hash, 'HS256')).toBe(true);
    expect(sameHmacDomain(key, padded, 'HS384')).toBe(true);
  });

  test('refuses an algorithm with no defined preprocessing', () => {
    const key = new Uint8Array(32).fill(1);
    // AES key wrapping has no HMAC preprocessing, so no domain claim is made.
    expect(sameHmacDomain(key, key, 'A128KW')).toBe(false);
    expect(sameHmacDomain(key, key, 'ES256')).toBe(false);
  });

  test("does not mutate the caller's key material", () => {
    // The comparison clears its own derived blocks; the inputs must survive.
    const a = new Uint8Array(32).fill(9);
    const b = new Uint8Array(32).fill(9);
    expect(sameHmacDomain(a, b, 'HS256')).toBe(true);
    expect([...a]).toEqual(Array.from({ length: 32 }, () => 9));
    expect([...b]).toEqual(Array.from({ length: 32 }, () => 9));
  });
});
