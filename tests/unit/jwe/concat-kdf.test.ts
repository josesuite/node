import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createHash } from 'node:crypto';

import { concatKdf, partyInfo } from '../../../src/algorithms/jwe/concat-kdf.ts';

const ascii = (text: string) => new TextEncoder().encode(text);
const b64u = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

describe('published test vector', () => {
  /**
   * The worked ECDH-ES example from the JWA specification, with its stated
   * shared secret and derived key. An independently published vector is what
   * establishes the encoding is right; a self-consistent round trip would pass
   * with the fields in any order.
   */
  const Z = new Uint8Array([
    158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72,
    246, 218, 167, 121, 140, 254, 144, 196,
  ]);

  test('derives the published key for direct agreement', () => {
    const derived = concatKdf(Z, {
      algorithmId: ascii('A128GCM'),
      partyUInfo: b64u('QWxpY2U'),
      partyVInfo: b64u('Qm9i'),
      keyBytes: 16,
    });

    assert.deepStrictEqual([...derived], [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]);
  });
});

describe('encoding invariants', () => {
  const Z = new Uint8Array(32).fill(7);

  function derive(overrides: Partial<Parameters<typeof concatKdf>[1]> = {}) {
    return concatKdf(Z, {
      algorithmId: ascii('A128GCM'),
      partyUInfo: new Uint8Array(0),
      partyVInfo: new Uint8Array(0),
      keyBytes: 16,
      ...overrides,
    });
  }

  test('binds the algorithm identifier', () => {
    // Direct agreement feeds `enc` and wrapped agreement feeds `alg`; deriving
    // the same key for both would let one be substituted for the other.
    assert.notDeepStrictEqual(derive({ algorithmId: ascii('A128GCM') }), derive({ algorithmId: ascii('A128KW') }));
    assert.notDeepStrictEqual(derive({ algorithmId: ascii('A128GCM') }), derive({ algorithmId: ascii('A256GCM') }));
  });

  test('binds the requested key length', () => {
    const short = derive({ keyBytes: 16 });
    const long = derive({ keyBytes: 32 });

    // The length enters the hash, so the shorter key is not a prefix of the
    // longer one. A KDF that merely truncated would leak one from the other.
    assert.notDeepStrictEqual([...long.subarray(0, 16)], [...short]);
  });

  test('separates party fields rather than concatenating them', () => {
    // Without length prefixes these two would produce identical OtherInfo,
    // letting an attacker move bytes across the boundary undetected.
    const split = derive({ partyUInfo: ascii('AB'), partyVInfo: ascii('CD') });
    const shifted = derive({ partyUInfo: ascii('ABC'), partyVInfo: ascii('D') });

    assert.notDeepStrictEqual(split, shifted);
  });

  test('treats an absent party field as empty', () => {
    assert.deepStrictEqual(partyInfo(undefined), new Uint8Array(0));
    assert.deepStrictEqual(partyInfo(ascii('x')), ascii('x'));

    assert.deepStrictEqual(derive({ partyUInfo: partyInfo(undefined) }), derive({ partyUInfo: new Uint8Array(0) }));
  });

  test('binds the shared secret including leading zeros', () => {
    // A bignum conversion would strip the leading zero and derive the same key
    // for two different secrets, which happens for roughly one agreement in
    // 256.
    const leadingZero = new Uint8Array(32);
    leadingZero.set([0, 1, 2, 3], 0);
    const stripped = leadingZero.subarray(1);

    const input = {
      algorithmId: ascii('A128GCM'),
      partyUInfo: new Uint8Array(0),
      partyVInfo: new Uint8Array(0),
      keyBytes: 16,
    };
    assert.notDeepStrictEqual(concatKdf(leadingZero, input), concatKdf(stripped, input));
  });
});

describe('multi-round derivation', () => {
  const Z = new Uint8Array(32).fill(3);
  const base = { algorithmId: ascii('A256CBC-HS512'), partyUInfo: new Uint8Array(0), partyVInfo: new Uint8Array(0) };

  test('produces the exact requested length past one hash block', () => {
    for (const keyBytes of [16, 24, 32, 33, 48, 64]) {
      const key = concatKdf(Z, { ...base, keyBytes });
      assert.strictEqual(key.length, keyBytes);
      assert.strictEqual(key.buffer.byteLength, keyBytes);
    }
  });

  test('advances the counter between rounds', () => {
    // Both 32-byte halves of a 64-byte key come from the same secret and
    // OtherInfo; only the counter distinguishes them, so equal halves would
    // mean the counter never moved.
    const derived = concatKdf(Z, { ...base, keyBytes: 64 });

    assert.notDeepStrictEqual([...derived.subarray(0, 32)], [...derived.subarray(32)]);
  });

  test('concatenates rounds and truncates the last one', () => {
    // Recomputing the rounds independently pins the structure: each round is
    // SHA-256 over counter, secret and OtherInfo, joined in order, with the
    // final round cut to length rather than rehashed at a shorter size.
    const keyBytes = 48;
    const otherInfo = Buffer.concat([
      Buffer.from([0, 0, 0, base.algorithmId.length]),
      Buffer.from(base.algorithmId),
      Buffer.from([0, 0, 0, 0]),
      Buffer.from([0, 0, 0, 0]),
      Buffer.from([0, 0, (keyBytes * 8) >> 8, (keyBytes * 8) & 0xff]),
    ]);

    const expected = Buffer.concat(
      [1, 2].map((round) =>
        createHash('sha256')
          .update(Buffer.from([0, 0, 0, round]))
          .update(Buffer.from(Z))
          .update(otherInfo)
          .digest(),
      ),
    ).subarray(0, keyBytes);

    assert.deepStrictEqual([...concatKdf(Z, { ...base, keyBytes })], [...expected]);
  });
});
