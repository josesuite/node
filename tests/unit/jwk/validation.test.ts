import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';
import type { MaterialRejection } from '../../../src/key/validation.ts';
import {
  toBigInt,
  validateOctMaterial,
  validateRsaPrivate,
  validateRsaPublic,
  validateUInt,
} from '../../../src/key/validation.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

/** A real 3072-bit RSA key, so the arithmetic checks run against valid material. */
function rsaJwk(modulusLength = 3072): Record<string, string> {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength });
  return privateKey.export({ format: 'jwk' }) as unknown as Record<string, string>;
}

const RSA_3072 = rsaJwk();

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Narrows to the rejection branch so an unexpected success fails here. */
function rejectionOf(result: { readonly ok: true } | MaterialRejection): MaterialRejection {
  assert.strictEqual(result.ok, false);
  return result as MaterialRejection;
}

describe('Base64urlUInt encoding', () => {
  test('rejects empty and redundantly padded integers', () => {
    assert.strictEqual(validateUInt(new Uint8Array(), 'n')?.reason, 'n_empty');
    assert.strictEqual(validateUInt(new Uint8Array([0x00, 0x01]), 'n')?.reason, 'n_leading_zero');
    // A single zero octet encodes zero, which is not a valid modulus or exponent.
    assert.strictEqual(validateUInt(new Uint8Array([0x00]), 'n')?.reason, 'n_leading_zero');
  });

  test('accepts a minimal encoding', () => {
    assert.strictEqual(validateUInt(new Uint8Array([0x01, 0x00, 0x01]), 'e'), undefined);
  });

  test('converts exactly, beyond the safe-integer range', () => {
    assert.strictEqual(toBigInt(new Uint8Array([0x01, 0x00, 0x01])), 65_537n);
    assert.strictEqual(
      toBigInt(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])),
      18_446_744_073_709_551_615n,
    );
  });
});

describe('RSA public material', () => {
  test('accepts a valid 3072-bit key', () => {
    const result = validateRsaPublic(object(RSA_3072), { receiveOnly: false });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.material.modulusBits, 3072);
    }
  });

  test('enforces the modern 3072-bit floor and the receive-only 2048-bit range', () => {
    const rsa2048 = rsaJwk(2048);

    const modern = validateRsaPublic(object(rsa2048), { receiveOnly: false });
    assert.strictEqual(modern.ok, false);
    if (!modern.ok) {
      assert.strictEqual(modern.reason, 'n_too_small');
      assert.strictEqual(modern.category, 'incompatible_key');
    }

    const receive = validateRsaPublic(object(rsa2048), { receiveOnly: true });
    assert.strictEqual(receive.ok, true);
    if (receive.ok) {
      assert.strictEqual(receive.material.modulusBits, 2048);
    }
  });

  test('rejects a modulus below the absolute floor even when receive-only', () => {
    const rsa1024 = rsaJwk(1024);
    assert.strictEqual(validateRsaPublic(object(rsa1024), { receiveOnly: true }).ok, false);
  });

  test('rejects an even modulus', () => {
    const n = Buffer.from(RSA_3072['n']!, 'base64url');
    n[n.length - 1] = n[n.length - 1]! & 0xfe;
    const result = validateRsaPublic(object({ ...RSA_3072, n: b64u(n) }), { receiveOnly: false });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'n_even');
    }
  });

  test('rejects invalid exponents', () => {
    const cases: readonly [string, string][] = [
      [b64u(new Uint8Array([0x02])), 'e_even'],
      [b64u(new Uint8Array([0x01])), 'e_too_small'],
    ];

    for (const [e, reason] of cases) {
      const result = validateRsaPublic(object({ ...RSA_3072, e }), { receiveOnly: false });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, reason);
      }
    }
  });

  test('bounds the exponent to 32 bits', () => {
    const result = validateRsaPublic(object({ ...RSA_3072, e: b64u(new Uint8Array([1, 0, 0, 0, 1])) }), {
      receiveOnly: false,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }
  });

  test('rejects missing, mistyped, and malformed members', () => {
    const { n: _n, ...withoutN } = RSA_3072;
    assert.strictEqual(validateRsaPublic(object(withoutN), { receiveOnly: false }).ok, false);

    const mistyped = validateRsaPublic(object({ ...RSA_3072, n: 1 }), { receiveOnly: false });
    assert.strictEqual(mistyped.ok, false);
    if (!mistyped.ok) {
      assert.strictEqual(mistyped.reason, 'n_not_a_string');
    }

    // Padded Base64 is not valid here even though the bytes would decode.
    const padded = validateRsaPublic(object({ ...RSA_3072, e: 'AQAB=' }), { receiveOnly: false });
    assert.strictEqual(padded.ok, false);
    if (!padded.ok) {
      assert.strictEqual(padded.category, 'invalid_encoding');
    }
  });
});

describe('RSA private material', () => {
  const publicMaterial = (() => {
    const result = validateRsaPublic(object(RSA_3072), { receiveOnly: false });
    if (!result.ok) {
      throw new Error('fixture');
    }
    return result.material;
  })();

  test('accepts a complete, consistent CRT parameter group', () => {
    const result = validateRsaPrivate(object(RSA_3072), publicMaterial);
    assert.strictEqual(result.ok, true);

    // The decoded private members must be returned, not merely validated:
    // a key carrying only the public members cannot sign.
    if (result.ok) {
      for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const) {
        assert.ok(result.material[name].length > 0);
      }
      assert.deepStrictEqual(result.material.n, publicMaterial.n);
    }
  });

  test('requires the complete CRT group', () => {
    for (const missing of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      const partial = { ...RSA_3072 };
      delete partial[missing];
      assert.strictEqual(rejectionOf(validateRsaPrivate(object(partial), publicMaterial)).reason, `${missing}_missing`);
    }
  });

  test('rejects multi-prime keys', () => {
    const result = rejectionOf(validateRsaPrivate(object({ ...RSA_3072, oth: [] }), publicMaterial));
    assert.strictEqual(result.reason, 'oth_unsupported');
  });

  test('rejects an inconsistent qi that the backend would accept', () => {
    // Node imports this key and signs with it successfully, so the mismatch has
    // to be caught here or not at all.
    const qi = Buffer.from(RSA_3072['qi']!, 'base64url');
    qi[qi.length - 1] = qi[qi.length - 1]! ^ 0x01;
    const result = rejectionOf(validateRsaPrivate(object({ ...RSA_3072, qi: b64u(qi) }), publicMaterial));
    assert.strictEqual(result.reason, 'qi_mismatch');
  });

  test('rejects factors whose product is not the modulus', () => {
    const other = rsaJwk();
    const result = rejectionOf(validateRsaPrivate(object({ ...RSA_3072, p: other['p']! }), publicMaterial));
    // Substituting a foreign prime breaks the product before any CRT check.
    assert.strictEqual(result.reason, 'pq_product_mismatch');
  });

  test('rejects mismatched CRT exponents', () => {
    const dp = Buffer.from(RSA_3072['dp']!, 'base64url');
    dp[dp.length - 1] = dp[dp.length - 1]! ^ 0x01;
    assert.strictEqual(
      rejectionOf(validateRsaPrivate(object({ ...RSA_3072, dp: b64u(dp) }), publicMaterial)).reason,
      'dp_mismatch',
    );

    const dq = Buffer.from(RSA_3072['dq']!, 'base64url');
    dq[dq.length - 1] = dq[dq.length - 1]! ^ 0x01;
    assert.strictEqual(
      rejectionOf(validateRsaPrivate(object({ ...RSA_3072, dq: b64u(dq) }), publicMaterial)).reason,
      'dq_mismatch',
    );
  });

  test('rejects a private exponent inconsistent with the public exponent', () => {
    const other = rsaJwk();
    // A foreign `d` of the same size keeps every length valid but breaks the
    // modular relationship with `e`.
    const result = rejectionOf(validateRsaPrivate(object({ ...RSA_3072, d: other['d']! }), publicMaterial));
    assert.match(result.reason, /^d_inconsistent_mod_[pq]$|^dp_mismatch$/);
  });

  test('rejects equal primes', () => {
    const result = rejectionOf(
      validateRsaPrivate(object({ ...RSA_3072, p: RSA_3072['q']!, q: RSA_3072['q']! }), publicMaterial),
    );
    assert.strictEqual(result.reason, 'p_equals_q');
  });

  test('rejects a unit factor without dividing by zero', () => {
    // `p = 1, q = n` satisfies the product check, so validation reaches the
    // `p - 1` moduli. A unit factor must be reported as a normalized rejection
    // rather than throwing a RangeError out of import.
    const forged = { ...RSA_3072, p: b64u(Uint8Array.from([1])), q: RSA_3072['n']! };
    let result: ReturnType<typeof validateRsaPrivate> | undefined;
    assert.doesNotThrow(() => {
      result = validateRsaPrivate(object(forged), publicMaterial);
    });
    assert.notStrictEqual(result, undefined);
    assert.strictEqual(rejectionOf(result!).reason, 'factor_not_greater_than_one');
  });
});

function octJwk(bytes: number): Record<string, string> {
  return { kty: 'oct', k: Buffer.alloc(bytes, 7).toString('base64url') };
}

describe('symmetric key material', () => {
  test('accepts a key meeting the algorithm minimum', () => {
    const result = validateOctMaterial(object(octJwk(32)), 32);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.key.length, 32);
    }
  });

  test('accepts a key longer than the minimum', () => {
    assert.strictEqual(validateOctMaterial(object(octJwk(64)), 32).ok, true);
  });

  test('rejects a key shorter than the algorithm requires', () => {
    // A short MAC key weakens the algorithm below its stated strength.
    const result = validateOctMaterial(object(octJwk(31)), 32);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'k_too_short');
      assert.strictEqual(result.category, 'incompatible_key');
    }
  });

  test('rejects an empty key', () => {
    assert.strictEqual(validateOctMaterial(object({ kty: 'oct', k: '' }), 32).ok, false);
  });

  test('enforces the maximum symmetric key size', () => {
    const result = validateOctMaterial(object(octJwk(129)), 32);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }

    assert.strictEqual(validateOctMaterial(object(octJwk(128)), 32).ok, true);
  });

  test('rejects a missing or mistyped k', () => {
    assert.strictEqual(validateOctMaterial(object({ kty: 'oct' }), 32).ok, false);

    const mistyped = validateOctMaterial(object({ kty: 'oct', k: 1 }), 32);
    assert.strictEqual(mistyped.ok, false);
    if (!mistyped.ok) {
      assert.strictEqual(mistyped.reason, 'k_not_a_string');
    }
  });

  test('rejects non-canonical Base64url', () => {
    const result = validateOctMaterial(object({ kty: 'oct', k: `${Buffer.alloc(32, 7).toString('base64url')}=` }), 32);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_encoding');
    }
  });
});
