import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';
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

describe('Base64urlUInt encoding', () => {
  test('rejects empty and redundantly padded integers', () => {
    expect(validateUInt(new Uint8Array(), 'n')?.reason).toBe('n_empty');
    expect(validateUInt(new Uint8Array([0x00, 0x01]), 'n')?.reason).toBe('n_leading_zero');
    // A single zero octet encodes zero, which is not a valid modulus or exponent.
    expect(validateUInt(new Uint8Array([0x00]), 'n')?.reason).toBe('n_leading_zero');
  });

  test('accepts a minimal encoding', () => {
    expect(validateUInt(new Uint8Array([0x01, 0x00, 0x01]), 'e')).toBeUndefined();
  });

  test('converts exactly, beyond the safe-integer range', () => {
    expect(toBigInt(new Uint8Array([0x01, 0x00, 0x01]))).toBe(65_537n);
    expect(toBigInt(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toBe(
      18_446_744_073_709_551_615n,
    );
  });
});

describe('RSA public material', () => {
  test('accepts a valid 3072-bit key', () => {
    const result = validateRsaPublic(object(RSA_3072), { receiveOnly: false });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.material.modulusBits).toBe(3072);
    }
  });

  test('enforces the modern 3072-bit floor and the receive-only 2048-bit range', () => {
    const rsa2048 = rsaJwk(2048);

    const modern = validateRsaPublic(object(rsa2048), { receiveOnly: false });
    expect(modern.ok).toBe(false);
    if (!modern.ok) {
      expect(modern.reason).toBe('n_too_small');
      expect(modern.category).toBe('incompatible_key');
    }

    const receive = validateRsaPublic(object(rsa2048), { receiveOnly: true });
    expect(receive.ok).toBe(true);
    if (receive.ok) {
      expect(receive.material.modulusBits).toBe(2048);
    }
  });

  test('rejects a modulus below the absolute floor even when receive-only', () => {
    const rsa1024 = rsaJwk(1024);
    expect(validateRsaPublic(object(rsa1024), { receiveOnly: true }).ok).toBe(false);
  });

  test('rejects an even modulus', () => {
    const n = Buffer.from(RSA_3072['n']!, 'base64url');
    n[n.length - 1] = n[n.length - 1]! & 0xfe;
    const result = validateRsaPublic(object({ ...RSA_3072, n: b64u(n) }), { receiveOnly: false });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('n_even');
    }
  });

  test('rejects invalid exponents', () => {
    const cases: readonly [string, string][] = [
      [b64u(new Uint8Array([0x02])), 'e_even'],
      [b64u(new Uint8Array([0x01])), 'e_too_small'],
    ];

    for (const [e, reason] of cases) {
      const result = validateRsaPublic(object({ ...RSA_3072, e }), { receiveOnly: false });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(reason);
      }
    }
  });

  test('bounds the exponent to 32 bits', () => {
    const result = validateRsaPublic(object({ ...RSA_3072, e: b64u(new Uint8Array([1, 0, 0, 0, 1])) }), {
      receiveOnly: false,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
    }
  });

  test('rejects missing, mistyped, and malformed members', () => {
    const { n: _n, ...withoutN } = RSA_3072;
    expect(validateRsaPublic(object(withoutN), { receiveOnly: false }).ok).toBe(false);

    const mistyped = validateRsaPublic(object({ ...RSA_3072, n: 1 }), { receiveOnly: false });
    expect(mistyped.ok).toBe(false);
    if (!mistyped.ok) {
      expect(mistyped.reason).toBe('n_not_a_string');
    }

    // Padded Base64 is not valid here even though the bytes would decode.
    const padded = validateRsaPublic(object({ ...RSA_3072, e: 'AQAB=' }), { receiveOnly: false });
    expect(padded.ok).toBe(false);
    if (!padded.ok) {
      expect(padded.category).toBe('invalid_encoding');
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
    expect(result.ok).toBe(true);

    // The decoded private members must be returned, not merely validated:
    // a key carrying only the public members cannot sign.
    if (result.ok) {
      for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const) {
        expect(result.material[name].length).toBeGreaterThan(0);
      }
      expect(result.material.n).toEqual(publicMaterial.n);
    }
  });

  test('requires the complete CRT group', () => {
    for (const missing of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      const partial = { ...RSA_3072 };
      delete partial[missing];
      expect(validateRsaPrivate(object(partial), publicMaterial)?.reason).toBe(`${missing}_missing`);
    }
  });

  test('rejects multi-prime keys', () => {
    const result = validateRsaPrivate(object({ ...RSA_3072, oth: [] }), publicMaterial);
    expect(result?.reason).toBe('oth_unsupported');
  });

  test('rejects an inconsistent qi that the backend would accept', () => {
    // Node imports this key and signs with it successfully, so the mismatch has
    // to be caught here or not at all.
    const qi = Buffer.from(RSA_3072['qi']!, 'base64url');
    qi[qi.length - 1] = qi[qi.length - 1]! ^ 0x01;
    const result = validateRsaPrivate(object({ ...RSA_3072, qi: b64u(qi) }), publicMaterial);
    expect(result?.reason).toBe('qi_mismatch');
  });

  test('rejects factors whose product is not the modulus', () => {
    const other = rsaJwk();
    const result = validateRsaPrivate(object({ ...RSA_3072, p: other['p']! }), publicMaterial);
    expect(result).toBeDefined();
    // Substituting a foreign prime breaks the product before any CRT check.
    expect(result?.reason).toBe('pq_product_mismatch');
  });

  test('rejects mismatched CRT exponents', () => {
    const dp = Buffer.from(RSA_3072['dp']!, 'base64url');
    dp[dp.length - 1] = dp[dp.length - 1]! ^ 0x01;
    expect(validateRsaPrivate(object({ ...RSA_3072, dp: b64u(dp) }), publicMaterial)?.reason).toBe('dp_mismatch');

    const dq = Buffer.from(RSA_3072['dq']!, 'base64url');
    dq[dq.length - 1] = dq[dq.length - 1]! ^ 0x01;
    expect(validateRsaPrivate(object({ ...RSA_3072, dq: b64u(dq) }), publicMaterial)?.reason).toBe('dq_mismatch');
  });

  test('rejects a private exponent inconsistent with the public exponent', () => {
    const other = rsaJwk();
    // A foreign `d` of the same size keeps every length valid but breaks the
    // modular relationship with `e`.
    const result = validateRsaPrivate(object({ ...RSA_3072, d: other['d']! }), publicMaterial);
    expect(result).toBeDefined();
    expect(result?.reason).toMatch(/^d_inconsistent_mod_[pq]$|^dp_mismatch$/);
  });

  test('rejects equal primes', () => {
    const result = validateRsaPrivate(object({ ...RSA_3072, p: RSA_3072['q']!, q: RSA_3072['q']! }), publicMaterial);
    expect(result?.reason).toBe('p_equals_q');
  });

  test('rejects a unit factor without dividing by zero', () => {
    // `p = 1, q = n` satisfies the product check, so validation reaches the
    // `p - 1` moduli. A unit factor must be reported as a normalized rejection
    // rather than throwing a RangeError out of import.
    const forged = { ...RSA_3072, p: b64u(Uint8Array.from([1])), q: RSA_3072['n']! };
    let result: ReturnType<typeof validateRsaPrivate>;
    expect(() => {
      result = validateRsaPrivate(object(forged), publicMaterial);
    }).not.toThrow();
    expect(result?.reason).toBe('factor_not_greater_than_one');
  });
});

function octJwk(bytes: number): Record<string, string> {
  return { kty: 'oct', k: Buffer.alloc(bytes, 7).toString('base64url') };
}

describe('symmetric key material', () => {
  test('accepts a key meeting the algorithm minimum', () => {
    const result = validateOctMaterial(object(octJwk(32)), 32);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.key).toHaveLength(32);
    }
  });

  test('accepts a key longer than the minimum', () => {
    expect(validateOctMaterial(object(octJwk(64)), 32).ok).toBe(true);
  });

  test('rejects a key shorter than the algorithm requires', () => {
    // A short MAC key weakens the algorithm below its stated strength.
    const result = validateOctMaterial(object(octJwk(31)), 32);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('k_too_short');
      expect(result.category).toBe('incompatible_key');
    }
  });

  test('rejects an empty key', () => {
    expect(validateOctMaterial(object({ kty: 'oct', k: '' }), 32).ok).toBe(false);
  });

  test('enforces the maximum symmetric key size', () => {
    const result = validateOctMaterial(object(octJwk(129)), 32);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
    }

    expect(validateOctMaterial(object(octJwk(128)), 32).ok).toBe(true);
  });

  test('rejects a missing or mistyped k', () => {
    expect(validateOctMaterial(object({ kty: 'oct' }), 32).ok).toBe(false);

    const mistyped = validateOctMaterial(object({ kty: 'oct', k: 1 }), 32);
    expect(mistyped.ok).toBe(false);
    if (!mistyped.ok) {
      expect(mistyped.reason).toBe('k_not_a_string');
    }
  });

  test('rejects non-canonical Base64url', () => {
    const result = validateOctMaterial(object({ kty: 'oct', k: `${Buffer.alloc(32, 7).toString('base64url')}=` }), 32);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_encoding');
    }
  });
});
