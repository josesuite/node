import { describe, expect, test } from 'bun:test';
import { pbkdf2Sync } from 'node:crypto';

import { keyManagementShape } from '../../../src/algorithms/jwe/index.ts';
import {
  buildSalt,
  checkWorkFactor,
  derivePbes2Key,
  MAX_ITERATIONS,
  MAX_SALT_INPUT_BYTES,
  MIN_ITERATIONS,
  MIN_SALT_INPUT_BYTES,
  pbes2Parameters,
} from '../../../src/algorithms/jwe/pbes2.ts';

const ALGORITHMS = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'] as const;

const PASSWORD = new TextEncoder().encode('correct horse battery staple');
const SALT_INPUT = new Uint8Array(16).fill(7);

describe('parameters', () => {
  test('binds each variant to its hash, key size and wrapping algorithm', () => {
    expect(pbes2Parameters('PBES2-HS256+A128KW')).toEqual({
      hash: 'SHA-256',
      keyBytes: 16,
      wrappingAlgorithm: 'A128KW',
    });
    expect(pbes2Parameters('PBES2-HS384+A192KW')).toEqual({
      hash: 'SHA-384',
      keyBytes: 24,
      wrappingAlgorithm: 'A192KW',
    });
    expect(pbes2Parameters('PBES2-HS512+A256KW')).toEqual({
      hash: 'SHA-512',
      keyBytes: 32,
      wrappingAlgorithm: 'A256KW',
    });
    expect(pbes2Parameters('PBES2-HS256+A256KW')).toBeUndefined();
  });

  test('is registered as receive-only wrapping', () => {
    for (const algorithm of ALGORITHMS) {
      const shape = keyManagementShape(algorithm);
      expect(shape?.mode).toBe('password_wrapping');
      expect(shape?.carriesEncryptedKey).toBe(true);
    }
  });
});

describe('salt construction', () => {
  test('prefixes the algorithm name and a zero octet', () => {
    const salt = buildSalt('PBES2-HS256+A128KW', SALT_INPUT);
    const name = new TextEncoder().encode('PBES2-HS256+A128KW');

    expect(salt.length).toBe(name.length + 1 + SALT_INPUT.length);
    expect([...salt.subarray(0, name.length)]).toEqual([...name]);
    expect(salt[name.length]).toBe(0x00);
    expect([...salt.subarray(name.length + 1)]).toEqual([...SALT_INPUT]);
  });

  test('binds the derived key to the identifier that named it', () => {
    // Without the prefix, one variant's KEK could be reused under another.
    const a = buildSalt('PBES2-HS256+A128KW', SALT_INPUT);
    const b = buildSalt('PBES2-HS512+A256KW', SALT_INPUT);

    expect(a).not.toEqual(b);
  });

  test('separates the name from the salt input unambiguously', () => {
    // The zero octet is what stops a longer name with a shorter salt from
    // colliding with a shorter name and a longer salt.
    const a = buildSalt('AB', new Uint8Array([0x43, 0x44]));
    const b = buildSalt('ABC', new Uint8Array([0x44]));

    expect(a).not.toEqual(b);
  });
});

describe('work factor bounds', () => {
  test('accepts values inside policy', () => {
    expect(checkWorkFactor('PBES2-HS256+A128KW', SALT_INPUT, MIN_ITERATIONS).ok).toBe(true);
    expect(checkWorkFactor('PBES2-HS256+A128KW', SALT_INPUT, MAX_ITERATIONS).ok).toBe(true);
  });

  test('rejects a salt input below the minimum', () => {
    // The algorithm prefix does not count toward this minimum.
    const result = checkWorkFactor('PBES2-HS256+A128KW', new Uint8Array(MIN_SALT_INPUT_BYTES - 1), MIN_ITERATIONS);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('salt_too_short');
    }
  });

  test('rejects an oversized salt input', () => {
    const result = checkWorkFactor('PBES2-HS256+A128KW', new Uint8Array(MAX_SALT_INPUT_BYTES + 1), MIN_ITERATIONS);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('salt_too_long');
    }
  });

  test('rejects an iteration count below the minimum', () => {
    // The historical 1,000-iteration recommendation is far below policy.
    for (const iterations of [0, 1, 1000, MIN_ITERATIONS - 1]) {
      const result = checkWorkFactor('PBES2-HS256+A128KW', SALT_INPUT, iterations);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('iterations_below_minimum');
      }
    }
  });

  test('rejects an iteration count above the maximum', () => {
    // An unbounded count is a denial-of-service vector: the work is done here
    // at the sender's choosing.
    for (const iterations of [MAX_ITERATIONS + 1, 10_000_000, 2 ** 40]) {
      const result = checkWorkFactor('PBES2-HS256+A128KW', SALT_INPUT, iterations);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('iterations_above_maximum');
      }
    }
  });

  test('rejects an unsupported identifier', () => {
    const result = checkWorkFactor('PBES2-HS256+A256KW', SALT_INPUT, MIN_ITERATIONS);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('unsupported_algorithm');
    }
  });
});

describe('derivation', () => {
  for (const algorithm of ALGORITHMS) {
    test(`${algorithm} matches an independently computed PBKDF2`, async () => {
      // Recomputed through the provider's own PBKDF2 so the test establishes
      // the salt and hash selection rather than agreeing with itself.
      const parameters = pbes2Parameters(algorithm)!;
      const derived = await derivePbes2Key(algorithm, PASSWORD, SALT_INPUT, MIN_ITERATIONS);

      expect(derived.ok).toBe(true);
      if (!derived.ok) {
        return;
      }
      expect(derived.value.length).toBe(parameters.keyBytes);

      const expected = pbkdf2Sync(
        Buffer.from(PASSWORD),
        Buffer.from(buildSalt(algorithm, SALT_INPUT)),
        MIN_ITERATIONS,
        parameters.keyBytes,
        parameters.hash.replace('SHA-', 'sha'),
      );

      expect([...derived.value]).toEqual([...expected]);
    });
  }

  test('derives different keys for different passwords', async () => {
    const a = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, SALT_INPUT, MIN_ITERATIONS);
    const b = await derivePbes2Key(
      'PBES2-HS256+A128KW',
      new TextEncoder().encode('another password'),
      SALT_INPUT,
      MIN_ITERATIONS,
    );

    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(a.value).not.toEqual(b.value);
    }
  });

  test('derives different keys for different salts', async () => {
    const a = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, SALT_INPUT, MIN_ITERATIONS);
    const b = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, new Uint8Array(16).fill(9), MIN_ITERATIONS);

    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(a.value).not.toEqual(b.value);
    }
  });

  test('does not normalize or trim the password', async () => {
    // A text adapter converts with UTF-8 and nothing else: trimming would
    // silently accept a different password than the user supplied.
    const plain = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, SALT_INPUT, MIN_ITERATIONS);
    const padded = await derivePbes2Key(
      'PBES2-HS256+A128KW',
      new TextEncoder().encode(' correct horse battery staple '),
      SALT_INPUT,
      MIN_ITERATIONS,
    );

    expect(plain.ok && padded.ok).toBe(true);
    if (plain.ok && padded.ok) {
      expect(plain.value).not.toEqual(padded.value);
    }
  });

  test('refuses to derive outside the work-factor bounds', async () => {
    // The expensive step enforces the bounds itself rather than trusting a
    // caller to have checked first.
    const low = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, SALT_INPUT, 1000);
    expect(low.ok).toBe(false);

    const shortSalt = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, new Uint8Array(4), MIN_ITERATIONS);
    expect(shortSalt.ok).toBe(false);

    const high = await derivePbes2Key('PBES2-HS256+A128KW', PASSWORD, SALT_INPUT, MAX_ITERATIONS + 1);
    expect(high.ok).toBe(false);
  });

  test('reports an unsupported identifier', async () => {
    const result = await derivePbes2Key('PBES2-HS256+A256KW', PASSWORD, SALT_INPUT, MIN_ITERATIONS);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('unsupported');
    }
  });
});
