import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import { signCompact } from '../../../src/jws/sign.ts';
import { importKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { checkLimits, LIMITS_V1, type Limits, lowerLimits } from '../../../src/policy/limits.ts';

describe('LIMIT-01 limits-v1 baseline', () => {
  test('matches the published limits-v1 defaults', () => {
    expect(LIMITS_V1.jwtInput).toBe(16 * 1024);
    expect(LIMITS_V1.joseInput).toBe(1024 * 1024);
    expect(LIMITS_V1.headerSource).toBe(8 * 1024);
    expect(LIMITS_V1.totalHeaderSource).toBe(32 * 1024);
    expect(LIMITS_V1.payload).toBe(256 * 1024);
    expect(LIMITS_V1.ciphertext).toBe(512 * 1024);
    expect(LIMITS_V1.externalAad).toBe(16 * 1024);
    expect(LIMITS_V1.jsonDepth).toBe(32);
    expect(LIMITS_V1.jsonObjectMembers).toBe(128);
    expect(LIMITS_V1.mergedHeaderMembers).toBe(64);
    expect(LIMITS_V1.jsonArrayElements).toBe(1024);
    expect(LIMITS_V1.jsonNodes).toBe(65_536);
    expect(LIMITS_V1.signatures).toBe(8);
    expect(LIMITS_V1.recipients).toBe(8);
    expect(LIMITS_V1.cryptographicLayers).toBe(2);
    expect(LIMITS_V1.candidateKeys).toBe(1);
    expect(LIMITS_V1.cryptographicAttempts).toBe(16);
    expect(LIMITS_V1.rsaModulusBits).toBe(8192);
    expect(LIMITS_V1.symmetricKeyOctets).toBe(128);
    expect(LIMITS_V1.pbes2IterationsMin).toBe(100_000);
    expect(LIMITS_V1.pbes2IterationsMax).toBe(1_000_000);
    expect(LIMITS_V1.decompressionRatio).toBe(20);
    expect(LIMITS_V1.networkAttempts).toBe(1);
    expect(LIMITS_V1.redirects).toBe(0);
  });

  test('is frozen so an operation cannot mutate the shared baseline', () => {
    expect(Object.isFrozen(LIMITS_V1)).toBe(true);
  });
});

describe('lowerLimits', () => {
  test('applies a lowered value and leaves the rest at the baseline', () => {
    const limits = lowerLimits({ payload: 1024 });
    expect(limits.payload).toBe(1024);
    expect(limits.joseInput).toBe(LIMITS_V1.joseInput);
    expect(Object.isFrozen(limits)).toBe(true);
  });

  test('permits a value equal to the baseline', () => {
    expect(lowerLimits({ signatures: LIMITS_V1.signatures }).signatures).toBe(8);
  });

  test('rejects raising a limit above the reviewed baseline', () => {
    // The baseline permits lowering only; raising needs a named reviewed profile.
    expect(() => lowerLimits({ payload: LIMITS_V1.payload + 1 })).toThrow(RangeError);
    expect(() => lowerLimits({ cryptographicAttempts: 17 })).toThrow(RangeError);
  });

  test('rejects non-integer and negative values', () => {
    expect(() => lowerLimits({ payload: -1 })).toThrow(RangeError);
    expect(() => lowerLimits({ payload: 1.5 })).toThrow(RangeError);
    expect(() => lowerLimits({ payload: Number.NaN })).toThrow(RangeError);
  });

  test('ignores absent overrides rather than treating them as zero', () => {
    expect(lowerLimits({}).payload).toBe(LIMITS_V1.payload);
    expect(lowerLimits({ payload: undefined }).payload).toBe(LIMITS_V1.payload);
  });

  test('allows zero as an explicit lower bound', () => {
    expect(lowerLimits({ redirects: 0 }).redirects).toBe(0);
  });
});

describe('limits reaching an operation are validated', () => {
  test('rejects a value raised above the baseline', () => {
    // `Limits` is structural and spreading a real one carries its brand, so the
    // type alone cannot stop an inflated bound reaching a public entry point.
    const raised = { ...LIMITS_V1, payload: LIMITS_V1.payload + 1 } as Limits;
    expect(checkLimits(raised)).toBe('limit_payload_exceeds_baseline');
  });

  test('rejects a missing or non-integer value', () => {
    const { payload: _removed, ...incomplete } = LIMITS_V1;
    expect(checkLimits(incomplete as Limits)).toBe('limit_payload_invalid');
    expect(checkLimits({ ...LIMITS_V1, payload: 1.5 } as Limits)).toBe('limit_payload_invalid');
    expect(checkLimits({ ...LIMITS_V1, payload: -1 } as Limits)).toBe('limit_payload_invalid');
  });

  test('accepts the baseline and anything lowered from it', () => {
    expect(checkLimits(LIMITS_V1)).toBeUndefined();
    expect(checkLimits(lowerLimits({ payload: 1 }))).toBeUndefined();
  });
});

describe('public operations refuse unvalidated limits', () => {
  test('a JWS creator rejects an inflated bound', async () => {
    const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const parsed = parseJson(
      new TextEncoder().encode(JSON.stringify(generated.privateKey.export({ format: 'jwk' }))),
      LIMITS_V1,
    );
    if (!parsed.ok || parsed.value.kind !== 'object') {
      throw new Error('bad fixture');
    }
    const imported = importKey(parsed.value, { algorithm: 'ES256', operation: 'sign' });
    if (!imported.ok) {
      throw new Error('import failed');
    }

    const result = await signCompact(new TextEncoder().encode('{}'), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      key: imported.key,
      limits: { ...LIMITS_V1, payload: LIMITS_V1.payload + 1 } as Limits,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('limit_payload_exceeds_baseline');
    }
  });
});
