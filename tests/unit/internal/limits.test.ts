import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import { signCompact } from '../../../src/jws/sign.ts';
import { importKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { checkLimits, LIMITS_V1, type Limits, lowerLimits } from '../../../src/policy/limits.ts';

describe('LIMIT-01 limits-v1 baseline', () => {
  test('matches the published limits-v1 defaults', () => {
    assert.strictEqual(LIMITS_V1.jwtInput, 16 * 1024);
    assert.strictEqual(LIMITS_V1.joseInput, 1024 * 1024);
    assert.strictEqual(LIMITS_V1.headerSource, 8 * 1024);
    assert.strictEqual(LIMITS_V1.totalHeaderSource, 32 * 1024);
    assert.strictEqual(LIMITS_V1.payload, 256 * 1024);
    assert.strictEqual(LIMITS_V1.ciphertext, 512 * 1024);
    assert.strictEqual(LIMITS_V1.externalAad, 16 * 1024);
    assert.strictEqual(LIMITS_V1.jsonDepth, 32);
    assert.strictEqual(LIMITS_V1.jsonObjectMembers, 128);
    assert.strictEqual(LIMITS_V1.mergedHeaderMembers, 64);
    assert.strictEqual(LIMITS_V1.jsonArrayElements, 1024);
    assert.strictEqual(LIMITS_V1.jsonNodes, 65_536);
    assert.strictEqual(LIMITS_V1.signatures, 8);
    assert.strictEqual(LIMITS_V1.recipients, 8);
    assert.strictEqual(LIMITS_V1.cryptographicLayers, 2);
    assert.strictEqual(LIMITS_V1.candidateKeys, 1);
    assert.strictEqual(LIMITS_V1.cryptographicAttempts, 16);
    assert.strictEqual(LIMITS_V1.rsaModulusBits, 8192);
    assert.strictEqual(LIMITS_V1.symmetricKeyOctets, 128);
    assert.strictEqual(LIMITS_V1.pbes2IterationsMin, 100_000);
    assert.strictEqual(LIMITS_V1.pbes2IterationsMax, 1_000_000);
    assert.strictEqual(LIMITS_V1.decompressionRatio, 20);
    assert.strictEqual(LIMITS_V1.networkAttempts, 1);
    assert.strictEqual(LIMITS_V1.redirects, 0);
  });

  test('is frozen so an operation cannot mutate the shared baseline', () => {
    assert.strictEqual(Object.isFrozen(LIMITS_V1), true);
  });
});

describe('lowerLimits', () => {
  test('applies a lowered value and leaves the rest at the baseline', () => {
    const limits = lowerLimits({ payload: 1024 });
    assert.strictEqual(limits.payload, 1024);
    assert.strictEqual(limits.joseInput, LIMITS_V1.joseInput);
    assert.strictEqual(Object.isFrozen(limits), true);
  });

  test('permits a value equal to the baseline', () => {
    assert.strictEqual(lowerLimits({ signatures: LIMITS_V1.signatures }).signatures, 8);
  });

  test('rejects raising a limit above the reviewed baseline', () => {
    // The baseline permits lowering only; raising needs a named reviewed profile.
    assert.throws(() => lowerLimits({ payload: LIMITS_V1.payload + 1 }), RangeError);
    assert.throws(() => lowerLimits({ cryptographicAttempts: 17 }), RangeError);
  });

  test('rejects non-integer and negative values', () => {
    assert.throws(() => lowerLimits({ payload: -1 }), RangeError);
    assert.throws(() => lowerLimits({ payload: 1.5 }), RangeError);
    assert.throws(() => lowerLimits({ payload: Number.NaN }), RangeError);
  });

  test('ignores absent overrides rather than treating them as zero', () => {
    assert.strictEqual(lowerLimits({}).payload, LIMITS_V1.payload);
  });

  test('allows zero as an explicit lower bound', () => {
    assert.strictEqual(lowerLimits({ redirects: 0 }).redirects, 0);
  });
});

describe('limits reaching an operation are validated', () => {
  test('rejects a value raised above the baseline', () => {
    // `Limits` is structural and spreading a real one carries its brand, so the
    // type alone cannot stop an inflated bound reaching a public entry point.
    const raised = { ...LIMITS_V1, payload: LIMITS_V1.payload + 1 } as Limits;
    assert.strictEqual(checkLimits(raised), 'limit_payload_exceeds_baseline');
  });

  test('rejects a missing or non-integer value', () => {
    const { payload: _removed, ...incomplete } = LIMITS_V1;
    assert.strictEqual(checkLimits(incomplete as Limits), 'limit_payload_invalid');
    assert.strictEqual(checkLimits({ ...LIMITS_V1, payload: 1.5 } as Limits), 'limit_payload_invalid');
    assert.strictEqual(checkLimits({ ...LIMITS_V1, payload: -1 } as Limits), 'limit_payload_invalid');
  });

  test('accepts the baseline and anything lowered from it', () => {
    assert.strictEqual(checkLimits(LIMITS_V1), undefined);
    assert.strictEqual(checkLimits(lowerLimits({ payload: 1 })), undefined);
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

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'limit_payload_exceeds_baseline');
    }
  });
});
