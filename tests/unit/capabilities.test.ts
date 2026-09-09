import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { getCapabilityReport } from '../../src/capabilities.ts';

describe('capability reporting', () => {
  test('reports only implemented and enabled release capabilities', () => {
    const report = getCapabilityReport();

    assert.strictEqual(report.specificationVersion, '1.0.11');
    for (const direction of [report.algorithms.jws.create, report.algorithms.jws.receive]) {
      assert.ok(!direction.includes('Ed25519'));
      assert.ok(!direction.includes('Ed448'));
      assert.ok(!direction.includes('ML-DSA-44'));
      assert.ok(!direction.includes('none'));
    }
    assert.ok(!report.algorithms.jwe_alg.create.includes('RSA1_5'));
    assert.ok(!report.algorithms.jwe_alg.receive.includes('RSA1_5'));
    assert.deepStrictEqual(report.profiles, ['project-jwt-v1', 'project-single-use-jwt-v1', 'oauth-at-jwt-v1']);
    assert.ok(!report.curves.includes('Ed448'));
  });

  test('reports each direction separately', () => {
    const report = getCapabilityReport();

    // A receive-only legacy algorithm must not appear as available for creation:
    // reporting one undifferentiated set would tell a caller it may select an
    // algorithm that policy then refuses to produce with.
    assert.ok(report.algorithms.jwe_alg.receive.includes('RSA-OAEP'));
    assert.ok(!report.algorithms.jwe_alg.create.includes('RSA-OAEP'));

    // A required algorithm is available in both directions.
    assert.ok(report.algorithms.jws.create.includes('ES256'));
    assert.ok(report.algorithms.jws.receive.includes('ES256'));
  });

  test('names the actual backend combination', () => {
    const report = getCapabilityReport();

    // Dispatch uses both providers, so naming only one would misreport what
    // executes the cryptography.
    assert.strictEqual(report.backend.name, 'webcrypto+node:crypto');
    assert.deepStrictEqual(report.backend.providers, ['WebCrypto', 'node:crypto']);
  });

  test('states the required capabilities this build cannot offer', () => {
    const report = getCapabilityReport();

    // Ed25519 is a required capability with no qualified backend. The gap is
    // stated rather than left as an absence a caller would have to infer.
    const gap = report.requiredCapabilityGaps.find((entry) => entry.identifier === 'Ed25519');
    assert.notStrictEqual(gap, undefined);
    assert.strictEqual(gap!.use, 'jws');
    assert.strictEqual(gap!.reason, 'no_qualified_backend');

    assert.strictEqual(report.fullSuiteConformant, false);
  });

  test('does not expose mutable capability state', () => {
    const report = getCapabilityReport();

    assert.strictEqual(Object.isFrozen(report), true);
    assert.strictEqual(Object.isFrozen(report.algorithms), true);
    assert.strictEqual(Object.isFrozen(report.algorithms.jws), true);
    assert.strictEqual(Object.isFrozen(report.algorithms.jws.create), true);
    assert.strictEqual(Object.isFrozen(report.requiredCapabilityGaps), true);
    assert.strictEqual(Object.isFrozen(report.limits), true);
  });
});
