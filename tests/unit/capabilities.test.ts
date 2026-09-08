import { describe, expect, test } from 'bun:test';
import { getCapabilityReport } from '../../src/capabilities.ts';

describe('capability reporting', () => {
  test('reports only implemented and enabled release capabilities', () => {
    const report = getCapabilityReport();

    expect(report.specificationVersion).toBe('1.0.11');
    for (const direction of [report.algorithms.jws.create, report.algorithms.jws.receive]) {
      expect(direction).not.toContain('Ed25519');
      expect(direction).not.toContain('Ed448');
      expect(direction).not.toContain('ML-DSA-44');
      expect(direction).not.toContain('none');
    }
    expect(report.algorithms.jwe_alg.create).not.toContain('RSA1_5');
    expect(report.algorithms.jwe_alg.receive).not.toContain('RSA1_5');
    expect(report.profiles).toEqual(['project-jwt-v1', 'project-single-use-jwt-v1', 'oauth-at-jwt-v1']);
    expect(report.curves).not.toContain('Ed448');
  });

  test('reports each direction separately', () => {
    const report = getCapabilityReport();

    // A receive-only legacy algorithm must not appear as available for creation:
    // reporting one undifferentiated set would tell a caller it may select an
    // algorithm that policy then refuses to produce with.
    expect(report.algorithms.jwe_alg.receive).toContain('RSA-OAEP');
    expect(report.algorithms.jwe_alg.create).not.toContain('RSA-OAEP');

    // A required algorithm is available in both directions.
    expect(report.algorithms.jws.create).toContain('ES256');
    expect(report.algorithms.jws.receive).toContain('ES256');
  });

  test('names the actual backend combination', () => {
    const report = getCapabilityReport();

    // Dispatch uses both providers, so naming only one would misreport what
    // executes the cryptography.
    expect(report.backend.name).toBe('webcrypto+node:crypto');
    expect(report.backend.providers).toEqual(['WebCrypto', 'node:crypto']);
  });

  test('states the required capabilities this build cannot offer', () => {
    const report = getCapabilityReport();

    // Ed25519 is a required capability with no qualified backend. The gap is
    // stated rather than left as an absence a caller would have to infer.
    const gap = report.requiredCapabilityGaps.find((entry) => entry.identifier === 'Ed25519');
    expect(gap).toBeDefined();
    expect(gap!.use).toBe('jws');
    expect(gap!.reason).toBe('no_qualified_backend');

    expect(report.fullSuiteConformant).toBe(false);
  });

  test('does not expose mutable capability state', () => {
    const report = getCapabilityReport();

    expect(Object.isFrozen(report)).toBe(true);
    expect(Object.isFrozen(report.algorithms)).toBe(true);
    expect(Object.isFrozen(report.algorithms.jws)).toBe(true);
    expect(Object.isFrozen(report.algorithms.jws.create)).toBe(true);
    expect(Object.isFrozen(report.requiredCapabilityGaps)).toBe(true);
    expect(Object.isFrozen(report.limits)).toBe(true);
  });
});
