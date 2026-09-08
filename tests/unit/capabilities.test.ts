import { describe, expect, test } from 'bun:test';
import { getCapabilityReport } from '../../src/capabilities.ts';

describe('capability reporting', () => {
  test('reports only implemented and enabled release capabilities', () => {
    const report = getCapabilityReport();

    expect(report.specificationVersion).toBe('1.0.11');
    expect(report.algorithms.jws).not.toContain('Ed25519');
    expect(report.algorithms.jws).not.toContain('Ed448');
    expect(report.algorithms.jws).not.toContain('ML-DSA-44');
    expect(report.algorithms.jws).not.toContain('none');
    expect(report.algorithms.jwe_alg).not.toContain('RSA1_5');
    expect(report.profiles).toEqual(['project-jwt-v1', 'project-single-use-jwt-v1', 'oauth-at-jwt-v1']);
    expect(report.curves).not.toContain('Ed448');
  });

  test('does not expose mutable capability state', () => {
    const report = getCapabilityReport();

    expect(Object.isFrozen(report)).toBe(true);
    expect(Object.isFrozen(report.algorithms)).toBe(true);
    expect(Object.isFrozen(report.algorithms.jws)).toBe(true);
    expect(Object.isFrozen(report.limits)).toBe(true);
  });
});
