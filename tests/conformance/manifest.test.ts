import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { validateManifest, type ManifestIssue, type TraceabilityManifest } from './manifest.ts';

const inventory = {
  specificationVersion: '1.0.11',
  requirementIds: new Set(['ENC-01', 'TEST-06']),
  artifactIds: new Set(['tests/unit/encoding.test.ts', 'reviews/release.md']),
};

const valid: TraceabilityManifest = {
  specificationVersion: '1.0.11',
  requirements: {
    'ENC-01': ['encoding-positive', 'encoding-negative'],
    'TEST-06': ['manifest-review'],
  },
  evidence: [
    {
      id: 'encoding-positive',
      kind: 'positive_fixture',
      artifact: 'tests/unit/encoding.test.ts',
      requirements: ['ENC-01'],
    },
    {
      id: 'encoding-negative',
      kind: 'negative_fixture',
      artifact: 'tests/unit/encoding.test.ts',
      requirements: ['ENC-01'],
    },
    {
      id: 'manifest-review',
      kind: 'security_review',
      artifact: 'reviews/release.md',
      requirements: ['TEST-06'],
    },
  ],
};

/** Asserts deep membership, reporting the whole list so a miss is diagnosable. */
function assertContainsEqual(issues: readonly ManifestIssue[], expected: ManifestIssue): void {
  const found = issues.some((issue) => {
    try {
      assert.deepStrictEqual(issue, expected);
      return true;
    } catch {
      return false;
    }
  });
  assert.ok(found, `expected ${JSON.stringify(expected)} among ${JSON.stringify(issues)}`);
}

describe('conformance traceability manifest', () => {
  test('accepts a complete bidirectional mapping', () => {
    assert.deepStrictEqual(validateManifest(valid, inventory), []);
  });

  test('rejects stale, orphaned, uncovered, and unattributed records', () => {
    const issues = validateManifest(
      {
        specificationVersion: '1.0.10',
        requirements: { 'ENC-01': ['missing'] },
        evidence: [
          {
            id: 'orphan',
            kind: 'non_executable',
            artifact: 'missing.md',
            requirements: [],
          },
        ],
      },
      inventory,
    );

    assert.deepStrictEqual(
      new Set(issues.map((issue) => issue.kind)),
      new Set([
        'stale_specification_version',
        'unknown_artifact',
        'unattributed_evidence',
        'missing_non_executable_reason',
        'missing_review_artifact',
        'inconsistent_reverse_mapping',
        'uncovered_requirement',
      ]),
    );
  });

  test('rejects duplicate evidence and mismatched forward mappings', () => {
    const issues = validateManifest(
      {
        ...valid,
        requirements: { ...valid.requirements, 'ENC-01': ['encoding-positive'] },
        evidence: [...valid.evidence, valid.evidence[0]!],
      },
      inventory,
    );

    assertContainsEqual(issues, { kind: 'duplicate_evidence_id', value: 'encoding-positive' });
    assertContainsEqual(issues, { kind: 'inconsistent_reverse_mapping', value: 'encoding-negative:ENC-01' });
  });

  test('rejects an unknown requirement used only as a forward-map key', () => {
    const issues = validateManifest(
      {
        ...valid,
        requirements: { ...valid.requirements, 'ORPHAN-01': ['encoding-positive'] },
      },
      inventory,
    );

    assertContainsEqual(issues, { kind: 'unknown_requirement', value: 'ORPHAN-01' });
  });
});
