import { describe, expect, test } from 'bun:test';
import { validateManifest, type TraceabilityManifest } from './manifest.ts';

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

describe('conformance traceability manifest', () => {
  test('accepts a complete bidirectional mapping', () => {
    expect(validateManifest(valid, inventory)).toEqual([]);
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

    expect(new Set(issues.map((issue) => issue.kind))).toEqual(
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

    expect(issues).toContainEqual({ kind: 'duplicate_evidence_id', value: 'encoding-positive' });
    expect(issues).toContainEqual({ kind: 'inconsistent_reverse_mapping', value: 'encoding-negative:ENC-01' });
  });

  test('rejects an unknown requirement used only as a forward-map key', () => {
    const issues = validateManifest(
      {
        ...valid,
        requirements: { ...valid.requirements, 'ORPHAN-01': ['encoding-positive'] },
      },
      inventory,
    );

    expect(issues).toContainEqual({ kind: 'unknown_requirement', value: 'ORPHAN-01' });
  });
});
