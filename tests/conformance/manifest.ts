export const SPECIFICATION_VERSION = '1.0.11';

export type EvidenceKind =
  | 'positive_fixture'
  | 'negative_fixture'
  | 'boundary_fixture'
  | 'property_test'
  | 'fuzz_target'
  | 'backend_test'
  | 'security_review'
  | 'non_executable';

export interface Evidence {
  readonly id: string;
  readonly kind: EvidenceKind;
  readonly artifact: string;
  readonly requirements: readonly string[];
  readonly reason?: string;
  readonly reviewArtifact?: string;
}

export interface TraceabilityManifest {
  readonly specificationVersion: string;
  readonly requirements: Readonly<Record<string, readonly string[]>>;
  readonly evidence: readonly Evidence[];
}

export interface ManifestInventory {
  readonly specificationVersion: string;
  readonly requirementIds: ReadonlySet<string>;
  readonly artifactIds: ReadonlySet<string>;
}

export type ManifestIssue =
  | { readonly kind: 'stale_specification_version'; readonly value: string }
  | { readonly kind: 'duplicate_evidence_id'; readonly value: string }
  | { readonly kind: 'unknown_requirement'; readonly value: string }
  | { readonly kind: 'unknown_artifact'; readonly value: string }
  | { readonly kind: 'uncovered_requirement'; readonly value: string }
  | { readonly kind: 'unattributed_evidence'; readonly value: string }
  | { readonly kind: 'missing_non_executable_reason'; readonly value: string }
  | { readonly kind: 'missing_review_artifact'; readonly value: string }
  | { readonly kind: 'inconsistent_reverse_mapping'; readonly value: string };

/** Validates both directions of traceability without reading source files. */
export function validateManifest(
  manifest: TraceabilityManifest,
  inventory: ManifestInventory,
): readonly ManifestIssue[] {
  const issues: ManifestIssue[] = [];
  const evidenceById = new Map<string, Evidence>();

  if (manifest.specificationVersion !== inventory.specificationVersion) {
    issues.push({ kind: 'stale_specification_version', value: manifest.specificationVersion });
  }

  for (const evidence of manifest.evidence) {
    if (evidenceById.has(evidence.id)) {
      issues.push({ kind: 'duplicate_evidence_id', value: evidence.id });
      continue;
    }
    evidenceById.set(evidence.id, evidence);

    if (!inventory.artifactIds.has(evidence.artifact)) {
      issues.push({ kind: 'unknown_artifact', value: evidence.artifact });
    }
    if (evidence.requirements.length === 0) {
      issues.push({ kind: 'unattributed_evidence', value: evidence.id });
    }
    if (evidence.kind === 'non_executable') {
      if (evidence.reason === undefined || evidence.reason.length === 0) {
        issues.push({ kind: 'missing_non_executable_reason', value: evidence.id });
      }
      if (evidence.reviewArtifact === undefined || !inventory.artifactIds.has(evidence.reviewArtifact)) {
        issues.push({ kind: 'missing_review_artifact', value: evidence.id });
      }
    }
    for (const requirement of evidence.requirements) {
      if (!inventory.requirementIds.has(requirement)) {
        issues.push({ kind: 'unknown_requirement', value: requirement });
      }
    }
  }

  for (const requirement of Object.keys(manifest.requirements)) {
    if (!inventory.requirementIds.has(requirement)) {
      issues.push({ kind: 'unknown_requirement', value: requirement });
    }
  }

  for (const requirement of inventory.requirementIds) {
    const evidenceIds = manifest.requirements[requirement];
    if (evidenceIds === undefined || evidenceIds.length === 0) {
      issues.push({ kind: 'uncovered_requirement', value: requirement });
      continue;
    }
    for (const evidenceId of evidenceIds) {
      const evidence = evidenceById.get(evidenceId);
      if (evidence === undefined || !evidence.requirements.includes(requirement)) {
        issues.push({ kind: 'inconsistent_reverse_mapping', value: `${requirement}:${evidenceId}` });
      }
    }
  }

  for (const evidence of manifest.evidence) {
    for (const requirement of evidence.requirements) {
      if (!manifest.requirements[requirement]?.includes(evidence.id)) {
        issues.push({ kind: 'inconsistent_reverse_mapping', value: `${evidence.id}:${requirement}` });
      }
    }
  }

  return issues;
}
