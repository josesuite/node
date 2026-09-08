import { implementedAlgorithms, isQualifiedAlgorithm, type AlgorithmUse } from './algorithms/registry.ts';
import type { Limits } from './policy/limits.ts';
import { LIMITS_V1 } from './policy/limits.ts';

export interface CapabilityReport {
  readonly specificationVersion: '1.0.11';
  readonly algorithms: Readonly<Record<AlgorithmUse, readonly string[]>>;
  readonly curves: readonly string[];
  readonly serializations: readonly string[];
  readonly profiles: readonly string[];
  readonly backend: {
    readonly name: 'node:crypto';
    readonly restrictions: readonly string[];
  };
  readonly limits: Readonly<Limits>;
}

/**
 * Implemented but not qualified on every supported runtime, so they are withheld
 * from the report: advertising a capability that a given deployment's provider
 * may not offer would let a caller select an algorithm that then fails at use.
 */
function algorithms(use: AlgorithmUse): readonly string[] {
  return Object.freeze(
    implementedAlgorithms(use)
      .map(({ identifier }) => identifier)
      .filter(isQualifiedAlgorithm),
  );
}

export function getCapabilityReport(limits: Limits = LIMITS_V1): CapabilityReport {
  return Object.freeze({
    specificationVersion: '1.0.11',
    algorithms: Object.freeze({
      jws: algorithms('jws'),
      jwe_alg: algorithms('jwe_alg'),
      jwe_enc: algorithms('jwe_enc'),
    }),
    curves: Object.freeze(['P-256', 'P-384', 'P-521', 'secp256k1', 'X25519', 'X448']),
    serializations: Object.freeze([
      'JWS Compact',
      'JWS Flattened JSON',
      'JWS General JSON',
      'JWE Compact',
      'JWE Flattened JSON',
      'JWE General JSON',
    ]),
    profiles: Object.freeze(['project-jwt-v1', 'project-single-use-jwt-v1', 'oauth-at-jwt-v1']),
    backend: Object.freeze({
      name: 'node:crypto',
      restrictions: Object.freeze([
        'Managed-memory secret zeroization is best effort',
        'Remote key resolution and certificate trust are unavailable',
        'Ed25519, Ed448, compression, and post-quantum algorithms are unqualified',
      ]),
    }),
    limits: Object.freeze({ ...limits }),
  });
}
