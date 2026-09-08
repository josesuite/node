import { implementedAlgorithms, isQualifiedAlgorithm, type AlgorithmUse } from './algorithms/registry.ts';
import type { Limits } from './policy/limits.ts';
import { LIMITS_V1 } from './policy/limits.ts';

/**
 * Algorithms available in each direction.
 *
 * The directions are reported separately because an identifier available for
 * receiving is not necessarily available for creating: listing a receive-only
 * legacy algorithm in one undifferentiated set would tell a caller it may select
 * that algorithm to produce a token, which policy then refuses.
 */
export interface DirectionalAlgorithms {
  readonly create: readonly string[];
  readonly receive: readonly string[];
}

export interface CapabilityReport {
  readonly specificationVersion: '1.0.11';
  readonly algorithms: Readonly<Record<AlgorithmUse, DirectionalAlgorithms>>;
  readonly curves: readonly string[];
  readonly serializations: readonly string[];
  readonly profiles: readonly string[];
  readonly backend: {
    /** Both providers are named because dispatch uses each for different algorithms. */
    readonly name: 'webcrypto+node:crypto';
    readonly providers: readonly string[];
    readonly restrictions: readonly string[];
  };
  readonly limits: Readonly<Limits>;
}

/**
 * Implemented but not qualified on every supported runtime, so they are withheld
 * from the report: advertising a capability that a given deployment's provider
 * may not offer would let a caller select an algorithm that then fails at use.
 */
function algorithms(use: AlgorithmUse): DirectionalAlgorithms {
  const qualified = implementedAlgorithms(use).filter((entry) => isQualifiedAlgorithm(entry.identifier));
  return Object.freeze({
    create: Object.freeze(qualified.filter((entry) => entry.canCreate).map((entry) => entry.identifier)),
    receive: Object.freeze(qualified.filter((entry) => entry.canReceive).map((entry) => entry.identifier)),
  });
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
      name: 'webcrypto+node:crypto',
      // secp256k1 ECDSA and the AES-KW paths use the native module because
      // WebCrypto does not offer them on every supported runtime.
      providers: Object.freeze(['WebCrypto', 'node:crypto']),
      restrictions: Object.freeze([
        'Managed-memory secret zeroization is best effort',
        'Remote key resolution and certificate trust are unavailable',
        'Ed25519, Ed448, compression, and post-quantum algorithms are unqualified',
      ]),
    }),
    limits: Object.freeze({ ...limits }),
  });
}
