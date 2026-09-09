/**
 * Key import.
 *
 * Import is deliberately separate from parsing. Parsing yields untrusted
 * structure; import validates the complete object, its mathematical material,
 * and its purpose, then produces a key bound to exactly one algorithm and one
 * operation family by trusted configuration.
 *
 * No cryptographic operation runs with partially validated private material:
 * every check below completes before a usable key exists, so a malformed or
 * self-inconsistent key can never reach a signing or decryption call.
 */

import { ecdsaCurve } from '../algorithms/jws/ecdsa.ts';
import { hmacOutputBytes } from '../algorithms/jws/hmac.ts';
import {
  type AlgorithmDescriptor,
  type AlgorithmUse,
  isQualifiedAlgorithm,
  lookupAlgorithm,
} from '../algorithms/registry.ts';
import { keyManagementShape } from '../algorithms/jwe/index.ts';
import { contentEncryptionShape } from '../algorithms/content-encryption/index.ts';
import type { ErrorCategory } from '../errors/codes.ts';
import { deriveEcPublicPoint, deriveOkpPublicKey, validateEcPointOnCurve } from '../internal/crypto/node.ts';
import type { JsonObject } from '../internal/json/types.ts';
import { parseJson } from '../internal/json/parse.ts';
import type { KeyIdentity } from './identity.ts';
import { checkBinding, type KeyMetadata, readKeyMetadata } from './operations.ts';
import type { EcCurve, KeyOperation, OkpCurve } from './types.ts';
import type { Limits } from '../policy/limits.ts';
import { checkLimits, LIMITS_V1 } from '../policy/limits.ts';
import {
  type EcMaterial,
  type OkpMaterial,
  type RsaPrivateMaterial,
  type RsaPublicMaterial,
  validateEcMaterial,
  validateOctMaterial,
  validateOkpMaterial,
  validateRsaPrivate,
  validateRsaPublic,
} from './validation.ts';

/**
 * A key that has passed every validation and is bound to one algorithm and one
 * operation family.
 *
 * The identity is the canonical form used for equality decisions, so a private
 * key and its public half compare as one key. Secret material is not part of
 * any printable representation of this record.
 */
interface UsableKeyBase {
  readonly algorithm: string;
  readonly operation: KeyOperation;
  readonly contentAlgorithms: readonly string[];
  readonly identity: KeyIdentity;
  readonly metadata: KeyMetadata;
  readonly isPrivate: boolean;
}

/**
 * A discriminated union rather than one record with a widened `material` field,
 * so an adapter for one key type cannot be handed another type's material
 * without the compiler objecting.
 */
export type UsableKey =
  | (UsableKeyBase & {
      readonly keyType: 'RSA';
      readonly material: RsaPublicMaterial | RsaPrivateMaterial;
    })
  | (UsableKeyBase & { readonly keyType: 'EC'; readonly material: EcMaterial })
  | (UsableKeyBase & { readonly keyType: 'OKP'; readonly material: OkpMaterial })
  | (UsableKeyBase & { readonly keyType: 'oct'; readonly material: Uint8Array })
  | (UsableKeyBase & { readonly keyType: 'AKP'; readonly material: Uint8Array });

/** `Omit` applied across each member of a union rather than to the union. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type ImportResult =
  | { readonly ok: true; readonly key: UsableKey }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

export interface ImportOptions {
  /** The single algorithm this key is bound to; metadata may not widen it. */
  readonly algorithm: string;
  /** The single operation family this key is bound to. */
  readonly operation: KeyOperation;
  /** Content algorithms this key-management key may protect or recover. */
  readonly contentAlgorithms?: readonly string[];
  /**
   * Admits the smaller legacy RSA modulus range for verification of existing
   * tokens. Never permitted for creation.
   */
  readonly receiveOnly?: boolean;
  /** Minimum symmetric key size the bound algorithm requires. */
  readonly minimumSymmetricBytes?: number;
}

export function importKeyBytes(source: Uint8Array, options: ImportOptions, limits: Limits = LIMITS_V1): ImportResult {
  const limitDefect = checkLimits(limits);
  if (limitDefect !== undefined) {
    return reject(limitDefect, 'policy_violation');
  }
  if (source.length > limits.serializedJwk) {
    return reject('jwk_too_large', 'resource_limit');
  }
  const parsed = parseJson(source, limits);
  if (!parsed.ok) {
    return reject(
      'jwk_invalid_json',
      parsed.failure === 'resource_limit'
        ? 'resource_limit'
        : parsed.failure === 'duplicate_member'
          ? 'malformed_input'
          : 'invalid_encoding',
    );
  }
  return parsed.value.kind === 'object' ? importKey(parsed.value, options, limits) : reject('jwk_not_an_object');
}

const EC_CURVES: ReadonlySet<string> = new Set<EcCurve>(['P-256', 'P-384', 'P-521', 'secp256k1']);

const OKP_CURVES: ReadonlySet<string> = new Set<OkpCurve>(['Ed25519', 'Ed448', 'X25519', 'X448']);

function isEcCurve(value: string): value is EcCurve {
  return EC_CURVES.has(value);
}

function isOkpCurve(value: string): value is OkpCurve {
  return OKP_CURVES.has(value);
}

function reject(reason: string, category: ErrorCategory = 'invalid_key'): ImportResult {
  return { ok: false, category, reason };
}

/** Any one of these marks the JWK private, including a CRT member without `d`. */
const RSA_PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as const;

/** Key type each JWS algorithm family requires, by identifier prefix. */
const JWS_KEY_TYPES: readonly (readonly [RegExp, UsableKey['keyType']])[] = [
  [/^HS(256|384|512)$/, 'oct'],
  [/^(RS|PS)(256|384|512)$/, 'RSA'],
  [/^ES(256|384|512|256K)$/, 'EC'],
  [/^(Ed25519|Ed448|EdDSA)$/, 'OKP'],
];

/**
 * The registry says an identifier names a real capability; it does not say
 * which key the identifier needs. Without this an `oct` secret binds to `RS256`
 * and only fails later at dispatch, where the cause is no longer visible as a
 * configuration defect.
 */
function checkAlgorithmEligibility(
  partial: DistributiveOmit<UsableKey, 'algorithm' | 'operation' | 'contentAlgorithms'>,
  algorithm: string,
): { readonly category: ErrorCategory; readonly reason: string } | undefined {
  const keyManagement = keyManagementShape(algorithm);
  if (keyManagement !== undefined) {
    const requiredType =
      keyManagement.mode === 'key_transport'
        ? 'RSA'
        : keyManagement.mode === 'direct_agreement' || keyManagement.mode === 'agreement_with_wrapping'
          ? undefined
          : 'oct';
    if (requiredType !== undefined && partial.keyType !== requiredType) {
      return { category: 'incompatible_key', reason: 'key_type_not_eligible_for_algorithm' };
    }
    if (
      requiredType === undefined &&
      (partial.keyType !== 'EC' || partial.identity.kty !== 'EC') &&
      (partial.keyType !== 'OKP' ||
        partial.identity.kty !== 'OKP' ||
        (partial.identity.crv !== 'X25519' && partial.identity.crv !== 'X448'))
    ) {
      return { category: 'incompatible_key', reason: 'key_type_not_eligible_for_algorithm' };
    }
  }
  const required = JWS_KEY_TYPES.find(([pattern]) => pattern.test(algorithm))?.[1];
  if (required !== undefined && partial.keyType !== required) {
    return { category: 'incompatible_key', reason: 'key_type_not_eligible_for_algorithm' };
  }

  // ECDSA fixes its curve: P-256 signatures are not interchangeable with P-384,
  // and accepting a mismatch would let the curve be decided by the key rather
  // than by the bound algorithm.
  const curve = ecdsaCurve(algorithm);
  if (
    curve !== undefined &&
    partial.keyType === 'EC' &&
    partial.identity.kty === 'EC' &&
    partial.identity.crv !== curve
  ) {
    return { category: 'incompatible_key', reason: 'curve_not_eligible_for_algorithm' };
  }

  // A curve-named EdDSA identifier must match the key's curve.
  if (
    (algorithm === 'Ed25519' || algorithm === 'Ed448') &&
    partial.identity.kty === 'OKP' &&
    partial.identity.crv !== algorithm
  ) {
    return { category: 'incompatible_key', reason: 'curve_not_eligible_for_algorithm' };
  }

  // MAC-02 fixes the minimum secret size at the hash output length. This is a
  // requirement of the algorithm, not a caller-tunable policy.
  const minimum = hmacOutputBytes(algorithm);
  if (minimum !== undefined && partial.keyType === 'oct' && partial.material.length < minimum) {
    return { category: 'incompatible_key', reason: 'symmetric_key_too_short' };
  }

  return undefined;
}

function readCurve(jwk: JsonObject): string | undefined {
  const member = jwk.members.get('crv');
  return member?.kind === 'string' ? member.value : undefined;
}

/**
 * Imports a JWK as a usable key under the supplied trusted binding.
 *
 * Order matters here: the key's own structure and material are validated before
 * its metadata is checked against the binding, so a malformed key is reported as
 * malformed rather than as a binding mismatch.
 */
export function importKey(jwk: JsonObject, options: ImportOptions, limits: Limits = LIMITS_V1): ImportResult {
  const ktyMember = jwk.members.get('kty');
  if (ktyMember === undefined) {
    return reject('kty_missing');
  }
  if (ktyMember.kind !== 'string') {
    return reject('kty_not_a_string');
  }

  const metadataResult = readKeyMetadata(jwk, limits);
  if (!metadataResult.ok) {
    return { ok: false, category: metadataResult.category, reason: metadataResult.reason };
  }
  const metadata = metadataResult.metadata;

  const receiveOnly = options.receiveOnly ?? false;

  switch (ktyMember.value) {
    case 'RSA': {
      const publicResult = validateRsaPublic(jwk, { receiveOnly });
      if (!publicResult.ok) {
        return { ok: false, category: publicResult.category, reason: publicResult.reason };
      }
      if (publicResult.material.modulusBits > limits.rsaModulusBits) {
        return reject('modulus_too_large', 'resource_limit');
      }

      // Presence of any private member means the whole private group must be
      // present and consistent; a partial private key is never admitted.
      // Keying this on `d` alone would silently import a JWK carrying orphan
      // CRT members as a public key, discarding material the producer supplied
      // rather than reporting the malformed group.
      const isPrivate = RSA_PRIVATE_MEMBERS.some((name) => jwk.members.has(name));
      // The private members are carried on the key, not just validated: signing
      // needs the CRT group, and a key holding only `n` and `e` cannot sign.
      let material: RsaPublicMaterial | RsaPrivateMaterial = publicResult.material;
      if (isPrivate) {
        const privateResult = validateRsaPrivate(jwk, publicResult.material);
        if (!privateResult.ok) {
          return { ok: false, category: privateResult.category, reason: privateResult.reason };
        }
        material = privateResult.material;
      }

      return finish(
        {
          keyType: 'RSA',
          identity: {
            kty: 'RSA',
            n: publicResult.material.n,
            e: publicResult.material.e,
          },
          metadata,
          isPrivate,
          material,
        },
        options,
      );
    }

    case 'EC': {
      const curve = readCurve(jwk);
      if (curve === undefined) {
        return reject('crv_missing');
      }
      if (!isEcCurve(curve)) {
        return reject('crv_unsupported', 'incompatible_key');
      }

      const result = validateEcMaterial(jwk, curve, deriveEcPublicPoint, validateEcPointOnCurve);
      if (!result.ok) {
        return { ok: false, category: result.category, reason: result.reason };
      }
      return finish(
        {
          keyType: 'EC',
          identity: {
            kty: 'EC',
            crv: result.material.curve,
            x: result.material.x,
            y: result.material.y,
          },
          metadata,
          isPrivate: result.material.d !== undefined,
          material: result.material,
        },
        options,
      );
    }

    case 'OKP': {
      const curve = readCurve(jwk);
      if (curve === undefined) {
        return reject('crv_missing');
      }
      if (!isOkpCurve(curve)) {
        return reject('crv_unsupported', 'incompatible_key');
      }

      if (curve === 'Ed25519' || curve === 'Ed448') {
        return reject('curve_not_qualified', 'unsupported_algorithm');
      }

      const result = validateOkpMaterial(jwk, curve, deriveOkpPublicKey);
      if (!result.ok) {
        return { ok: false, category: result.category, reason: result.reason };
      }

      return finish(
        {
          keyType: 'OKP',
          identity: { kty: 'OKP', crv: result.material.curve, x: result.material.x },
          metadata,
          isPrivate: result.material.d !== undefined,
          material: result.material,
        },
        options,
      );
    }

    case 'oct': {
      const result = validateOctMaterial(jwk, options.minimumSymmetricBytes ?? 0);
      if (!result.ok) {
        return { ok: false, category: result.category, reason: result.reason };
      }
      if (result.key.length > limits.symmetricKeyOctets) {
        return reject('k_too_large', 'resource_limit');
      }

      return finish(
        {
          keyType: 'oct',
          identity: { kty: 'oct', k: result.key },
          metadata,
          // A symmetric key is always secret; there is no public half.
          isPrivate: true,
          material: result.key,
        },
        options,
      );
    }

    default:
      // An unknown key type has no interpretation here and is never loaded
      // dynamically or guessed at.
      return reject('kty_unsupported', 'incompatible_key');
  }
}

/**
 * Selector positions an operation family may bind an algorithm from.
 *
 * Signing and verification select from the signature position; every other
 * operation belongs to an encrypted object, where the identifier may name
 * either key management or content encryption.
 */
const POSITIONS_BY_OPERATION: Readonly<Record<KeyOperation, readonly AlgorithmUse[]>> = Object.freeze({
  sign: ['jws'],
  verify: ['jws'],
  encrypt: ['jwe_alg'],
  decrypt: ['jwe_alg'],
  wrapKey: ['jwe_alg'],
  unwrapKey: ['jwe_alg'],
  deriveKey: ['jwe_alg'],
});

function finish(
  partial: DistributiveOmit<UsableKey, 'algorithm' | 'operation' | 'contentAlgorithms'>,
  options: ImportOptions,
): ImportResult {
  if (!isQualifiedAlgorithm(options.algorithm)) {
    return { ok: false, category: 'unsupported_algorithm', reason: 'algorithm_not_qualified' };
  }
  // The bound identifier must name a real capability in a position the
  // operation can select from. Binding a key to an unrecognized or prohibited
  // string would otherwise produce a key that only fails much later, at
  // dispatch, where the cause is no longer visible as a configuration defect.
  let descriptor: AlgorithmDescriptor | undefined;
  for (const position of POSITIONS_BY_OPERATION[options.operation]) {
    const candidate = lookupAlgorithm(options.algorithm, position);
    if (candidate !== undefined) {
      descriptor = candidate;
      break;
    }
  }

  if (descriptor === undefined || descriptor.category === 'unspecified') {
    return { ok: false, category: 'unsupported_algorithm', reason: 'algorithm_unsupported_for_operation' };
  }
  if (descriptor.category === 'prohibited') {
    return { ok: false, category: 'prohibited_algorithm', reason: 'prohibited_algorithm' };
  }
  const shape = descriptor.use === 'jwe_alg' ? keyManagementShape(options.algorithm) : undefined;
  const validOperation =
    shape === undefined ||
    (shape.mode === 'direct'
      ? options.operation === 'encrypt' || options.operation === 'decrypt'
      : shape.mode === 'direct_agreement' || shape.mode === 'agreement_with_wrapping'
        ? options.operation === 'deriveKey'
        : options.operation === 'wrapKey' || options.operation === 'unwrapKey');
  if (!validOperation) {
    return reject('operation_not_eligible_for_algorithm', 'incompatible_key');
  }

  const creates =
    options.operation === 'sign' ||
    options.operation === 'encrypt' ||
    options.operation === 'wrapKey' ||
    (options.operation === 'deriveKey' && !partial.isPrivate);
  const contentAlgorithms = validateContentBinding(descriptor.use, options, creates);
  if (!contentAlgorithms.ok) {
    return contentAlgorithms;
  }
  if (options.algorithm === 'dir' && partial.keyType === 'oct') {
    const content = contentEncryptionShape(contentAlgorithms.value[0]!);
    if (content === undefined || partial.material.length !== content.cekBytes) {
      return reject('direct_key_size_mismatch', 'incompatible_key');
    }
  }
  if (creates && !descriptor.canCreate) {
    return { ok: false, category: 'policy_violation', reason: 'algorithm_receive_only' };
  }
  if (!creates && !descriptor.canReceive) {
    return { ok: false, category: 'policy_violation', reason: 'algorithm_creation_only' };
  }

  const eligibility = checkAlgorithmEligibility(partial, options.algorithm);
  if (eligibility !== undefined) {
    return { ok: false, category: eligibility.category, reason: eligibility.reason };
  }

  const binding = checkBinding(partial.metadata, options.algorithm, options.operation);
  if (!binding.ok) {
    // The key is well formed but does not satisfy the binding it is being used
    // under, which is a different condition from invalid material.
    return { ok: false, category: 'incompatible_key', reason: binding.reason };
  }

  return {
    ok: true,
    key: seal({
      ...partial,
      algorithm: options.algorithm,
      operation: options.operation,
      contentAlgorithms: contentAlgorithms.value,
    } as UsableKey),
  };
}

function validateContentBinding(
  use: AlgorithmUse,
  options: ImportOptions,
  creates: boolean,
):
  | { readonly ok: true; readonly value: readonly string[] }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string } {
  if (use !== 'jwe_alg') {
    return options.contentAlgorithms === undefined
      ? { ok: true, value: Object.freeze([]) }
      : { ok: false, category: 'policy_violation', reason: 'content_algorithms_not_applicable' };
  }

  const values = options.contentAlgorithms;
  if (values === undefined || values.length === 0 || new Set(values).size !== values.length) {
    return { ok: false, category: 'policy_violation', reason: 'content_algorithms_required' };
  }
  if (options.algorithm === 'dir' && values.length !== 1) {
    return { ok: false, category: 'policy_violation', reason: 'direct_requires_one_content_algorithm' };
  }
  for (const value of values) {
    const descriptor = lookupAlgorithm(value, 'jwe_enc');
    if (
      descriptor === undefined ||
      descriptor.category === 'prohibited' ||
      descriptor.category === 'unspecified' ||
      !isQualifiedAlgorithm(value) ||
      (creates ? !descriptor.canCreate : !descriptor.canReceive)
    ) {
      return { ok: false, category: 'unsupported_algorithm', reason: 'content_algorithm_not_qualified' };
    }
  }
  return { ok: true, value: Object.freeze([...values]) };
}

/**
 * Marks a record as having been produced by this module.
 *
 * The module-private set recognizes exact objects only, so a record assembled
 * elsewhere by copying or inheriting from a real key cannot gain trusted status.
 */
const IMPORTED_KEYS = new WeakSet<UsableKey>();

export function isImportedKey(key: UsableKey): boolean {
  return IMPORTED_KEYS.has(key);
}

/** Copies every `Uint8Array` in a flat material record, leaving scalars alone. */
function copyMaterial<T>(material: T): T {
  if (material instanceof Uint8Array) {
    return new Uint8Array(material) as T;
  }

  const copy: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(material as Record<string, unknown>)) {
    copy[name] = value instanceof Uint8Array ? new Uint8Array(value) : value;
  }
  return Object.freeze(copy) as T;
}

/**
 * Detaches a validated key from every array the caller can still reach and
 * makes its secret material unreachable by ordinary inspection.
 *
 * Three separate problems are closed here. The caller retains the arrays the
 * JWK was decoded from, so without copying it could change a key's bytes after
 * validation while the key kept its trusted status. The identity aliased the
 * same arrays as the material, so one mutation moved both the key and the value
 * used for equality decisions. And private material reached logs and error
 * reports through ordinary serialization and printing, so `material` is
 * non-enumerable and both `toJSON` and the inspect hook replace the whole key
 * with a description carrying no material at all. Making it non-enumerable
 * alone is not enough: some runtimes print non-enumerable properties anyway.
 *
 * This is defense in depth against accident and casual disclosure, not an
 * opaque handle: a managed runtime cannot prevent deliberate retrieval, and
 * copies of the material may persist until collected.
 */
function seal(key: UsableKey): UsableKey {
  const { material, identity, metadata, ...rest } = key;

  const describe = () => ({
    keyType: key.keyType,
    algorithm: key.algorithm,
    operation: key.operation,
    isPrivate: key.isPrivate,
    kid: metadata.kid,
  });

  const hidden = { enumerable: false, writable: false, configurable: false };
  const sealed = Object.defineProperties(
    { ...rest, identity: copyMaterial(identity), metadata: Object.freeze({ ...metadata }) },
    {
      material: { ...hidden, value: copyMaterial(material) },
      toJSON: { ...hidden, value: describe },
      // Node consults this symbol before its default formatting.
      [Symbol.for('nodejs.util.inspect.custom')]: { ...hidden, value: describe },
    },
  );

  const imported = Object.freeze(sealed) as UsableKey;
  IMPORTED_KEYS.add(imported);
  return imported;
}
