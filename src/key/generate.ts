/**
 * Policy-bound key generation.
 *
 * Generation produces a JWK and then admits it through the ordinary import
 * path, so a generated key reaches the caller having passed exactly the checks
 * an imported one does and carrying the same single-algorithm, single-operation
 * binding. Returning a key straight from the provider would create a second
 * admission path, and the two would eventually disagree about what is
 * acceptable.
 *
 * Parameters come from the requested algorithm and from trusted configuration,
 * never from a provider default. A backend's own defaults have changed across
 * releases and are not a policy this library can inherit: RSA-02 fixes the
 * exponent at 65,537 and the modern modulus floor at 3,072 bits, and those are
 * applied here rather than assumed.
 */

import { generateKeyPair as nodeGenerateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

import { contentEncryptionShape } from '../algorithms/content-encryption/index.ts';
import { hmacOutputBytes } from '../algorithms/jws/hmac.ts';
import { keyManagementShape } from '../algorithms/jwe/index.ts';
import { isQualifiedAlgorithm, lookupAlgorithm } from '../algorithms/registry.ts';
import type { ErrorCategory } from '../errors/codes.ts';
import { type ImportResult, importKeyBytes, type UsableKey } from './import.ts';
import type { EcCurve, KeyOperation } from './types.ts';
import { type Limits, LIMITS_V1 } from '../policy/limits.ts';

/** RSA-02: the only public exponent this library generates. */
const RSA_EXPONENT = 65537;

/** RSA-02: modern-profile modulus floor. Generation never uses a legacy size. */
const RSA_MINIMUM_MODULUS_BITS = 3072;

export interface GenerateKeyOptions {
  /** The single algorithm the generated key is bound to. */
  readonly algorithm: string;
  /**
   * Content algorithms a key-management key may protect or recover.
   *
   * Required for every `jwe_alg` identifier, carrying the same binding an
   * imported key-management key must supply.
   */
  readonly contentAlgorithms?: readonly string[];
  /**
   * Curve for an algorithm that does not name one.
   *
   * ECDSA identifiers fix their own curve, so this is required only where the
   * algorithm genuinely leaves the choice open, and it is then supplied by
   * configuration rather than inferred.
   */
  readonly curve?: EcCurve;
  /**
   * RSA modulus size in bits. Defaults to the modern floor.
   *
   * A larger value is accepted up to the resource limit; a smaller one is
   * refused, because generation has no compatibility case for a legacy size.
   */
  readonly modulusBits?: number;
  readonly limits?: Limits;
}

/**
 * A generated asymmetric pair, with each half bound to its own operation.
 *
 * The two are separate keys rather than one key granted every operation: a
 * signing key that also verifies, or a decryption key that also encrypts,
 * widens what a single compromised value permits.
 */
export interface GeneratedKeyPair {
  readonly privateKey: UsableKey;
  readonly publicKey: UsableKey;
}

export type GenerateKeyPairResult =
  | { readonly ok: true; readonly keys: GeneratedKeyPair }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

export type GenerateSecretResult =
  | { readonly ok: true; readonly key: UsableKey }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(
  reason: string,
  category: ErrorCategory = 'policy_violation',
): {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly reason: string;
} {
  return { ok: false, category, reason };
}

/** Operation pair each generated asymmetric family binds its two halves to. */
const KEY_PAIR_OPERATIONS: Readonly<Record<string, readonly [KeyOperation, KeyOperation]>> = Object.freeze({
  jws: ['sign', 'verify'],
  key_transport: ['unwrapKey', 'wrapKey'],
  direct_agreement: ['deriveKey', 'deriveKey'],
  agreement_with_wrapping: ['deriveKey', 'deriveKey'],
});

type EligibilityFailure = { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

/**
 * Confirms an identifier may be generated for at all.
 *
 * Generation is a creation operation, so a receive-only legacy identifier is
 * refused here rather than producing a key that could only ever verify or
 * decrypt. Import applies the same rule, but reporting it before generating
 * keeps an expensive RSA generation from running for a request that cannot
 * succeed.
 */
function checkCreationEligibility(algorithm: string): EligibilityFailure | undefined {
  if (!isQualifiedAlgorithm(algorithm)) {
    return reject('algorithm_not_qualified', 'unsupported_algorithm');
  }

  const descriptor = lookupAlgorithm(algorithm, 'jws') ?? lookupAlgorithm(algorithm, 'jwe_alg');
  if (descriptor === undefined || descriptor.category === 'unspecified') {
    return reject('algorithm_unsupported_for_generation', 'unsupported_algorithm');
  }
  if (descriptor.category === 'prohibited') {
    return reject('prohibited_algorithm', 'prohibited_algorithm');
  }
  if (!descriptor.canCreate) {
    return reject('algorithm_receive_only');
  }

  return undefined;
}

type SizeResult = { readonly ok: true; readonly value: number } | EligibilityFailure;

/** Resolves the exact secret size the requested algorithm fixes. */
function secretBytes(options: GenerateKeyOptions): SizeResult {
  const hmacBytes = hmacOutputBytes(options.algorithm);
  if (hmacBytes !== undefined) {
    return { ok: true, value: hmacBytes };
  }

  const shape = keyManagementShape(options.algorithm);
  if (shape === undefined) {
    return reject('algorithm_requires_a_key_pair_not_a_secret', 'incompatible_key');
  }

  if (shape.mode === 'direct') {
    // `dir` uses the content algorithm's CEK directly, so its size is that
    // algorithm's, and exactly one content algorithm may be bound.
    const contentAlgorithms = options.contentAlgorithms;
    if (contentAlgorithms === undefined || contentAlgorithms.length !== 1) {
      return reject('direct_requires_one_content_algorithm');
    }
    const content = contentEncryptionShape(contentAlgorithms[0]!);
    if (content === undefined) {
      return reject('content_algorithm_unsupported', 'unsupported_algorithm');
    }
    return { ok: true, value: content.cekBytes };
  }

  const aesBytes = AES_KEY_BYTES[options.algorithm];
  if (aesBytes !== undefined) {
    return { ok: true, value: aesBytes };
  }

  return reject('algorithm_requires_a_key_pair_not_a_secret', 'incompatible_key');
}

/** AES key size in octets for each symmetric key-management identifier. */
const AES_KEY_BYTES: Readonly<Record<string, number>> = Object.freeze({
  A128KW: 16,
  A192KW: 24,
  A256KW: 32,
  A128GCMKW: 16,
  A192GCMKW: 24,
  A256GCMKW: 32,
});

/** Curve each ECDSA identifier fixes, so it is never taken from configuration. */
const ECDSA_CURVES: Readonly<Record<string, EcCurve>> = Object.freeze({
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
  ES256K: 'secp256k1',
});

/** Provider curve names, keyed by the JOSE curve identifier. */
const PROVIDER_CURVES: Readonly<Record<string, string>> = Object.freeze({
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  secp256k1: 'secp256k1',
});

/** Curves an agreement algorithm may use, since it names none itself. */
const AGREEMENT_CURVES: ReadonlySet<string> = new Set<EcCurve>(['P-256', 'P-384', 'P-521']);

/**
 * A provider-exported JWK, treated as opaque JSON.
 *
 * The members are never read here: the material goes straight to the importer,
 * which is the component that decides what a valid key looks like.
 */
type ExportedJwk = Readonly<Record<string, unknown>>;

type MaterialResult =
  | { readonly ok: true; readonly privateJwk: ExportedJwk; readonly publicJwk: ExportedJwk }
  | EligibilityFailure;

const generateKeyPairAsync = promisify(nodeGenerateKeyPair);

/**
 * Produces raw key material from the provider as a JWK pair.
 *
 * Asymmetric generation is asynchronous because RSA generation is expensive
 * enough to stall an event loop for a noticeable interval at these sizes.
 */
async function generateMaterial(options: GenerateKeyOptions): Promise<MaterialResult> {
  const limits = options.limits ?? LIMITS_V1;

  if (options.algorithm.startsWith('RSA-OAEP') || /^(RS|PS)(256|384|512)$/.test(options.algorithm)) {
    const modulusBits = options.modulusBits ?? RSA_MINIMUM_MODULUS_BITS;
    if (!Number.isSafeInteger(modulusBits) || modulusBits < RSA_MINIMUM_MODULUS_BITS) {
      return reject('modulus_below_modern_floor');
    }
    if (modulusBits > limits.rsaModulusBits) {
      return reject('modulus_too_large', 'resource_limit');
    }
    return exportRsaPair(modulusBits);
  }

  const ecdsaCurve = ECDSA_CURVES[options.algorithm];
  if (ecdsaCurve !== undefined) {
    // The identifier fixes the curve, so a conflicting configured curve is a
    // contradiction rather than a value to prefer one way or the other.
    if (options.curve !== undefined && options.curve !== ecdsaCurve) {
      return reject('curve_not_eligible_for_algorithm', 'incompatible_key');
    }
    return exportEcPair(ecdsaCurve);
  }

  const mode = keyManagementShape(options.algorithm)?.mode;
  if (mode === 'direct_agreement' || mode === 'agreement_with_wrapping') {
    const curve = options.curve;
    if (curve === undefined) {
      return reject('curve_required_for_agreement_algorithm');
    }
    if (!AGREEMENT_CURVES.has(curve)) {
      return reject('curve_not_eligible_for_algorithm', 'incompatible_key');
    }
    return exportEcPair(curve);
  }

  // No currently registered creation algorithm reaches this point; the earlier
  // eligibility and operation-family checks account for every one. It stays as
  // a fail-closed default so that adding a registry row without adding its
  // generation parameters refuses the request rather than producing a key from
  // provider defaults.
  return reject('algorithm_unsupported_for_generation', 'unsupported_algorithm');
}

/**
 * A provider failure is reported as a backend failure carrying no detail from
 * the underlying error, which could otherwise quote key material.
 */
async function exportRsaPair(modulusBits: number): Promise<MaterialResult> {
  try {
    const pair = await generateKeyPairAsync('rsa', {
      modulusLength: modulusBits,
      publicExponent: RSA_EXPONENT,
      publicKeyEncoding: { format: 'jwk' },
      privateKeyEncoding: { format: 'jwk' },
    });
    return asMaterial(pair);
  } catch {
    return reject('key_generation_failed', 'backend_failure');
  }
}

async function exportEcPair(curve: EcCurve): Promise<MaterialResult> {
  try {
    const pair = await generateKeyPairAsync('ec', {
      namedCurve: PROVIDER_CURVES[curve]!,
      publicKeyEncoding: { format: 'jwk' },
      privateKeyEncoding: { format: 'jwk' },
    });
    return asMaterial(pair);
  } catch {
    return reject('key_generation_failed', 'backend_failure');
  }
}

/**
 * The `jwk` encoding is declared to the provider above, but its overloads type
 * the result by the encoding's string/Buffer forms rather than by the object
 * a `jwk` export actually returns, so the shape is restated here.
 */
function asMaterial(pair: { readonly publicKey: unknown; readonly privateKey: unknown }): MaterialResult {
  return {
    ok: true,
    privateJwk: pair.privateKey as ExportedJwk,
    publicJwk: pair.publicKey as ExportedJwk,
  };
}

interface AdmitOptions {
  readonly algorithm: string;
  readonly operation: KeyOperation;
  readonly contentAlgorithms: readonly string[] | undefined;
  readonly limits: Limits;
}

/**
 * Admits generated material through the ordinary import path.
 *
 * Serializing to JWK bytes rather than calling the parsed-object importer keeps
 * generation on the one public admission path, so generated and imported keys
 * cannot diverge in which checks they have passed.
 */
function admit(jwk: ExportedJwk, options: AdmitOptions): ImportResult {
  const bytes = new TextEncoder().encode(JSON.stringify(jwk));
  return importKeyBytes(
    bytes,
    {
      algorithm: options.algorithm,
      operation: options.operation,
      ...(options.contentAlgorithms === undefined ? {} : { contentAlgorithms: options.contentAlgorithms }),
    },
    options.limits,
  );
}
