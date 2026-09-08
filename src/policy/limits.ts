/**
 * The shared `limits-v1` baseline resource limits applied to untrusted input.
 *
 * Deployments may lower these values. Raising any of them requires a separate,
 * explicitly named configuration and a resource review, so this module exposes
 * no "unlimited" representation: every bound is finite by construction, and an
 * absent limit is not expressible.
 */

const KIB = 1024;
const MIB = 1024 * 1024;

/**
 * Marks a value as having passed `lowerLimits`.
 *
 * Without it `Limits` is a structural type, so an object literal with the right
 * shape satisfies it and reaches every operation without the baseline check
 * ever running. That is a way to raise a bound by passing a large number at a
 * call site, which is exactly what the lowering rule exists to prevent.
 */
declare const VALIDATED: unique symbol;

export interface Limits {
  readonly [VALIDATED]: true;
  /** Entire JWT serialized input, octets. */
  readonly jwtInput: number;
  /** Entire generic JOSE serialized input, octets. */
  readonly joseInput: number;
  /** One decoded protected header or one unprotected header source object. */
  readonly headerSource: number;
  /** All header source bytes across one JOSE object. */
  readonly totalHeaderSource: number;
  /** Decoded JWS payload or authenticated JWE plaintext. */
  readonly payload: number;
  readonly detachedPayload: number;
  readonly ciphertext: number;
  readonly externalAad: number;

  /** JSON container nesting, counting the root as depth one. */
  readonly jsonDepth: number;
  readonly jsonObjectMembers: number;
  readonly mergedHeaderMembers: number;
  readonly jsonArrayElements: number;
  /** Total parsed JSON scalar and container nodes per operation. */
  readonly jsonNodes: number;
  readonly jsonString: number;
  readonly numberLexeme: number;
  readonly numberExponentMagnitude: number;

  readonly signatures: number;
  readonly recipients: number;
  readonly cryptographicLayers: number;
  readonly candidateKeys: number;
  readonly cryptographicAttempts: number;

  readonly jwksKeys: number;
  readonly serializedJwk: number;
  readonly remoteJwksResponse: number;

  readonly rsaModulusBits: number;
  readonly symmetricKeyOctets: number;
  readonly signatureOctets: number;

  readonly kid: number;
  readonly jti: number;
  readonly identifier: number;
  /** Maximum length of an algorithm, curve, key-type, use, or operation name. */
  readonly algorithmName: number;
  readonly url: number;

  readonly certificateChain: number;
  readonly derCertificate: number;

  readonly pbes2Salt: number;
  readonly pbes2Password: number;
  readonly pbes2IterationsMin: number;
  readonly pbes2IterationsMax: number;
  readonly pbkdf2PrfEvaluations: number;

  readonly compressedInput: number;
  readonly decompressedOutput: number;
  readonly decompressionRatio: number;

  /** Connection deadline in milliseconds. */
  readonly remoteConnectionMs: number;
  readonly remoteRequestMs: number;
  readonly networkAttempts: number;
  readonly redirects: number;
  readonly concurrentRefreshesPerIssuer: number;
  readonly negativeCacheEntriesPerIssuer: number;
}

const BASELINE = Object.freeze({
  jwtInput: 16 * KIB,
  joseInput: MIB,
  headerSource: 8 * KIB,
  totalHeaderSource: 32 * KIB,
  payload: 256 * KIB,
  detachedPayload: 256 * KIB,
  ciphertext: 512 * KIB,
  externalAad: 16 * KIB,

  jsonDepth: 32,
  jsonObjectMembers: 128,
  mergedHeaderMembers: 64,
  jsonArrayElements: 1024,
  jsonNodes: 65_536,
  jsonString: 256 * KIB,
  numberLexeme: 128,
  numberExponentMagnitude: 308,

  signatures: 8,
  recipients: 8,
  cryptographicLayers: 2,
  candidateKeys: 1,
  cryptographicAttempts: 16,

  jwksKeys: 100,
  serializedJwk: 16 * KIB,
  remoteJwksResponse: MIB,

  rsaModulusBits: 8192,
  symmetricKeyOctets: 128,
  signatureOctets: 8 * KIB,

  kid: 256,
  jti: 256,
  identifier: 1024,
  algorithmName: 64,
  url: 2048,

  certificateChain: 5,
  derCertificate: 16 * KIB,

  pbes2Salt: 64,
  pbes2Password: 1024,
  pbes2IterationsMin: 100_000,
  pbes2IterationsMax: 1_000_000,
  pbkdf2PrfEvaluations: 1_000_000,

  compressedInput: 64 * KIB,
  decompressedOutput: 256 * KIB,
  decompressionRatio: 20,

  remoteConnectionMs: 2000,
  remoteRequestMs: 5000,
  networkAttempts: 1,
  redirects: 0,
  concurrentRefreshesPerIssuer: 1,
  negativeCacheEntriesPerIssuer: 100,
});

/** The baseline itself is a validated value: every entry equals its own bound. */
export const LIMITS_V1 = BASELINE as unknown as Limits;

type LimitName = keyof typeof BASELINE;

const LIMIT_KEYS = Object.keys(BASELINE) as readonly LimitName[];

/**
 * Builds an operation's limits by lowering the baseline.
 *
 * Only lowering is permitted. A value above the baseline is rejected rather
 * than silently accepted, so that raising a bound is a deliberate, reviewed act
 * and cannot happen by passing a large number at a call site.
 */
export function lowerLimits(overrides: Partial<Record<LimitName, number>>): Limits {
  const result: Record<string, number> = { ...BASELINE };

  for (const key of LIMIT_KEYS) {
    const override = overrides[key];
    if (override === undefined) {
      continue;
    }

    if (!Number.isSafeInteger(override) || override < 0) {
      throw new RangeError(`limit ${key} must be a non-negative safe integer`);
    }
    if (override > BASELINE[key]) {
      throw new RangeError(`limit ${key} exceeds the limits-v1 baseline`);
    }
    result[key] = override;
  }

  return Object.freeze(result) as unknown as Limits;
}

/**
 * Confirms a limits value is complete and no looser than the baseline.
 *
 * `Limits` is structural, and spreading a real one carries its brand, so the
 * type alone cannot stop a caller passing an inflated bound at a public entry
 * point. Checking here means an operation either runs under limits that were
 * genuinely lowered or does not run at all.
 */
export function checkLimits(limits: Limits): string | undefined {
  const values = limits as unknown as Partial<Record<LimitName, unknown>>;

  for (const key of LIMIT_KEYS) {
    const value = values[key];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
      return `limit_${key}_invalid`;
    }
    if (value > BASELINE[key]) {
      return `limit_${key}_exceeds_baseline`;
    }
  }

  return undefined;
}
