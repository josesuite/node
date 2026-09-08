/**
 * Closed algorithm descriptor table.
 *
 * This is a fixed implementation table, not a downloaded registry or a
 * provider-discovery mechanism. A registry refresh must never enlarge a
 * deployed allowlist on its own, so new identifiers appear here only through a
 * reviewed code change.
 *
 * Recognition is deliberately separate from enablement. An identifier present
 * here still requires the caller's explicit allowlist before any operation, and
 * a prohibited row is recognized only far enough to report the right error
 * rather than silently behaving as if the identifier were unknown.
 */

/**
 * Where an identifier may appear. An identifier selects an algorithm only in
 * the context it is registered for, which keeps a
 * content-encryption name carried inside a signed object from dispatching a
 * signature backend.
 */
export type AlgorithmUse = 'jws' | 'jwe_alg' | 'jwe_enc';

/**
 * Suite categories describe the implementation obligation for an algorithm,
 * independently of whether a deployment enables it.
 */
export type SuiteCategory =
  | 'required'
  | 'recommended'
  | 'optional'
  | 'legacy'
  | 'prohibited'
  /**
   * Registered elsewhere but deliberately given no parameters or implementation here, so
   * it is unavailable in both directions until a dedicated implementation
   * defines it.
   */
  | 'unspecified';

export interface AlgorithmDescriptor {
  readonly identifier: string;
  readonly use: AlgorithmUse;
  readonly category: SuiteCategory;
  /** Eligible for the default policy without a dedicated opt-in. */
  readonly defaultEligible: boolean;
  /** Permitted for creation when explicitly enabled. Legacy rows are receive-only. */
  readonly canCreate: boolean;
  /** Permitted for verification/decryption when explicitly enabled. */
  readonly canReceive: boolean;
}

function descriptor(
  identifier: string,
  use: AlgorithmUse,
  category: SuiteCategory,
  defaultEligible: boolean,
  canCreate: boolean,
  canReceive: boolean,
): AlgorithmDescriptor {
  return Object.freeze({ identifier, use, category, defaultEligible, canCreate, canReceive });
}

const JWS_ALGORITHMS: readonly AlgorithmDescriptor[] = [
  descriptor('HS256', 'jws', 'required', true, true, true),
  descriptor('HS384', 'jws', 'optional', false, true, true),
  descriptor('HS512', 'jws', 'recommended', true, true, true),
  descriptor('RS256', 'jws', 'required', true, true, true),
  descriptor('RS384', 'jws', 'optional', false, true, true),
  descriptor('RS512', 'jws', 'optional', false, true, true),
  descriptor('PS256', 'jws', 'required', true, true, true),
  descriptor('PS384', 'jws', 'optional', false, true, true),
  descriptor('PS512', 'jws', 'optional', false, true, true),
  descriptor('ES256', 'jws', 'required', true, true, true),
  descriptor('ES384', 'jws', 'recommended', true, true, true),
  descriptor('ES512', 'jws', 'optional', false, true, true),
  descriptor('ES256K', 'jws', 'optional', false, true, true),
  descriptor('Ed25519', 'jws', 'required', true, true, true),
  descriptor('Ed448', 'jws', 'optional', false, true, true),
  // Deprecated polymorphic identifier that does not name its own curve.
  // Receive-only, and never created or automatically aliased to a curve-
  // specific identifier: the curve must come from trusted key
  // policy instead.
  descriptor('EdDSA', 'jws', 'legacy', false, false, true),
  descriptor('ML-DSA-44', 'jws', 'optional', false, true, true),
  descriptor('ML-DSA-65', 'jws', 'optional', false, true, true),
  descriptor('ML-DSA-87', 'jws', 'optional', false, true, true),
  descriptor('none', 'jws', 'prohibited', false, false, false),
];

const JWE_KEY_MANAGEMENT: readonly AlgorithmDescriptor[] = [
  descriptor('dir', 'jwe_alg', 'required', true, true, true),
  descriptor('A128KW', 'jwe_alg', 'required', true, true, true),
  descriptor('A192KW', 'jwe_alg', 'optional', false, true, true),
  descriptor('A256KW', 'jwe_alg', 'required', true, true, true),
  descriptor('RSA-OAEP-256', 'jwe_alg', 'required', true, true, true),
  descriptor('RSA-OAEP', 'jwe_alg', 'legacy', false, false, true),
  // Registered, but no parameters or implementation is defined for them here, so
  // neither direction is available until a dedicated implementation adds them.
  descriptor('RSA-OAEP-384', 'jwe_alg', 'unspecified', false, false, false),
  descriptor('RSA-OAEP-512', 'jwe_alg', 'unspecified', false, false, false),
  descriptor('RSA1_5', 'jwe_alg', 'prohibited', false, false, false),
  descriptor('ECDH-ES', 'jwe_alg', 'recommended', true, true, true),
  descriptor('ECDH-ES+A128KW', 'jwe_alg', 'recommended', true, true, true),
  descriptor('ECDH-ES+A192KW', 'jwe_alg', 'optional', false, true, true),
  descriptor('ECDH-ES+A256KW', 'jwe_alg', 'recommended', true, true, true),
  descriptor('A128GCMKW', 'jwe_alg', 'optional', false, true, true),
  descriptor('A192GCMKW', 'jwe_alg', 'optional', false, true, true),
  descriptor('A256GCMKW', 'jwe_alg', 'optional', false, true, true),
  descriptor('PBES2-HS256+A128KW', 'jwe_alg', 'legacy', false, false, true),
  descriptor('PBES2-HS384+A192KW', 'jwe_alg', 'legacy', false, false, true),
  descriptor('PBES2-HS512+A256KW', 'jwe_alg', 'legacy', false, false, true),
];

const JWE_CONTENT_ENCRYPTION: readonly AlgorithmDescriptor[] = [
  descriptor('A128GCM', 'jwe_enc', 'required', true, true, true),
  descriptor('A192GCM', 'jwe_enc', 'optional', false, true, true),
  descriptor('A256GCM', 'jwe_enc', 'required', true, true, true),
  descriptor('A128CBC-HS256', 'jwe_enc', 'required', true, true, true),
  descriptor('A192CBC-HS384', 'jwe_enc', 'optional', false, true, true),
  descriptor('A256CBC-HS512', 'jwe_enc', 'required', true, true, true),
];

/**
 * Identifiers that exist only as key-level algorithm names are prohibited
 * wherever a JOSE object selects an algorithm. The raw CBC and CTR modes in
 * particular are unauthenticated and must never be mistaken for the distinct
 * authenticated CBC-HMAC constructions.
 *
 * They are listed once and expanded into all three contexts so that no selector
 * position can accidentally omit one.
 */
const PROHIBITED_IN_EVERY_CONTEXT = [
  'RS1',
  'HS1',
  'A128CBC',
  'A192CBC',
  'A256CBC',
  'A128CTR',
  'A192CTR',
  'A256CTR',
] as const;

function buildRegistry(): ReadonlyMap<string, ReadonlyMap<AlgorithmUse, AlgorithmDescriptor>> {
  const registry = new Map<string, Map<AlgorithmUse, AlgorithmDescriptor>>();

  const add = (entry: AlgorithmDescriptor): void => {
    let byUse = registry.get(entry.identifier);
    if (byUse === undefined) {
      byUse = new Map();
      registry.set(entry.identifier, byUse);
    }
    byUse.set(entry.use, entry);
  };

  for (const entry of JWS_ALGORITHMS) {
    add(entry);
  }
  for (const entry of JWE_KEY_MANAGEMENT) {
    add(entry);
  }
  for (const entry of JWE_CONTENT_ENCRYPTION) {
    add(entry);
  }

  for (const identifier of PROHIBITED_IN_EVERY_CONTEXT) {
    for (const use of ['jws', 'jwe_alg', 'jwe_enc'] as const) {
      add(descriptor(identifier, use, 'prohibited', false, false, false));
    }
  }

  return registry;
}

const REGISTRY = buildRegistry();

const UNQUALIFIED = new Set(['Ed25519', 'Ed448', 'EdDSA', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);

export function isQualifiedAlgorithm(identifier: string): boolean {
  return !UNQUALIFIED.has(identifier);
}

/**
 * Looks up an identifier in one selector position.
 *
 * Returns undefined when the identifier has no specified capability in that
 * context, which callers report as unsupported. That is deliberately distinct
 * from a prohibited descriptor, which callers report as prohibited: the two
 * mean different things to an operator reading the failure.
 */
export function lookupAlgorithm(identifier: string, use: AlgorithmUse): AlgorithmDescriptor | undefined {
  return REGISTRY.get(identifier)?.get(use);
}

/**
 * Whether an identifier is prohibited in the given selector position.
 *
 * Callers apply this to every entry of a multi-signature or multi-recipient
 * object before resolving any key, including entries that would otherwise go
 * unselected. That whole-object scope is what makes a prohibited construction
 * unreachable rather than merely unchosen.
 */
export function isProhibitedAlgorithm(identifier: string, use: AlgorithmUse): boolean {
  return lookupAlgorithm(identifier, use)?.category === 'prohibited';
}

export function defaultEligibleAlgorithms(use: AlgorithmUse): readonly string[] {
  const eligible: string[] = [];
  for (const [identifier, byUse] of REGISTRY) {
    if (byUse.get(use)?.defaultEligible === true) {
      eligible.push(identifier);
    }
  }
  return eligible;
}

/** Returns descriptors available to capability reporting. */
export function implementedAlgorithms(use: AlgorithmUse): readonly AlgorithmDescriptor[] {
  const implemented: AlgorithmDescriptor[] = [];
  for (const byUse of REGISTRY.values()) {
    const entry = byUse.get(use);
    if (entry !== undefined && entry.category !== 'prohibited' && entry.category !== 'unspecified') {
      implemented.push(entry);
    }
  }
  return implemented.toSorted((left, right) => left.identifier.localeCompare(right.identifier));
}
