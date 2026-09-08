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
