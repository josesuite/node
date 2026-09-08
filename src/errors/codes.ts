/**
 * These string values are the shared category names used across the project's
 * implementations in other languages, so they are part of the observable
 * contract and are deliberately not renamed to language-native conventions.
 * Renaming one here would break agreement with those implementations and the
 * shared conformance corpus.
 */
export const ERROR_CATEGORIES = [
  'malformed_input',
  'unsupported_serialization',
  'invalid_encoding',
  'invalid_header',
  'unsupported_critical_parameter',
  'unsupported_algorithm',
  'prohibited_algorithm',
  'invalid_key',
  'incompatible_key',
  'key_resolution_failure',
  'signature_verification_failure',
  'authentication_failure',
  'claim_validation_failure',
  'expired_token',
  'token_not_yet_valid',
  'issuer_mismatch',
  'audience_mismatch',
  'token_type_mismatch',
  'replay_detected',
  'resource_limit',
  'policy_violation',
  'backend_failure',
] as const;

export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

const CATEGORY_LOOKUP: ReadonlySet<string> = new Set(ERROR_CATEGORIES);

export function isErrorCategory(value: string): value is ErrorCategory {
  return CATEGORY_LOOKUP.has(value);
}
