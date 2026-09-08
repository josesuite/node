import { JoseError, type JoseErrorOptions } from './error.ts';

export { ERROR_CATEGORIES, TRUST_STAGES, isErrorCategory } from './codes.ts';
export type { ErrorCategory, TrustStage } from './codes.ts';
export { JoseError, isJoseError } from './error.ts';
export type { JoseDiagnostic, JoseErrorDetail, JoseErrorOptions } from './error.ts';

/**
 * Result of an operation whose failures are expected validation outcomes rather
 * than exceptional conditions.
 *
 * A value is only reachable through the `ok: true` branch, so a failed
 * operation cannot hand back a success-shaped object carrying payload or
 * claims. That makes it impossible for a caller to read verified-looking data
 * from an operation that did not actually verify anything.
 */
export type JoseResult<T> =
  | { readonly ok: true; readonly value: T }
  | {
      readonly ok: false;
      readonly error: JoseError;
    };

export function ok<T>(value: T): JoseResult<T> {
  return { ok: true, value };
}

export function failure<T = never>(options: JoseErrorOptions): JoseResult<T> {
  return { ok: false, error: new JoseError(options) };
}
