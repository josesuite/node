import type { ErrorCategory, TrustStage } from './codes.ts';

/**
 * Sanitized, non-secret detail about a failure.
 *
 * Errors must never carry secrets, complete input, expected MAC values,
 * plaintext, or the inventory of keys that were searched. Every field here is
 * therefore a bounded descriptor chosen by this implementation rather than
 * copied from untrusted input, so an error cannot become a disclosure channel
 * or a log-injection vector.
 */
export interface JoseErrorDetail {
  /** Stable non-secret reason slug, safe for logs and metrics labels. */
  readonly reason: string;
  /** Structural location, such as a header parameter name or entry index. */
  readonly location?: string;
}

export interface JoseErrorOptions extends JoseErrorDetail {
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  /**
   * Underlying cryptographic-provider cause, retained for in-process debugging
   * only. It is deliberately excluded from every serialized projection, because
   * provider messages are not guaranteed to be free of sensitive material.
   */
  readonly cause?: unknown;
}

/**
 * A sanitized view of a failure, for trusted in-process callers that
 * explicitly opt into diagnostics.
 *
 * This is deliberately not what an unauthenticated remote caller should see:
 * distinguishing a bad signature from an unknown key or an expired token tells
 * an attacker which part of their forgery to change next. Callers must map this
 * to a single coarse rejection before it leaves the process.
 */
export interface JoseDiagnostic extends JoseErrorDetail {
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
}
