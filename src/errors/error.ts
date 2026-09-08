import type { ErrorCategory, TrustStage } from './codes.ts';
import { inspect } from 'node:util';

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

export class JoseError extends Error {
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
  readonly location: string | undefined;

  constructor(options: JoseErrorOptions) {
    // The message deliberately contains only the category and non-secret
    // reason slug so that accidental logging cannot leak token material.
    super(`${options.category}: ${options.reason}`, { cause: options.cause });
    this.name = 'JoseError';
    this.category = options.category;
    this.stage = options.stage;
    this.reason = options.reason;
    this.location = options.location;
  }

  /** Explicit opt-in sanitized projection; excludes `cause` and the stack. */
  toDiagnostic(): JoseDiagnostic {
    return this.location === undefined
      ? { category: this.category, stage: this.stage, reason: this.reason }
      : {
          category: this.category,
          stage: this.stage,
          reason: this.reason,
          location: this.location,
        };
  }

  /**
   * Prevents `JSON.stringify` and similar inspection from emitting the retained
   * provider cause or the stack. Diagnostics must be opt-in, so the default
   * serialization of an error cannot leak more than the sanitized projection.
   */
  toJSON(): JoseDiagnostic {
    return this.toDiagnostic();
  }

  [inspect.custom](): string {
    return `JoseError ${inspect(this.toDiagnostic())}`;
  }
}

export function isJoseError(value: unknown): value is JoseError {
  return value instanceof JoseError;
}
