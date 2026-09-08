/**
 * Cryptographic backend contract.
 *
 * The JOSE layer owns parsing, exact authenticated inputs, registry
 * identifiers, key metadata, and policy. A backend owns only secure randomness
 * and the cryptographic primitives. Keeping the split explicit is what stops a
 * provider default from silently redefining the wire contract, for example by
 * choosing its own signature encoding or salt length.
 *
 * Every operation reports failure as a normalized result rather than by
 * throwing a provider-specific error, because a provider error is never a
 * usable substitute for a cryptographic outcome: a backend failure must never
 * be mistaken for a valid empty signature, a successful comparison, or
 * unauthenticated plaintext.
 */

export type BackendFailure =
  /** The provider does not implement this capability on this runtime. */
  | 'unsupported'
  /** The provider rejected the operation, e.g. malformed key or signature. */
  | 'operation_failed'
  /** Randomness or a key device was unavailable. */
  | 'unavailable';

export type BackendResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly failure: BackendFailure };

export function backendOk<T>(value: T): BackendResult<T> {
  return { ok: true, value };
}

export function backendError<T = never>(failure: BackendFailure): BackendResult<T> {
  return { ok: false, failure };
}
