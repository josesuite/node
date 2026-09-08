/**
 * Aggregate acceptance policy for multi-signature JWS.
 *
 * Acceptance is always an explicit configured predicate. There is deliberately
 * no "first valid signature wins" default: an object carrying several
 * signatures says nothing about which signers an application requires, and
 * inferring one from the token would let the object's author choose it.
 *
 * Predicates count distinct trusted principals, never signature entries. One
 * key appearing under several `kid` values or in several entries is one
 * principal, so duplicate successful entries for the same signer cannot
 * manufacture a threshold.
 */

import type { ErrorCategory } from '../errors/codes.ts';

export type AggregatePolicy =
  /** Exactly one named signer must have produced a valid signature. */
  | { readonly kind: 'named'; readonly principalId: string }
  /** Every listed signer must be present. */
  | { readonly kind: 'all'; readonly required: ReadonlySet<string> }
  /** At least `threshold` of the eligible signers must be present. */
  | { readonly kind: 'threshold'; readonly eligible: ReadonlySet<string>; readonly threshold: number };

export type AggregateConfigResult =
  | { readonly ok: true; readonly policy: AggregatePolicy }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function invalid(reason: string): AggregateConfigResult {
  return { ok: false, category: 'policy_violation', reason };
}

export function namedSigner(principalId: string): AggregateConfigResult {
  if (principalId.length === 0) {
    return invalid('principal_id_empty');
  }
  return { ok: true, policy: { kind: 'named', principalId } };
}

export function allRequiredSigners(required: readonly string[]): AggregateConfigResult {
  const set = new Set(required);
  if (set.size === 0) {
    return invalid('required_set_empty');
  }
  if (set.size !== required.length) {
    // A duplicate makes the intended set size ambiguous, which matters because
    // the predicate is defined over distinct principals.
    return invalid('required_set_duplicate');
  }
  if (required.some((id) => id.length === 0)) {
    return invalid('principal_id_empty');
  }
  return { ok: true, policy: { kind: 'all', required: set } };
}

/**
 * Requires `threshold` distinct principals drawn from `eligible`.
 *
 * The bounds are validated here, before any token is seen, so an unsatisfiable
 * configuration is reported as the configuration defect it is rather than
 * surfacing later as a verification failure.
 */
export function thresholdOfSigners(eligible: readonly string[], threshold: number): AggregateConfigResult {
  const set = new Set(eligible);
  if (set.size === 0) {
    return invalid('eligible_set_empty');
  }
  if (set.size !== eligible.length) {
    return invalid('eligible_set_duplicate');
  }
  if (eligible.some((id) => id.length === 0)) {
    return invalid('principal_id_empty');
  }
  if (!Number.isInteger(threshold)) {
    return invalid('threshold_not_an_integer');
  }
  if (threshold < 1 || threshold > set.size) {
    return invalid('threshold_out_of_range');
  }
  return { ok: true, policy: { kind: 'threshold', eligible: set, threshold } };
}

/**
 * Applies the predicate to the principals established by successful entries.
 *
 * Principals outside the configured set never contribute, so an unrelated valid
 * signature cannot help satisfy a policy naming other signers.
 */
export function isSatisfied(policy: AggregatePolicy, established: ReadonlySet<string>): boolean {
  switch (policy.kind) {
    case 'named':
      return established.has(policy.principalId);
    case 'all': {
      for (const id of policy.required) {
        if (!established.has(id)) {
          return false;
        }
      }
      return true;
    }
    case 'threshold': {
      let count = 0;
      for (const id of policy.eligible) {
        if (established.has(id)) {
          count++;
        }
      }
      return count >= policy.threshold;
    }
  }
}

/** Principals the policy refers to, used to validate signer independence. */
export function referencedPrincipals(policy: AggregatePolicy): ReadonlySet<string> {
  switch (policy.kind) {
    case 'named':
      return new Set([policy.principalId]);
    case 'all':
      return policy.required;
    case 'threshold':
      return policy.eligible;
  }
}
