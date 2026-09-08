/**
 * JSON JWS verification with aggregate acceptance.
 *
 * Every supplied entry is evaluated. Evaluation deliberately does not stop at
 * the first success or the first failure: the aggregate predicate is defined
 * over the whole set of established principals, and per-entry results are
 * reported separately from the aggregate decision.
 *
 * A failed entry contributes no principal and never removes one established by
 * another entry, so a valid and an invalid signature from the same signer still
 * satisfy a policy naming that signer.
 */

import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import type { OperationBudget } from '../internal/validation/limits.ts';
import type { UsableKey } from '../key/import.ts';
import type { AlgorithmPolicy } from '../policy/algorithms.ts';
import type { Limits } from '../policy/limits.ts';
import type { AggregatePolicy } from './aggregate.ts';

/**
 * A key bound to the principal that trusted configuration says holds it.
 *
 * The principal comes from configuration, never from the token: a `kid` may
 * narrow which candidates are tried, but can never introduce a key or a signer
 * identity the caller did not already trust.
 */
export interface TrustedSigner {
  readonly principalId: string;
  readonly key: UsableKey;
}

export interface EntryOutcome {
  /** Index in the received `signatures` array, preserving input order. */
  readonly index: number;
  readonly ok: boolean;
  /** Principal established by this entry, present only on success. */
  readonly principalId: string | undefined;
  readonly header: MergedHeader | undefined;
  readonly category: ErrorCategory | undefined;
  readonly stage: TrustStage | undefined;
  readonly reason: string | undefined;
}

export interface JsonVerifyFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
  /** Per-entry results, retained even when the aggregate decision rejects. */
  readonly entries: readonly EntryOutcome[];
}

export interface JsonVerifySuccess {
  readonly ok: true;
  readonly payload: Uint8Array;
  /** Distinct principals established by successful entries. */
  readonly principals: ReadonlySet<string>;
  readonly entries: readonly EntryOutcome[];
}

export type JsonVerifyResult = JsonVerifySuccess | JsonVerifyFailure;

export interface JsonVerifyOptions {
  readonly policy: AlgorithmPolicy;
  readonly aggregate: AggregatePolicy;
  /** Candidate keys with their configured principals. */
  readonly signers: readonly TrustedSigner[];
  readonly limits: Limits;
  readonly detachedPayload?: Uint8Array | undefined;
  /**
   * Accepts RFC 7797 unencoded payloads. Off by default: the parameter decides
   * what the signing input is built from, so a token must not be able to select
   * a payload mode the caller never enabled.
   */
  readonly unencodedPayload?: boolean | undefined;
  readonly legacyEddsaCurve?: string | undefined;
  /**
   * Opt in to counting MAC-backed principals in the aggregate policy.
   *
   * Only a profile whose semantics treat the corresponding principals as
   * shared-secret security domains, rather than as independently attributable
   * parties, may set this.
   */
  readonly sharedSecretDomains?: boolean | undefined;
  /**
   * Budget shared with an enclosing operation, so a nested token's work counts
   * against the same totals as its container. Absent, this operation owns its
   * own budget: a standalone call still accounts, rather than running unbounded
   * because nobody passed one in.
   */
  readonly operationBudget?: OperationBudget | undefined;
}

function fail(
  stage: TrustStage,
  category: ErrorCategory,
  reason: string,
  entries: readonly EntryOutcome[] = [],
): JsonVerifyFailure {
  return { ok: false, category, stage, reason, entries };
}
