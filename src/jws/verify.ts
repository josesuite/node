/**
 * Compact JWS verification.
 *
 * Stages run in a fixed order: structure, then headers and critical
 * extensions, then algorithm policy, then key eligibility, and only then
 * cryptography. Each stage's failure is reported with its own category, so a
 * token rejected on policy never reaches key resolution and a rejection at the
 * wrong stage is visible as such rather than hidden behind a matching category.
 *
 * A successful backend result is necessary but not sufficient: the algorithm,
 * key binding, and signature representation are all checked around it.
 */

import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import type { OperationBudget } from '../internal/validation/limits.ts';
import type { UsableKey } from '../key/import.ts';
import type { AlgorithmPolicy } from '../policy/algorithms.ts';
import type { Limits } from '../policy/limits.ts';

export interface VerifyFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
}

export interface VerifySuccess {
  readonly ok: true;
  /** Authenticated payload octets. */
  readonly payload: Uint8Array;
  /** Header provenance, so callers can tell protected values from hints. */
  readonly header: MergedHeader;
  /**
   * The principal this key was bound to by trusted configuration.
   *
   * For an asymmetric signature this identifies the configured signer. For a
   * MAC it identifies the shared-secret domain and does **not** establish which
   * holder of that secret produced the object, since every holder can produce
   * an identical MAC.
   */
  readonly principalId: string;
  /** True when the binding was a MAC, where the above distinction applies. */
  readonly isSharedSecret: boolean;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

export interface VerifyOptions {
  readonly policy: AlgorithmPolicy;
  readonly key: UsableKey;
  readonly principalId: string;
  readonly limits: Limits;
  /**
   * External payload for detached mode. Its presence is an explicit caller
   * choice; detachment is never inferred from an empty component, and the
   * content is never fetched from an address inside the token.
   */
  readonly detachedPayload?: Uint8Array | undefined;
  /**
   * Accepts RFC 7797 unencoded payloads. Off by default: the parameter decides
   * what the signing input is built from, so a token must not be able to select
   * a payload mode the caller never enabled.
   */
  readonly unencodedPayload?: boolean | undefined;
  readonly legacyEddsaCurve?: string | undefined;
  readonly operationBudget?: OperationBudget | undefined;
}

function fail(stage: TrustStage, category: ErrorCategory, reason: string): VerifyFailure {
  return { ok: false, category, stage, reason };
}
