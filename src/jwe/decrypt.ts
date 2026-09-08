/**
 * JWE decryption.
 *
 * Stages run in a fixed order: structure, then whole-object header checks, then
 * algorithm policy, then recipient selection, and only then cryptography. The
 * whole-object checks run before any recipient is considered, because a
 * prohibited algorithm anywhere rejects the entire object even if that
 * recipient would never have been selected.
 *
 * Exactly one recipient is selected and exactly one key is tried. Trying each
 * key in turn would let the object's author decide which identity a successful
 * decryption is attributed to, so zero eligible recipients and several eligible
 * recipients are both refused rather than resolved by attempting them.
 *
 * Plaintext is released only after the content tag verifies. Nothing
 * provisional reaches the caller: no parser, callback, or nested operation sees
 * bytes that have not been authenticated.
 */

import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import type { OperationBudget } from '../internal/validation/limits.ts';
import type { UsableKey } from '../key/import.ts';
import type { AlgorithmPolicy } from '../policy/algorithms.ts';
import type { Limits } from '../policy/limits.ts';

/** A decryption key the caller already trusts, with the principal it belongs to. */
export interface TrustedRecipient {
  readonly principalId: string;
  readonly key: UsableKey;
  /**
   * Password octets for the password-based modes, supplied by trusted
   * configuration. It is bound to this key rather than to the operation, so an
   * object cannot select which password applies.
   */
  readonly password?: Uint8Array | undefined;
}

export interface DecryptOptions {
  /** Permitted key-management algorithms. */
  readonly keyPolicy: AlgorithmPolicy;
  /** Permitted content-encryption algorithms. */
  readonly contentPolicy: AlgorithmPolicy;
  readonly recipients: readonly TrustedRecipient[];
  /**
   * The one principal this operation decrypts as, chosen by the caller from
   * trusted context. Nothing in the object may change it.
   */
  readonly principalId: string;
  readonly limits: Limits;
  readonly operationBudget?: OperationBudget | undefined;
  /**
   * Enables the multi-recipient profile in which recipients may name differing
   * `alg` values in their own unprotected headers. Off by default: with one
   * algorithm the protected header is the only placement that binds it to the
   * authenticated data, and this profile is sound only because trusted
   * configuration independently constrains each recipient's algorithm and key.
   */
  readonly differingRecipientAlgorithms?: boolean | undefined;
}

/**
 * `not_selected` is neither a success nor an error category: those entries pass
 * structural and resource validation and are never cryptographically tried.
 */
export type RecipientOutcome =
  | { readonly index: number; readonly status: 'success' }
  | { readonly index: number; readonly status: 'not_selected' }
  | { readonly index: number; readonly status: 'failed'; readonly category: ErrorCategory };

export interface DecryptSuccess {
  readonly ok: true;
  /** Authenticated plaintext. Never populated unless the tag verified. */
  readonly plaintext: Uint8Array;
  readonly header: MergedHeader;
  /**
   * The principal whose key opened the object.
   *
   * This names the recipient that decrypted, not the sender: content
   * authentication proves the holder of the CEK produced the ciphertext, and
   * every recipient able to recover the CEK could have done so.
   */
  readonly principalId: string;
  readonly recipients: readonly RecipientOutcome[];
}

export interface DecryptFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
  /**
   * Per-entry statuses, present only when selection completed and the failure
   * came from the selected entry. A whole-object rejection evaluates no entry
   * and fabricates no status for one.
   */
  readonly recipients?: readonly RecipientOutcome[] | undefined;
}

export type DecryptResult = DecryptSuccess | DecryptFailure;

function fail(stage: TrustStage, category: ErrorCategory, reason: string): DecryptFailure {
  return { ok: false, category, stage, reason };
}
