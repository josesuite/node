/**
 * Algorithm policy decisions.
 *
 * A received identifier falls into one of three dispositions, kept deliberately
 * distinct because they mean different things. "Unsupported" says no such
 * capability is implemented; "prohibited" says the capability is refused on
 * purpose and can never be enabled; "not allowed" says it exists and could be
 * enabled under another configuration but this caller did not permit it.
 *
 * Collapsing them would misreport the implementation's capability surface to
 * operators and would lose the stronger, object-wide rejection that prohibited
 * identifiers require.
 */

import {
  type AlgorithmDescriptor,
  type AlgorithmUse,
  isQualifiedAlgorithm,
  lookupAlgorithm,
} from '../algorithms/registry.ts';
import type { ErrorCategory } from '../errors/codes.ts';

export type AlgorithmDecision =
  | { readonly ok: true; readonly descriptor: AlgorithmDescriptor }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

export type AlgorithmOperation = 'create' | 'receive';

/**
 * An immutable caller allowlist.
 *
 * The caller must supply this before any verification or decryption. Metadata
 * received in a token can only narrow the permitted set; it can never widen it,
 * which is what prevents an attacker from selecting the algorithm used to check
 * their own object.
 */
export class AlgorithmPolicy {
  private readonly permitted: ReadonlySet<string>;
  readonly use: AlgorithmUse;
  /**
   * The direction this allowlist was built for.
   *
   * Retained rather than discarded after construction so every dispatch can
   * check it. Without it a receive-only identifier reaches creation whenever the
   * allowlist happens to contain it, because the list alone cannot say which
   * direction its entries were validated for.
   */
  readonly operation: AlgorithmOperation;

  private constructor(use: AlgorithmUse, operation: AlgorithmOperation, permitted: ReadonlySet<string>) {
    this.use = use;
    this.operation = operation;
    this.permitted = permitted;
  }

  /**
   * Builds a policy from an explicit identifier list.
   *
   * Configuration is validated up front, before any token is processed. An
   * identifier that is prohibited, undefined in this context, or unusable for
   * the intended direction is a defect in the caller's configuration, and
   * surfacing it here means it cannot lie dormant until some particular token
   * happens to exercise it.
   */
  static create(use: AlgorithmUse, identifiers: readonly string[], operation: AlgorithmOperation): AlgorithmPolicy {
    if (identifiers.length === 0) {
      throw new RangeError('algorithm policy requires at least one identifier');
    }

    const permitted = new Set<string>();
    for (const identifier of identifiers) {
      const descriptor = lookupAlgorithm(identifier, use);
      if (descriptor === undefined) {
        throw new RangeError(`algorithm ${identifier} has no specified capability for ${use}`);
      }
      if (descriptor.category === 'prohibited') {
        throw new RangeError(`algorithm ${identifier} is prohibited`);
      }
      if (!isQualifiedAlgorithm(identifier)) {
        throw new RangeError(`algorithm ${identifier} is not qualified`);
      }
      if (operation === 'create' && !descriptor.canCreate) {
        throw new RangeError(`algorithm ${identifier} is receive-only`);
      }
      if (operation === 'receive' && !descriptor.canReceive) {
        throw new RangeError(`algorithm ${identifier} cannot be accepted`);
      }
      permitted.add(identifier);
    }

    return new AlgorithmPolicy(use, operation, permitted);
  }

  has(identifier: string): boolean {
    return this.permitted.has(identifier);
  }

  /** Sorted snapshot for capability reporting. */
  identifiers(): readonly string[] {
    return [...this.permitted].toSorted();
  }
}
