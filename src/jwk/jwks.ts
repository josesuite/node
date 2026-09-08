/**
 * JWK Set snapshots.
 *
 * A snapshot is validated as a whole and published atomically. A partly valid
 * set is never installed: if any entry or invariant fails, the previously
 * active set stays in place, so a failed refresh cannot silently narrow or
 * widen the keys an operation can see.
 *
 * The principal invariants are enforced here, during configuration validation,
 * rather than at verification time. A signature made under a key shared by two
 * principals has no determinate signer, so policies like "require signer A" or
 * "require two distinct principals" would become implementation-defined; the
 * only way to keep them meaningful is to refuse the configuration up front.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import type { JsonObject, JsonValue } from '../internal/json/types.ts';
import type { ImportOptions, UsableKey } from '../key/import.ts';
import { LIMITS_V1, type Limits } from '../policy/limits.ts';

/** One key in a snapshot, together with the trust decisions bound to it. */
export interface SnapshotEntry {
  readonly key: UsableKey;
  /** Opaque identifier for the party this key authenticates. */
  readonly principalId: string;
  /** Optional lookup hint; never a trust decision on its own. */
  readonly kid: string | undefined;
}

export interface SnapshotInput {
  readonly jwk: JsonObject;
  readonly principalId: string;
  readonly options: ImportOptions;
}

export type SnapshotBinding = Omit<SnapshotInput, 'jwk'>;

export interface KeySnapshot {
  readonly entries: readonly SnapshotEntry[];
  /** Namespace and operation family this snapshot is scoped to. */
  readonly namespace: string;
}

export type SnapshotResult =
  | { readonly ok: true; readonly snapshot: KeySnapshot }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly reason: string;
      /** Index of the offending entry, when the failure is attributable to one. */
      readonly index?: number;
    };

function reject(reason: string, category: ErrorCategory, index?: number): SnapshotResult {
  return index === undefined ? { ok: false, category, reason } : { ok: false, category, reason, index };
}

/**
 * Reads the `keys` array of a JWK Set container.
 *
 * An empty array is a valid set that resolves no key, which is different from a
 * missing or mistyped member. Array order carries no preference: it is never a
 * fallback or priority list.
 */
export function readJwksEntries(
  container: JsonObject,
  limits: Limits = LIMITS_V1,
):
  | { readonly ok: true; readonly keys: readonly JsonObject[] }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly reason: string;
    } {
  const member = container.members.get('keys');
  if (member === undefined) {
    return { ok: false, category: 'invalid_key', reason: 'keys_missing' };
  }
  if (member.kind !== 'array') {
    return { ok: false, category: 'invalid_key', reason: 'keys_not_an_array' };
  }

  if (member.elements.length > limits.jwksKeys) {
    return { ok: false, category: 'resource_limit', reason: 'too_many_keys' };
  }

  const keys: JsonObject[] = [];
  for (const element of member.elements) {
    // A non-object entry rejects the whole set rather than being skipped,
    // because a set containing one is malformed rather than merely partial.
    if (element.kind !== 'object') {
      return { ok: false, category: 'invalid_key', reason: 'key_entry_not_an_object' };
    }
    keys.push(element);
  }

  return { ok: true, keys };
}

function readKid(jwk: JsonObject): string | undefined {
  const member: JsonValue | undefined = jwk.members.get('kid');
  return member?.kind === 'string' ? member.value : undefined;
}
