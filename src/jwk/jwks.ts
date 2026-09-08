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
import { type KeyIdentity, sameHmacDomain, sameKeyMaterial } from '../key/identity.ts';
import { importKey, type ImportOptions, type UsableKey } from '../key/import.ts';
import { LIMITS_V1 } from '../policy/limits.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import { parseJson } from '../internal/json/parse.ts';

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

/**
 * Validates and builds a snapshot from trusted configuration.
 *
 * Every entry is imported and every cross-entry invariant checked before the
 * snapshot exists, so the caller either receives a fully valid set or nothing.
 */
export function buildSnapshot(
  namespace: string,
  inputs: readonly SnapshotInput[],
  limits: Limits = LIMITS_V1,
): SnapshotResult {
  if (inputs.length > limits.jwksKeys) {
    return reject('too_many_keys', 'resource_limit');
  }

  const entries: SnapshotEntry[] = [];
  const seenKids = new Set<string>();

  for (const [index, input] of inputs.entries()) {
    const imported = importKey(input.jwk, input.options, limits);
    if (!imported.ok) {
      return reject(imported.reason, imported.category, index);
    }

    const kid = readKid(input.jwk);
    if (kid !== undefined) {
      // Two entries sharing an identifier make selection ambiguous, and array
      // order must never be used to break the tie.
      if (seenKids.has(kid)) {
        return reject('duplicate_kid', 'invalid_key', index);
      }
      seenKids.add(kid);
    }

    entries.push({ key: imported.key, principalId: input.principalId, kid });
  }

  const invariant = checkPrincipalInvariants(entries);
  if (invariant !== undefined) {
    return invariant;
  }

  return { ok: true, snapshot: { entries, namespace } };
}

export function buildSnapshotBytes(
  namespace: string,
  source: Uint8Array,
  bindings: readonly SnapshotBinding[],
  limits: Limits = LIMITS_V1,
): SnapshotResult {
  const limitDefect = checkLimits(limits);
  if (limitDefect !== undefined) {
    return reject(limitDefect, 'policy_violation');
  }
  if (source.length > limits.remoteJwksResponse) {
    return reject('jwks_too_large', 'resource_limit');
  }
  const parsed = parseJson(source, limits);
  if (!parsed.ok || parsed.value.kind !== 'object') {
    return reject(
      'jwks_invalid_json',
      parsed.ok
        ? 'invalid_key'
        : parsed.failure === 'resource_limit'
          ? 'resource_limit'
          : parsed.failure === 'duplicate_member'
            ? 'malformed_input'
            : 'invalid_encoding',
    );
  }
  const entries = readJwksEntries(parsed.value, limits);
  if (!entries.ok) {
    return entries;
  }
  if (entries.keys.length !== bindings.length) {
    return reject('jwks_binding_count_mismatch', 'policy_violation');
  }
  return buildSnapshot(
    namespace,
    entries.keys.map((jwk, index) => ({ jwk, ...bindings[index]! })),
    limits,
  );
}

/**
 * Enforces the one-principal-per-key rules across a candidate snapshot.
 *
 * Two distinct checks apply. Identical key material bound to two principals is
 * refused because a signature under it would have no determinate signer.
 * Separately, two HMAC keys with different octets can still have one
 * authentication capability, so equivalent keys are refused across principals
 * even though their material compares unequal.
 */
export function checkPrincipalInvariants(
  entries: readonly { readonly key: UsableKey; readonly principalId: string }[],
): SnapshotResult | undefined {
  for (let i = 0; i < entries.length; i += 1) {
    const a = entries[i]!;

    for (let j = i + 1; j < entries.length; j += 1) {
      const b = entries[j]!;

      // The invariant is scoped to one operation family: the same bytes used
      // for different purposes are separate keys under this rule.
      if (sameKeyMaterial(a.key.identity, b.key.identity)) {
        if (a.principalId !== b.principalId) {
          return reject('shared_key_material_across_principals', 'policy_violation', j);
        }
        if (a.key.algorithm !== b.key.algorithm || !sameStringSet(a.key.contentAlgorithms, b.key.contentAlgorithms)) {
          // Duplicate material carrying conflicting bindings rejects the
          // snapshot rather than widening either key's permissions.
          return reject('duplicate_material_conflicting_binding', 'policy_violation', j);
        }
        continue;
      }

      if (
        a.principalId !== b.principalId &&
        a.key.algorithm === b.key.algorithm &&
        isHmacIdentity(a.key.identity) &&
        isHmacIdentity(b.key.identity) &&
        sameHmacDomain(a.key.identity.k, b.key.identity.k, a.key.algorithm)
      ) {
        return reject('equivalent_hmac_domains_across_principals', 'policy_violation', j);
      }
    }
  }

  return undefined;
}

function sameStringSet(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value) => b.includes(value));
}

function isHmacIdentity(identity: KeyIdentity): identity is Extract<KeyIdentity, { kty: 'oct' }> {
  return identity.kty === 'oct';
}

/**
 * Counts the distinct principals in a snapshot.
 *
 * Deduplication is by principal rather than by entry, so one key appearing
 * under several identifiers cannot inflate a distinct-signer count.
 */
export function distinctPrincipals(snapshot: KeySnapshot): ReadonlySet<string> {
  return new Set(snapshot.entries.map((entry) => entry.principalId));
}
