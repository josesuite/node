import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { isProtected } from '../internal/headers/types.ts';
import { normalizeMediaType } from '../internal/headers/media-type.ts';
import { parseJson } from '../internal/json/parse.ts';
import type { JsonObject } from '../internal/json/types.ts';
import { decryptCompact } from '../jwe/compact.ts';
import type { DecryptOptions } from '../jwe/decrypt.ts';
import type { ImportOptions, UsableKey } from '../key/import.ts';
import { importKey } from '../key/import.ts';
import type { Limits } from '../policy/limits.ts';
import { buildSnapshot, type KeySnapshot, type SnapshotInput } from './jwks.ts';

export type EncryptedKeyContainerType = 'jwk+json' | 'jwk-set+json';

export interface DecryptKeyContainerOptions {
  readonly type: EncryptedKeyContainerType;
  readonly contentTypeExternallyBound?: true | undefined;
  readonly decryption: Omit<DecryptOptions, 'limits'>;
  readonly limits: Limits;
  readonly jwk?: { readonly principalId: string; readonly namespace: string; readonly import: ImportOptions };
  readonly jwks?: { readonly namespace: string; readonly bindings: readonly Omit<SnapshotInput, 'jwk'>[] };
}

export type DecryptKeyContainerResult =
  | {
      readonly ok: true;
      readonly type: 'jwk+json';
      readonly key: UsableKey;
      readonly principalId: string;
      readonly namespace: string;
    }
  | { readonly ok: true; readonly type: 'jwk-set+json'; readonly snapshot: KeySnapshot }
  | { readonly ok: false; readonly category: ErrorCategory; readonly stage: TrustStage; readonly reason: string };

function fail(stage: TrustStage, category: ErrorCategory, reason: string): DecryptKeyContainerResult {
  return { ok: false, stage, category, reason };
}

export async function decryptKeyContainer(
  token: string,
  options: DecryptKeyContainerOptions,
): Promise<DecryptKeyContainerResult> {
  if (
    (options.type === 'jwk+json') !== (options.jwk !== undefined) ||
    (options.type === 'jwk-set+json') !== (options.jwks !== undefined)
  ) {
    return fail('configuration', 'policy_violation', 'key_container_binding_mismatch');
  }
  const decrypted = await decryptCompact(token, { ...options.decryption, limits: options.limits });
  if (!decrypted.ok) {
    return decrypted;
  }

  // Every exit after decryption is inside the cleanup, including the content-type
  // rejections: the plaintext is an owned decrypted private-key document, so a
  // rejected container must not leave it in memory.
  try {
    // The container's content type must be stated and protected, so a single key
    // and a key set cannot be substituted for one another. It may be omitted only
    // when the caller has already bound the type through the transport.
    const cty = decrypted.header.parameters.get('cty');
    if (cty === undefined) {
      if (options.contentTypeExternallyBound !== true) {
        return fail('header', 'token_type_mismatch', 'key_container_cty_required');
      }
    } else if (
      !isProtected(decrypted.header, 'cty') ||
      cty.value.kind !== 'string' ||
      normalizeMediaType(cty.value.value) !== normalizeMediaType(options.type)
    ) {
      return fail('header', 'token_type_mismatch', 'key_container_cty_mismatch');
    }

    const parsed = parseJson(decrypted.plaintext, options.limits);
    if (!parsed.ok) {
      return fail(
        'claims_syntax',
        parsed.failure === 'resource_limit'
          ? 'resource_limit'
          : parsed.failure === 'invalid_encoding'
            ? 'invalid_encoding'
            : 'malformed_input',
        'key_container_invalid_json',
      );
    }
    if (parsed.value.kind !== 'object') {
      return fail('claims_syntax', 'invalid_key', 'key_container_not_object');
    }

    if (options.type === 'jwk+json') {
      const imported = importKey(parsed.value, options.jwk!.import, options.limits);
      return imported.ok
        ? {
            ok: true,
            type: options.type,
            key: imported.key,
            principalId: options.jwk!.principalId,
            namespace: options.jwk!.namespace,
          }
        : fail('claims_semantics', imported.category, imported.reason);
    }

    const keys = parsed.value.members.get('keys');
    if (keys?.kind !== 'array') {
      return fail('claims_semantics', 'invalid_key', 'keys_missing_or_invalid');
    }
    // Bindings are positional, so a count mismatch would silently pair keys with
    // the wrong principal or usage rather than leaving one unbound.
    if (keys.elements.length !== options.jwks!.bindings.length) {
      return fail('configuration', 'policy_violation', 'jwks_binding_count_mismatch');
    }
    const inputs: SnapshotInput[] = [];
    for (const [index, value] of keys.elements.entries()) {
      if (value.kind !== 'object') {
        return fail('claims_semantics', 'invalid_key', 'key_entry_not_an_object');
      }
      if (isPrivateOrSymmetric(value)) {
        return fail('claims_semantics', 'invalid_key', 'public_jwks_contains_private_material');
      }
      inputs.push({ jwk: value, ...options.jwks!.bindings[index]! });
    }
    const snapshot = buildSnapshot(options.jwks!.namespace, inputs, options.limits);
    return snapshot.ok
      ? { ok: true, type: options.type, snapshot: snapshot.snapshot }
      : fail('claims_semantics', snapshot.category, snapshot.reason);
  } finally {
    decrypted.plaintext.fill(0);
  }
}

/** Members whose presence makes a JWK private, across every supported key type. */
const PRIVATE_MEMBERS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'priv']);

/**
 * Detects material that must never appear in a set of public verification keys.
 *
 * Membership is decided by the members present rather than by `kty`, so an entry
 * carrying private components is caught even when its declared type would
 * otherwise suggest a public key.
 */
function isPrivateOrSymmetric(value: JsonObject): boolean {
  const keyType = value.members.get('kty');
  return (
    (keyType?.kind === 'string' && keyType.value === 'oct') ||
    [...PRIVATE_MEMBERS].some((name) => value.members.has(name))
  );
}
