/**
 * JWK metadata validation: `use`, `key_ops`, and `alg`.
 *
 * Metadata may only narrow what trusted configuration already permits. None of
 * it is authenticated. It travels with the key, so absent metadata grants
 * nothing and unrecognized metadata makes the key ineligible rather than
 * defaulting to permissive.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import { utf8Length } from '../internal/encoding/utf8.ts';
import { decodeBase64url } from '../internal/encoding/base64url.ts';
import type { JsonObject } from '../internal/json/types.ts';
import { LIMITS_V1, type Limits } from '../policy/limits.ts';
import { KNOWN_OPERATIONS, type KeyOperation, type KeyUse, OPERATIONS_BY_USE } from './types.ts';

export interface KeyMetadata {
  readonly use: KeyUse | undefined;
  /** Undefined when `key_ops` is absent; an empty set when it is present but empty. */
  readonly keyOps: ReadonlySet<KeyOperation> | undefined;
  readonly alg: string | undefined;
  readonly kid: string | undefined;
}

function isKnownOperation(name: string): name is KeyOperation {
  return KNOWN_OPERATIONS.has(name);
}

export type MetadataResult =
  | { readonly ok: true; readonly metadata: KeyMetadata }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(reason: string, category: ErrorCategory = 'invalid_key'): MetadataResult {
  return { ok: false, category, reason };
}

/**
 * Reads and cross-checks the optional metadata members of a JWK.
 *
 * An unknown `use` or an unknown operation name makes the key ineligible: this
 * implementation cannot honour a restriction it does not understand, and
 * ignoring it would grant broader permission than the key's issuer intended.
 */
export function readKeyMetadata(jwk: JsonObject, limits: Limits = LIMITS_V1): MetadataResult {
  const certificateFailure = validateCertificateMetadata(jwk, limits);
  if (certificateFailure !== undefined) {
    return certificateFailure;
  }
  const useMember = jwk.members.get('use');
  let use: KeyUse | undefined;

  if (useMember !== undefined) {
    if (useMember.kind !== 'string') {
      return reject('use_not_a_string');
    }
    if (useMember.value !== 'sig' && useMember.value !== 'enc') {
      // An unrecognized purpose is not treated as "no purpose".
      return reject('use_unrecognized');
    }
    use = useMember.value;
  }

  const opsMember = jwk.members.get('key_ops');
  let keyOps: Set<KeyOperation> | undefined;

  if (opsMember !== undefined) {
    if (opsMember.kind !== 'array') {
      return reject('key_ops_not_an_array');
    }
    keyOps = new Set<KeyOperation>();

    for (const element of opsMember.elements) {
      if (element.kind !== 'string') {
        return reject('key_ops_entry_not_a_string');
      }
      const name = element.value;

      if (!isKnownOperation(name)) {
        return reject('key_ops_unrecognized');
      }
      // Duplicate entries make the intended permission set ambiguous.
      if (keyOps.has(name)) {
        return reject('key_ops_duplicate');
      }

      keyOps.add(name);
    }

    // A present but empty array is a deliberate statement that no operation is
    // permitted, which is different from the member being absent.
    if (keyOps.size > 0 && use !== undefined) {
      const compatible = OPERATIONS_BY_USE[use];
      for (const operation of keyOps) {
        if (!compatible.has(operation)) {
          // Mixed signing and encryption permissions are refused rather than
          // silently trimmed to the intersection, because trimming would hand
          // back a key the application believes has broader permissions.
          return reject('use_and_key_ops_conflict');
        }
      }
    }
  }

  const algMember = jwk.members.get('alg');
  let alg: string | undefined;

  if (algMember !== undefined) {
    if (algMember.kind !== 'string') {
      return reject('alg_not_a_string');
    }
    if (algMember.value.length > limits.algorithmName) {
      return reject('alg_too_long', 'resource_limit');
    }
    alg = algMember.value;
  }

  const kidMember = jwk.members.get('kid');
  let kid: string | undefined;

  if (kidMember !== undefined) {
    if (kidMember.kind !== 'string') {
      return reject('kid_not_a_string');
    }
    // Measured in UTF-8 bytes, matching how the limit is applied to a header
    // `kid`. String length counts UTF-16 code units, so a value of astral or
    // multi-byte characters would pass here and fail there for the same key.
    if (utf8Length(kidMember.value) > limits.kid) {
      return reject('kid_too_long', 'resource_limit');
    }
    kid = kidMember.value;
  }

  return { ok: true, metadata: { use, keyOps, alg, kid } };
}

function validateCertificateMetadata(jwk: JsonObject, limits: Limits): MetadataResult | undefined {
  const url = jwk.members.get('x5u');
  if (
    url !== undefined &&
    (url.kind !== 'string' || utf8Length(url.value) === 0 || utf8Length(url.value) > limits.url)
  ) {
    return reject('x5u_invalid');
  }
  for (const [name, bytes] of [
    ['x5t', 20],
    ['x5t#S256', 32],
  ] as const) {
    const member = jwk.members.get(name);
    if (member !== undefined) {
      const decoded = member.kind === 'string' ? decodeBase64url(member.value, bytes) : undefined;
      if (decoded === undefined || !decoded.ok || decoded.bytes.length !== bytes) {
        return reject(`${name}_invalid`);
      }
    }
  }
  const chain = jwk.members.get('x5c');
  if (chain === undefined) {
    return undefined;
  }
  if (chain.kind !== 'array' || chain.elements.length === 0 || chain.elements.length > limits.certificateChain) {
    return reject('x5c_invalid');
  }
  for (const value of chain.elements) {
    if (value.kind !== 'string' || !validCertificate(value.value, limits)) {
      return reject('x5c_invalid');
    }
  }
  return undefined;
}

function validCertificate(value: string, limits: Limits): boolean {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return false;
  }
  const bytes = Buffer.from(value, 'base64');
  return bytes.length > 0 && bytes.length <= limits.derCertificate && bytes.toString('base64') === value;
}

/**
 * Checks metadata against the algorithm and operation that trusted
 * configuration has bound to this key.
 *
 * A mismatch here is `incompatible_key` rather than `invalid_key`: the key
 * itself is well formed, it simply does not satisfy the binding it is being
 * used under.
 */
export function checkBinding(
  metadata: KeyMetadata,
  boundAlgorithm: string,
  operation: KeyOperation,
): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  // A supplied `alg` must match the configured binding exactly. Its absence
  // grants no permission; the binding alone decides.
  if (metadata.alg !== undefined && metadata.alg !== boundAlgorithm) {
    return { ok: false, reason: 'alg_binding_mismatch' };
  }

  if (metadata.keyOps !== undefined && !metadata.keyOps.has(operation)) {
    return { ok: false, reason: 'operation_not_permitted' };
  }

  if (metadata.use !== undefined && !OPERATIONS_BY_USE[metadata.use].has(operation)) {
    return { ok: false, reason: 'use_not_compatible' };
  }

  return { ok: true };
}
