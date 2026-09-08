/**
 * Key import.
 *
 * Import is deliberately separate from parsing. Parsing yields untrusted
 * structure; import validates the complete object, its mathematical material,
 * and its purpose, then produces a key bound to exactly one algorithm and one
 * operation family by trusted configuration.
 *
 * No cryptographic operation runs with partially validated private material:
 * every check below completes before a usable key exists, so a malformed or
 * self-inconsistent key can never reach a signing or decryption call.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import type { KeyIdentity } from './identity.ts';
import type { KeyMetadata } from './operations.ts';
import type { KeyOperation } from './types.ts';
import type { EcMaterial, OkpMaterial, RsaPrivateMaterial, RsaPublicMaterial } from './validation.ts';

/**
 * A key that has passed every validation and is bound to one algorithm and one
 * operation family.
 *
 * The identity is the canonical form used for equality decisions, so a private
 * key and its public half compare as one key. Secret material is not part of
 * any printable representation of this record.
 */
interface UsableKeyBase {
  readonly algorithm: string;
  readonly operation: KeyOperation;
  readonly contentAlgorithms: readonly string[];
  readonly identity: KeyIdentity;
  readonly metadata: KeyMetadata;
  readonly isPrivate: boolean;
}

/**
 * A discriminated union rather than one record with a widened `material` field,
 * so an adapter for one key type cannot be handed another type's material
 * without the compiler objecting.
 */
export type UsableKey =
  | (UsableKeyBase & {
      readonly keyType: 'RSA';
      readonly material: RsaPublicMaterial | RsaPrivateMaterial;
    })
  | (UsableKeyBase & { readonly keyType: 'EC'; readonly material: EcMaterial })
  | (UsableKeyBase & { readonly keyType: 'OKP'; readonly material: OkpMaterial })
  | (UsableKeyBase & { readonly keyType: 'oct'; readonly material: Uint8Array })
  | (UsableKeyBase & { readonly keyType: 'AKP'; readonly material: Uint8Array });

/** `Omit` applied across each member of a union rather than to the union. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type ImportResult =
  | { readonly ok: true; readonly key: UsableKey }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

export interface ImportOptions {
  /** The single algorithm this key is bound to; metadata may not widen it. */
  readonly algorithm: string;
  /** The single operation family this key is bound to. */
  readonly operation: KeyOperation;
  /** Content algorithms this key-management key may protect or recover. */
  readonly contentAlgorithms?: readonly string[];
  /**
   * Admits the smaller legacy RSA modulus range for verification of existing
   * tokens. Never permitted for creation.
   */
  readonly receiveOnly?: boolean;
  /** Minimum symmetric key size the bound algorithm requires. */
  readonly minimumSymmetricBytes?: number;
}
