/**
 * JWE creation.
 *
 * There is one plaintext and one content-encryption operation regardless of how
 * many recipients there are. Every recipient receives the same CEK by its own
 * key-management path; encrypting the plaintext separately per recipient would
 * produce several ciphertexts where the format defines one, and would multiply
 * the nonce budget without the allocator knowing.
 *
 * The protected header is serialized once and its encoded form is what enters
 * the authenticated data. Nothing downstream reserializes it, so the bytes a
 * recipient authenticates are exactly the bytes emitted here.
 *
 * Output is published only when every step succeeded. A partial object would
 * offer an attacker a ciphertext whose recipient set was decided by a failure.
 */

import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import type { RandomSource } from '../internal/crypto/backend.ts';
import type { UsableKey } from '../key/import.ts';
import type { AlgorithmPolicy } from '../policy/algorithms.ts';
import type { Limits } from '../policy/limits.ts';
import type { NonceAllocator } from './nonce.ts';

/** One recipient's key and the header members its algorithm needs. */
export interface RecipientInput {
  readonly key: UsableKey;
  /**
   * Unprotected members for this recipient, carried verbatim and excluded from
   * the authenticated data. These stay unauthenticated hints and must not hold
   * security-relevant data.
   */
  readonly unprotectedHeader?: Readonly<Record<string, string>> | undefined;
  /**
   * Names this recipient's long-lived AES key in the nonce allocator, required
   * whenever that key is used under a construction whose nonce must never
   * repeat: `dir` with a GCM content algorithm, and the GCM key-wrap modes.
   *
   * Provisioned by the deployment rather than derived here, for two reasons.
   * Only the deployment knows which separately configured entries are aliases of
   * one physical key, and every value derivable from a symmetric key is
   * secret-derived, so computing one would publish it to an external store. Two
   * names for one key must be given one identity: treating them separately
   * issues one nonce twice under that key, which is the failure the allocator
   * exists to prevent.
   */
  readonly keyIdentity?: string | undefined;
}

export interface EncryptOptions {
  readonly keyPolicy: AlgorithmPolicy;
  readonly contentPolicy: AlgorithmPolicy;
  readonly contentAlgorithm: string;
  readonly recipients: readonly RecipientInput[];
  readonly limits: Limits;
  readonly random: RandomSource;
  /**
   * Durable allocator, required whenever the content algorithm uses a nonce
   * that must never repeat. Its absence is a configuration error rather than a
   * cue to generate one locally.
   */
  readonly nonceAllocator?: NonceAllocator | undefined;
  /** Extra protected members; `alg` and `enc` come from the keys and options. */
  readonly protectedHeader?: Readonly<Record<string, string | boolean | string[]>> | undefined;
  /** External AAD octets. Zero octets emit no `aad` member. */
  readonly externalAad?: Uint8Array | undefined;
  /** Emit the single-recipient Flattened form instead of `recipients`. */
  readonly flattened?: boolean | undefined;
}

export type EncryptResult =
  | { readonly ok: true; readonly value: string }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly stage: TrustStage;
      readonly reason: string;
    };

function fail(category: ErrorCategory, reason: string, stage: TrustStage = 'configuration'): EncryptResult {
  return { ok: false, category, stage, reason };
}
