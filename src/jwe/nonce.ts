/**
 * GCM nonce allocation contract.
 *
 * AES-GCM loses all confidentiality and authenticity guarantees when one nonce
 * repeats under one key: the two ciphertexts reveal the XOR of their
 * plaintexts, and the authentication subkey can be recovered, allowing forgery
 * of further messages. Uniqueness therefore cannot rest on process memory,
 * which is lost on restart and duplicated by forking, cloning, and snapshot
 * restore.
 *
 * The allocator is supplied by the deployment. This module defines the contract
 * and the rules that hold regardless of which store backs it; it deliberately
 * ships no default implementation, because an in-memory one would satisfy the
 * type while silently breaking the guarantee the type exists to express.
 */

/**
 * Number of encryptions permitted under one AES key.
 *
 * Well below the underlying invocation ceiling, so that an accounting error of
 * a few orders of magnitude still leaves the construction safe.
 */
export const MAX_CREATIONS_PER_KEY = 2 ** 24;

export const GCM_NONCE_BYTES = 12;

/**
 * A nonce reserved for exactly one encryption.
 *
 * The reservation is recorded durably before the value is returned, so a
 * process that crashes between reservation and use burns the nonce rather than
 * risking its reissue.
 */
export interface NonceReservation {
  readonly nonce: Uint8Array;
}

export type NonceFailure =
  /** The store could not be reached or could not commit the reservation. */
  | 'unavailable'
  /** This key reached its creation cap and must be replaced. */
  | 'exhausted'
  /**
   * The store's state is not trustworthy: a counter moved backwards, a writer
   * identity is uncertain, or a restore left the sequence ambiguous.
   */
  | 'state_uncertain';

export type NonceResult =
  | { readonly ok: true; readonly reservation: NonceReservation }
  | { readonly ok: false; readonly failure: NonceFailure };

/**
 * Durable, atomically coordinated nonce allocation.
 *
 * `keyIdentity` names the actual AES key, not a configuration label: two names
 * for one key share a nonce space, and treating them separately would issue the
 * same nonce twice under the same key. It is provisioned by the deployment,
 * because only the deployment knows which separately configured entries are
 * aliases of one physical key, and any value computed from a symmetric key
 * would be secret-derived and would then be published to this store.
 *
 * An implementation carries four obligations that this interface's shape cannot
 * express:
 *
 *   - Reserve atomically across every writer sharing the key, including other
 *     processes and machines. A counter held only in process memory is
 *     duplicated by forking, cloning, and snapshot restore.
 *   - Count reservations against `MAX_CREATIONS_PER_KEY` for the key as a whole,
 *     across all of its aliases and writers, and report `exhausted` at the cap.
 *   - Burn a reserved value permanently. A caller that crashes or fails after
 *     reserving must never see that value reissued, so the reservation is
 *     recorded durably before it is returned.
 *   - Report `state_uncertain` rather than guessing whenever a restore, rollback,
 *     or ambiguous writer identity leaves the sequence in doubt. Recovery is
 *     installing a fresh key, not resuming the old counter.
 *
 * Every failure is terminal for the operation. There is no retry that can make
 * an uncertain counter certain, and encrypting anyway is the one outcome that
 * cannot be undone.
 */
export interface NonceAllocator {
  reserve(keyIdentity: string): Promise<NonceResult>;
}
