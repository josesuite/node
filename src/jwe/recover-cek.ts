/**
 * CEK recovery for one selected recipient.
 *
 * Every path here reports a failed recovery the same way, as `undefined`
 * rather than a distinct reason. A wrong key, a failed unwrap, a failed OAEP
 * decode, and an agreement that produced the wrong size are all outcomes an
 * attacker can provoke by construction, and distinguishing them is what turns a
 * decryption endpoint into an oracle.
 *
 * A recovered CEK is checked against the size the content algorithm fixes. That
 * size comes from `enc`, never from the recovered length, so a value of the
 * wrong size is refused rather than stretched or truncated into something the
 * cipher would accept.
 */

import { type KeyManagementShape } from '../algorithms/jwe/index.ts';
import type { UsableKey } from '../key/import.ts';

/** Wrapping IV and tag the GCM key-wrap mode carries in its header. */
export interface GcmKwHeaders {
  readonly iv: Uint8Array;
  readonly tag: Uint8Array;
}

/** Work factor and salt the password mode carries in its header. */
export interface Pbes2Headers {
  readonly saltInput: Uint8Array;
  readonly iterations: number;
}

/** Header values the agreement modes need, already validated as strings. */
export interface AgreementHeaders {
  /** Decoded `epk` coordinates; the sender's ephemeral public key. */
  readonly ephemeral: { readonly curve: string; readonly x: Uint8Array; readonly y: Uint8Array | undefined };
  /** Decoded `apu`, absent when the header omits it. */
  readonly partyU: Uint8Array | undefined;
  /** Decoded `apv`, absent when the header omits it. */
  readonly partyV: Uint8Array | undefined;
}

export type CekRecovery =
  /** The CEK was recovered and is the exact size `enc` requires. */
  | { readonly ok: true; readonly cek: Uint8Array; readonly owned: boolean }
  /** Recovery failed in a way an attacker could provoke; no detail is given. */
  | { readonly ok: false; readonly failure: 'recovery_failed' }
  /** The provider is unavailable, which is not an attacker-reachable outcome. */
  | { readonly ok: false; readonly failure: 'backend_failure' };

export interface RecoverInput {
  readonly keyAlgorithm: string;
  readonly contentAlgorithm: string;
  readonly shape: KeyManagementShape;
  readonly key: UsableKey;
  /** Decoded encrypted key, absent for the direct modes. */
  readonly encryptedKey: Uint8Array | undefined;
  readonly agreement: AgreementHeaders | undefined;
  readonly gcmKw: GcmKwHeaders | undefined;
  readonly pbes2: Pbes2Headers | undefined;
  /**
   * Password octets for the password mode, supplied by trusted configuration
   * rather than derived from anything in the object.
   */
  readonly password: Uint8Array | undefined;
}
