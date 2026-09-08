/**
 * CEK generation and per-recipient protection.
 *
 * One CEK protects the content, and each recipient gets its own path to that
 * same key. The exception is the direct modes, where the key is not chosen here
 * at all: it arrives from configuration or from an agreement, and generating
 * one would produce a key the recipient cannot reproduce.
 *
 * Every ephemeral agreement key is generated fresh. Reusing one across messages
 * would derive the same CEK each time, collapsing distinct messages onto one
 * key.
 */

import type { ErrorCategory } from '../errors/codes.ts';

export interface ProtectedRecipient {
  /** Absent for the direct modes, which carry no encrypted key. */
  readonly encryptedKey: Uint8Array | undefined;
  /**
   * Ephemeral public key for the agreement modes, absent otherwise.
   *
   * The recipient cannot reproduce the agreement without it, so it must reach
   * the emitted header; it is public by construction and carries no private
   * member.
   */
  readonly ephemeralPublicKey: EphemeralPublicKey | undefined;
  /**
   * Wrapping IV and tag for the GCM key-wrap mode, absent otherwise.
   *
   * These travel as header parameters and are distinct from the content IV and
   * tag; a recipient cannot unwrap without them.
   */
  readonly gcmKw: { readonly iv: Uint8Array; readonly tag: Uint8Array } | undefined;
}

/**
 * Decoded `apu`/`apv` octets bound into the Concat KDF.
 *
 * These are the same octets the header publishes; deriving with one value and
 * emitting another produces a key the recipient cannot reproduce.
 */
export interface PartyInfo {
  readonly partyU?: Uint8Array | undefined;
  readonly partyV?: Uint8Array | undefined;
}

/** Public half of a sender's ephemeral agreement key, as header members. */
export interface EphemeralPublicKey {
  readonly kty: 'EC' | 'OKP';
  readonly crv: string;
  readonly x: Uint8Array;
  /** Present for the NIST curves and absent for the Montgomery ones. */
  readonly y: Uint8Array | undefined;
}

export type ProtectCekResult =
  | {
      readonly ok: true;
      readonly cek: Uint8Array;
      readonly ownsCek: boolean;
      readonly recipients: readonly ProtectedRecipient[];
    }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };
