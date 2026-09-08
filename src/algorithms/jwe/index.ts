/**
 * Key-management dispatch for JWE.
 *
 * Each algorithm family decides three things: whether the recipient carries
 * encrypted-key bytes, whether the CEK is generated fresh or arrives from
 * elsewhere, and how many recipients may share the object. Those are expressed
 * here as one description so that a caller cannot assemble a combination the
 * family does not permit. Most importantly, `dir` and direct agreement derive
 * the CEK from one recipient's key, so a second recipient could not recover it
 * and the object would silently be undecryptable for them.
 */

export type KeyManagementMode =
  /** The configured symmetric key is the CEK; nothing is wrapped. */
  | 'direct'
  /** The agreement output is the CEK; nothing is wrapped. */
  | 'direct_agreement'
  /** A fresh CEK is wrapped under a key-encryption key. */
  | 'key_wrapping'
  /** A fresh CEK is encrypted under a public key. */
  | 'key_transport'
  /** A fresh CEK is wrapped under a key derived by agreement. */
  | 'agreement_with_wrapping'
  /** A fresh CEK is wrapped under AES-GCM, with its own IV and tag. */
  | 'gcm_wrapping'
  /** A fresh CEK is wrapped under a key derived from a password. */
  | 'password_wrapping';

export interface KeyManagementShape {
  readonly mode: KeyManagementMode;
  /**
   * True when the recipient must carry encrypted-key bytes. The direct modes
   * carry none at all, and the distinction is structural rather than a matter
   * of length: an empty encrypted key is not the same as an absent one.
   */
  readonly carriesEncryptedKey: boolean;
  /**
   * True when only one recipient may appear. The direct modes derive the CEK
   * from a single recipient's key, so additional recipients could never
   * recover it.
   */
  readonly singleRecipientOnly: boolean;
}
