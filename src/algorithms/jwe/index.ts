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

const SHAPES: Readonly<Record<string, KeyManagementShape>> = Object.freeze({
  dir: { mode: 'direct', carriesEncryptedKey: false, singleRecipientOnly: true },
  'ECDH-ES': { mode: 'direct_agreement', carriesEncryptedKey: false, singleRecipientOnly: true },

  A128KW: { mode: 'key_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  A192KW: { mode: 'key_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  A256KW: { mode: 'key_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },

  'RSA-OAEP-256': { mode: 'key_transport', carriesEncryptedKey: true, singleRecipientOnly: false },
  'RSA-OAEP': { mode: 'key_transport', carriesEncryptedKey: true, singleRecipientOnly: false },

  'ECDH-ES+A128KW': { mode: 'agreement_with_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  'ECDH-ES+A192KW': { mode: 'agreement_with_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  'ECDH-ES+A256KW': { mode: 'agreement_with_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },

  A128GCMKW: { mode: 'gcm_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  A192GCMKW: { mode: 'gcm_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  A256GCMKW: { mode: 'gcm_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },

  'PBES2-HS256+A128KW': { mode: 'password_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  'PBES2-HS384+A192KW': { mode: 'password_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
  'PBES2-HS512+A256KW': { mode: 'password_wrapping', carriesEncryptedKey: true, singleRecipientOnly: false },
});

/** How an identifier manages keys, or `undefined` when it names nothing here. */
export function keyManagementShape(algorithm: string): KeyManagementShape | undefined {
  return SHAPES[algorithm];
}

/**
 * The AES-KW identifier an agreement-with-wrapping algorithm wraps under.
 *
 * The derived key feeds this wrapping step, and its size comes from this
 * identifier rather than from the content algorithm, which is what makes the
 * KDF input for wrapped agreement differ from direct agreement.
 */
export function agreementWrappingAlgorithm(algorithm: string): string | undefined {
  const suffix = algorithm.startsWith('ECDH-ES+') ? algorithm.slice('ECDH-ES+'.length) : undefined;
  return suffix !== undefined && SHAPES[suffix]?.mode === 'key_wrapping' ? suffix : undefined;
}
