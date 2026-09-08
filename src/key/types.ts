/**
 * Key model.
 *
 * A parsed JWK and a usable key are deliberately different types. Parsing
 * yields untrusted structure; importing yields a key bound to exactly one
 * algorithm and one operation family by trusted configuration. Keeping them
 * apart is what prevents a key's own metadata from being read as permission to
 * use it, since that metadata arrives with the key and is not authenticated.
 */

export type KeyType = 'RSA' | 'EC' | 'oct' | 'OKP' | 'AKP';

export type EcCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';
export type OkpCurve = 'Ed25519' | 'Ed448' | 'X25519' | 'X448';

/**
 * Conceptual operation families. These are the project's own mapping and are
 * independent of any backend's operation names: a backend's low-level
 * bit-derivation facility does not correspond to a JOSE operation, and raw
 * agreement output is never exposed through the public API.
 */
export type KeyOperation = 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey';

/** The two mutually exclusive purposes a key may declare. */
export type KeyUse = 'sig' | 'enc';

/**
 * Operations permitted for each declared `use`. A key that declares one purpose
 * and an operation belonging to the other is self-contradictory about what it
 * is for, and is rejected at import rather than admitted and refused later.
 */
export const OPERATIONS_BY_USE: Readonly<Record<KeyUse, ReadonlySet<KeyOperation>>> = Object.freeze({
  sig: new Set<KeyOperation>(['sign', 'verify']),
  enc: new Set<KeyOperation>(['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey']),
});

export const KNOWN_OPERATIONS: ReadonlySet<string> = new Set<KeyOperation>([
  'sign',
  'verify',
  'encrypt',
  'decrypt',
  'wrapKey',
  'unwrapKey',
  'deriveKey',
]);
