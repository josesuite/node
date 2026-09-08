/**
 * Key-material equality and HMAC authentication-domain equivalence.
 *
 * These comparisons decide distinct-signer counting, duplicate rejection, and
 * the one-principal-per-key rule. They are defined over exact members rather
 * than left to the obvious approaches, because comparing serialized bytes,
 * `kid` values, backend handles, or object identity would each give a different
 * answer for the same input, and threshold decisions would then depend on which
 * one an implementation happened to pick.
 */

/**
 * The canonical members compared for each key type.
 *
 * Metadata is deliberately absent: `kid`, `use`, `key_ops`, and certificate
 * members describe how a key is labelled, not which key it is. Optional `alg`
 * is likewise excluded, except for post-quantum keys, where it is required and
 * fixes how the public value is interpreted, so it is part of the key itself.
 */
export type KeyIdentity =
  | {
      readonly kty: 'RSA';
      readonly n: Uint8Array;
      readonly e: Uint8Array;
    }
  | {
      readonly kty: 'EC';
      readonly crv: string;
      readonly x: Uint8Array;
      readonly y: Uint8Array;
    }
  | {
      readonly kty: 'OKP';
      readonly crv: string;
      readonly x: Uint8Array;
    }
  | {
      readonly kty: 'AKP';
      readonly alg: string;
      readonly pub: Uint8Array;
    }
  | {
      readonly kty: 'oct';
      readonly k: Uint8Array;
    };
