/**
 * Shared RSA key handling for the JWS signature adapters.
 */

export interface RsaJwkParameters {
  readonly n: Uint8Array;
  readonly e: Uint8Array;
  /** Present only for a private key; all CRT members travel together. */
  readonly d?: Uint8Array | undefined;
  readonly p?: Uint8Array | undefined;
  readonly q?: Uint8Array | undefined;
  readonly dp?: Uint8Array | undefined;
  readonly dq?: Uint8Array | undefined;
  readonly qi?: Uint8Array | undefined;
}

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Builds a JWK for WebCrypto from already-validated parameters.
 *
 * `alg` is deliberately omitted. WebCrypto checks it against the import
 * algorithm when present, and this library binds the algorithm through its own
 * key metadata, so carrying it here would duplicate that binding in a place
 * where a mismatch reports as an opaque import failure.
 */
export function rsaJwk(parameters: RsaJwkParameters): JsonWebKey {
  const jwk = rsaKeyFromJwk(parameters).key;
  return { ...jwk, kty: 'RSA' } as JsonWebKey;
}

/**
 * Builds a JWK carrying only the public members.
 *
 * A public operation must not be handed the private members even when the
 * caller holds a full key pair: WebCrypto binds usages to what the key
 * contains and refuses an encryption usage on a private key. Dropping them here
 * also keeps private material out of an operation that has no need of it.
 */
export function rsaPublicJwk(parameters: RsaJwkParameters): JsonWebKey {
  return { kty: 'RSA', n: b64u(parameters.n), e: b64u(parameters.e) };
}

export function rsaKeyFromJwk(parameters: RsaJwkParameters): { key: Record<string, string>; format: 'jwk' } {
  const jwk: Record<string, string> = {
    kty: 'RSA',
    n: b64u(parameters.n),
    e: b64u(parameters.e),
  };

  // The private members are only meaningful as a complete group; import
  // validation has already established that they are all present together.
  if (parameters.d !== undefined) {
    jwk['d'] = b64u(parameters.d);
    if (parameters.p !== undefined) {
      jwk['p'] = b64u(parameters.p);
    }
    if (parameters.q !== undefined) {
      jwk['q'] = b64u(parameters.q);
    }
    if (parameters.dp !== undefined) {
      jwk['dp'] = b64u(parameters.dp);
    }
    if (parameters.dq !== undefined) {
      jwk['dq'] = b64u(parameters.dq);
    }
    if (parameters.qi !== undefined) {
      jwk['qi'] = b64u(parameters.qi);
    }
  }

  return { key: jwk, format: 'jwk' };
}
