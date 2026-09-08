/**
 * The shared `limits-v1` baseline resource limits applied to untrusted input.
 *
 * Deployments may lower these values. Raising any of them requires a separate,
 * explicitly named configuration and a resource review, so this module exposes
 * no "unlimited" representation: every bound is finite by construction, and an
 * absent limit is not expressible.
 */

/**
 * Marks a value as having passed `lowerLimits`.
 *
 * Without it `Limits` is a structural type, so an object literal with the right
 * shape satisfies it and reaches every operation without the baseline check
 * ever running. That is a way to raise a bound by passing a large number at a
 * call site, which is exactly what the lowering rule exists to prevent.
 */
declare const VALIDATED: unique symbol;

export interface Limits {
  readonly [VALIDATED]: true;
  /** Entire JWT serialized input, octets. */
  readonly jwtInput: number;
  /** Entire generic JOSE serialized input, octets. */
  readonly joseInput: number;
  /** One decoded protected header or one unprotected header source object. */
  readonly headerSource: number;
  /** All header source bytes across one JOSE object. */
  readonly totalHeaderSource: number;
  /** Decoded JWS payload or authenticated JWE plaintext. */
  readonly payload: number;
  readonly detachedPayload: number;
  readonly ciphertext: number;
  readonly externalAad: number;

  /** JSON container nesting, counting the root as depth one. */
  readonly jsonDepth: number;
  readonly jsonObjectMembers: number;
  readonly mergedHeaderMembers: number;
  readonly jsonArrayElements: number;
  /** Total parsed JSON scalar and container nodes per operation. */
  readonly jsonNodes: number;
  readonly jsonString: number;
  readonly numberLexeme: number;
  readonly numberExponentMagnitude: number;

  readonly signatures: number;
  readonly recipients: number;
  readonly cryptographicLayers: number;
  readonly candidateKeys: number;
  readonly cryptographicAttempts: number;

  readonly jwksKeys: number;
  readonly serializedJwk: number;
  readonly remoteJwksResponse: number;

  readonly rsaModulusBits: number;
  readonly symmetricKeyOctets: number;
  readonly signatureOctets: number;

  readonly kid: number;
  readonly jti: number;
  readonly identifier: number;
  /** Maximum length of an algorithm, curve, key-type, use, or operation name. */
  readonly algorithmName: number;
  readonly url: number;

  readonly certificateChain: number;
  readonly derCertificate: number;

  readonly pbes2Salt: number;
  readonly pbes2Password: number;
  readonly pbes2IterationsMin: number;
  readonly pbes2IterationsMax: number;
  readonly pbkdf2PrfEvaluations: number;

  readonly compressedInput: number;
  readonly decompressedOutput: number;
  readonly decompressionRatio: number;

  /** Connection deadline in milliseconds. */
  readonly remoteConnectionMs: number;
  readonly remoteRequestMs: number;
  readonly networkAttempts: number;
  readonly redirects: number;
  readonly concurrentRefreshesPerIssuer: number;
  readonly negativeCacheEntriesPerIssuer: number;
}
