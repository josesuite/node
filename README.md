# JOSE Suite for Node.js

`@josesuite/node` is a JOSE library for Node.js and TypeScript, providing JWT creation and
validation, JWS signing and verification, JWE encryption and decryption, and JWK/JWKS key
management.

Use it in Node.js services that issue or validate tokens, authenticate signed messages, or encrypt
payloads for known recipients. Applications configure trusted algorithms, keys, and JWT validation
profiles explicitly.

## Installation

```bash
npm install @josesuite/node
```

Requires Node.js `>=20.10.0`. The package distributes compiled JavaScript as native ESM with
TypeScript declarations and zero runtime dependencies. Import public APIs from `@josesuite/node`;
there is no CommonJS entry point.

## Usage

The examples below show how to sign and verify messages, create and validate JWTs, and encrypt
data for multiple recipients. They assume you have already configured the required keys and
trusted algorithms.

Operations return a result indicating success or failure. Check that an operation succeeded
before using its output.

### Sign and verify a message

Signing and verification take explicit algorithm policies. Verification rejects algorithms
outside the allowlist and checks that the key's algorithm and operation bindings match.

```ts
// Issuer: sign with the private key
const signed = await signCompact(payload, {
  key: privateKey,
  policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
  limits: LIMITS_V1,
});

// Recipient: verify with the public key, under its own policy
const verified = await verifyCompact(signed.token, {
  key: publicKey,
  policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
  principalId: 'order-service',
  limits: LIMITS_V1,
});
```

On success, `signed.token` contains the Compact JWS and `verified.payload` contains the verified
payload bytes. Verification authenticates the message; it does not encrypt its contents.

### Issue and validate a JWT against a profile

A profile sets the expected issuer, audience, token type, and lifetime policy. Validation checks
these values and calls the configured subject validator. `verification.principalId` must match
the issuer, and the token type must be purpose-specific rather than the generic `JWT`.

```ts
// Define once at startup, reuse for every token
const profileResult = createJwtProfile({
  name: 'project-jwt-v1',
  issuer: 'https://issuer.example',
  audience: 'https://api.example',
  type: 'project+jwt',
  chain: 'JWS -> claims',
  clock,
  verification,
  subject: (issuer, subject) => subject.startsWith('user:'),
});

if (!profileResult.ok) throw new Error(profileResult.reason);
const profile = profileResult.profile;

const token = await createJwt({ profile, limits: LIMITS_V1, claims, signing });
const result = await validateJwt(token.token, { profile, limits: LIMITS_V1 });
```

### Encrypt for multiple recipients

This example encrypts one plaintext with a shared content encryption key, then wraps that key
for each RSA recipient. Each recipient decrypts with their own private key.

```ts
// Both recipients are addressed in a single encrypt call
const encrypted = await encryptJson(plaintext, {
  recipients: [{ key: billingPublicKey }, { key: auditPublicKey }],
  contentAlgorithm: 'A128CBC-HS256',
  keyPolicy: AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-256'], 'create'),
  contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
  limits: LIMITS_V1,
  random,
});
```

On success, `encrypted.value` contains the General JSON JWE as a string. Use `decryptJson` with
the recipient's configured key and policies to recover the plaintext.

## Features

- **JWS and JWE serializations.** Sign, verify, encrypt, and decrypt Compact, Flattened JSON, and
  General JSON messages. JWS supports detached payloads; JSON JWE supports external authenticated
  data.
- **Profile-driven JWT validation.** Create and validate signed or signed-then-encrypted Compact
  JWTs with `project-jwt-v1`, `project-single-use-jwt-v1`, or `oauth-at-jwt-v1`. The single-use
  profile requires an application-provided replay store.
- **Explicit algorithm policy.** Callers supply algorithm allowlists. Registration alone does not
  enable an algorithm, and token headers cannot expand the configured policy.
- **Key management.** Generate key pairs and secrets, import UTF-8 JWK JSON with `importKeyBytes`,
  export public RSA, EC, and OKP JWKs, and build JWKS snapshots with trusted principal bindings.
  Derive SHA-256 thumbprints and thumbprint URIs, or decrypt JWE-wrapped JWK/JWKS containers with
  `decryptKeyContainer`.
- **Bounded processing.** `LIMITS_V1` bounds input sizes and processing work. `lowerLimits` lets
  applications reduce those limits, but not raise them.
- **Structured failures.** JWS, JWE, and JWT failures carry a category, trust stage, and reason.
  Key-import and snapshot failures carry a category and reason.
- **Native cryptography.** Cryptographic operations use Node.js Web Crypto and `node:crypto`.
- **Multi-party messages.** Address one ciphertext to many recipients, and require named signers or
  a threshold of distinct signers when verifying General JWS.
- **Header inspection.** `inspectUnverifiedHeader` reads Compact JWS/JWE protected headers without
  authenticating them. Its output must not establish trust.

### Supported algorithms

All algorithms below require an explicit allowlist. `getCapabilityReport()` lists algorithms
separately for creation and receipt, along with curves, serializations, profiles, and known gaps.

| Operation                    | Algorithms                                                                                                                                                  |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWS signing and verification | `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `ES256K`                                        |
| JWE key management           | `dir`, `A128KW`, `A192KW`, `A256KW`, `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`, `A128GCMKW`, `A192GCMKW`, `A256GCMKW` |
| JWE content encryption       | `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`                                                                          |
| Legacy JWE decryption only   | `RSA-OAEP`, `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`                                                                                |

ECDH supports `P-256`, `P-384`, `P-521`, `X25519`, and `X448`. ECDSA uses the curve specified by
its algorithm, including `secp256k1` for `ES256K`.

`none` and `RSA1_5` are prohibited. `Ed25519`, `Ed448`, legacy `EdDSA`, and `ML-DSA` algorithms
are unavailable through the public algorithm policy. `RSA-OAEP-384` and `RSA-OAEP-512` are not
implemented. The capability report sets `fullSuiteConformant` to `false` and identifies the
missing required `Ed25519` capability.

### Limits and application responsibilities

- JWT APIs accept only Compact JWS or Compact JWE containing a Compact JWS. They reject JWE-only
  JWTs, detached JWTs, and unencoded JWT payloads. All profiles require `iss`, `sub`, `aud`, `exp`,
  and `iat`. The two project profiles enforce a maximum lifetime of 3,600 seconds; the OAuth
  profile requires an explicit `maximumLifetime`.
- RFC 7797 verification requires `unencodedPayload: true`. Inline unencoded payloads are limited
  to printable ASCII, with periods excluded in Compact form. `signCompact` supports unencoded
  creation with that same character restriction, including detached creation; `signJson` emits
  base64url-encoded payloads only.
- Remote JWKS fetching, automatic key discovery, and certificate trust validation are unavailable.
  Applications supply keys and trusted principal bindings. Public export omits private material;
  symmetric keys have no public export.
- JWE encryption requires an application-provided cryptographic random source. `dir` with AES-GCM
  content encryption and AES-GCM key wrapping also require a durable `NonceAllocator` and a
  configured `keyIdentity`. The allocator must prevent nonce reuse across writers and restarts
  and enforce the per-key creation limit. No allocator implementation is included.
- JWE compression is unavailable. Secret zeroization in managed memory is best effort.

## Further reading

The exported TypeScript declarations describe API options and result types. In this repository,
start with the [public exports](src/index.ts) or these usage tests:

- [JWT profiles and validation](tests/unit/jwt/jwt.test.ts)
- [JWE encryption and decryption](tests/unit/jwe/round-trip.test.ts)
- [Key generation](tests/unit/jwk/generate.test.ts) and [JWK import](tests/unit/jwk/import.test.ts)

Tests also use internal helpers; application code should import only from `@josesuite/node`.

## Standards

The package implements JOSE operations based on these standards, subject to JOSE Suite's algorithm
and validation policies:

| Standard                                                | Purpose                                 | Use case                                                                      |
| ------------------------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------- |
| [RFC&nbsp;7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature                      | Sign and verify payloads, compact or JSON with multiple signers               |
| [RFC&nbsp;7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption                     | Encrypt payloads for one or many recipients                                   |
| [RFC&nbsp;7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key and JWK Sets               | Import, export, and publish keys; build JWKS snapshots                        |
| [RFC&nbsp;7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms                     | Define cryptographic algorithms and key parameters used by JWS and JWE        |
| [RFC&nbsp;7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token                          | Issue and validate claims-based tokens against a profile                      |
| [RFC&nbsp;7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprints                         | Derive a stable key identifier for key lookup and pinning                     |
| [RFC&nbsp;7797](https://www.rfc-editor.org/rfc/rfc7797) | JWS Unencoded Payload Option            | Process unencoded JWS payloads within the restrictions above                  |
| [RFC&nbsp;8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT Best Current Practices              | Guide algorithm restrictions, explicit typing, and issuer/audience validation |
| [RFC&nbsp;9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT profile for OAuth 2.0 access tokens | Create and validate tokens with `oauth-at-jwt-v1`                             |
| [RFC&nbsp;9278](https://www.rfc-editor.org/rfc/rfc9278) | JWK Thumbprint URI                      | Reference a key by URI in claims and trust configuration                      |

## Security

Algorithm policies, key bindings, and JWT profiles come from trusted application configuration.
Keep detailed failure reasons internal and map authentication failures to a coarse external
response. Unverified headers and key identifiers do not establish a trusted identity.

See [SECURITY](SECURITY.md) for supported versions and how to report vulnerabilities privately.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for setup instructions, required checks, and how to submit a
pull request.

## Code of conduct

See [CODE OF CONDUCT](CODE_OF_CONDUCT.md) for community expectations and how to report concerns.

## License

Licensed under the [MIT License](LICENSE).
