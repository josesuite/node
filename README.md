# JOSE Suite for Node.js

`@josesuite/node` is a JOSE library for Node.js and TypeScript, providing JWT creation and validation, JWS signing and verification, JWE encryption and decryption, and JWK/JWKS key management.

It is built for applications that need explicit control over trusted algorithms, keys, and token validation, with consistent JOSE behavior across JOSE Suite implementations.

## Getting started

### Installation

```bash
npm install @josesuite/node
```

Requires Node.js `>=20.10.0`. The package uses ESM and includes TypeScript declarations.

### Usage

The examples below are abbreviated to show the shape of each API. See the
[JOSE Suite documentation](https://docs.josesuite.com) for complete, runnable examples.

#### Sign and verify a message

Every operation takes an explicit algorithm policy. A token cannot talk the verifier into
accepting an algorithm the policy does not list, which is what closes the algorithm confusion
class of attack.

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

#### Issue and validate a JWT against a profile

A profile fixes the issuer, audience, token type, and lifetime once. Validation checks the
whole set on every token, so individual call sites cannot forget one.

```ts
// Define once at startup, reuse for every token
const profile = createJwtProfile({
  name: 'project-jwt-v1',
  issuer: 'https://issuer.example',
  audience: 'https://api.example',
  type: 'JWT',
  chain: 'JWS -> claims',
  clock,
  verification,
  subject: (issuer, subject) => subject.startsWith('user:'),
});

const token = await createJwt({ profile, limits: LIMITS_V1, claims, signing });
const result = await validateJwt(token.token, { profile, limits: LIMITS_V1 });
```

#### Encrypt for multiple recipients

One ciphertext, one content encryption key, wrapped separately per recipient. Each recipient
decrypts with only their own private key.

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

Every operation returns a result object rather than throwing: check `.ok` before reading
`.token`, `.payload`, or `.value`.

## Features

- Sign and verify JWS messages, including detached payloads and opt-in unencoded payloads.
- Encrypt and decrypt JWE payloads, including messages addressed to multiple recipients.
- Use Compact, Flattened JSON, and General JSON serializations for JWS and JWE.
- Create and validate signed JWTs and nested signed-and-encrypted JWTs with application profiles for issuer, audience, token type, and time checks.
- Generate asymmetric key pairs and symmetric secrets, validate imported JWKs, and export public keys.
- Work with JWKS snapshots and calculate SHA-256 JWK thumbprints and thumbprint URIs.
- Require named signers or a threshold of distinct signers when verifying General JWS messages.

The package has zero runtime dependencies and uses Node.js cryptographic APIs. Algorithm selection is explicit; registered algorithms are not automatically enabled.

## Standards

The package implements JOSE operations based on these standards, subject to JOSE Suite's algorithm and validation policies:

| Standard                                                | Purpose                      | Use case                                                                            |
| ------------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------------------- |
| [RFC&nbsp;7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature           | Sign and verify payloads, compact or JSON with multiple signers                     |
| [RFC&nbsp;7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption          | Encrypt payloads for one or many recipients                                         |
| [RFC&nbsp;7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key and JWK Sets    | Import, export, and publish keys; build JWKS snapshots                              |
| [RFC&nbsp;7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms          | Resolve which algorithms are permitted for a given operation                        |
| [RFC&nbsp;7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token               | Issue and validate claims-based tokens against a profile                            |
| [RFC&nbsp;7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprints              | Derive a stable key identifier for key lookup and pinning                           |
| [RFC&nbsp;7797](https://www.rfc-editor.org/rfc/rfc7797) | JWS Unencoded Payload Option | Sign large or detached payloads without base64url-encoding them                     |
| [RFC&nbsp;8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT Best Current Practices   | Reject algorithm confusion, unbounded input, and other known JWT attacks by default |
| [RFC&nbsp;9278](https://www.rfc-editor.org/rfc/rfc9278) | JWK Thumbprint URI           | Reference a key by URI in claims and trust configuration                            |

## Security

See [SECURITY](SECURITY.md) for supported versions and how to report vulnerabilities privately.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for setup instructions, required checks, and how to submit a pull request.

## Code of conduct

See [CODE OF CONDUCT](CODE_OF_CONDUCT.md) for community expectations and how to report concerns.

## License

Licensed under the [MIT License](LICENSE).
