# JOSE Suite for Node.js

`@josesuite/node` is a JOSE library for Node.js and TypeScript, providing JWT creation and validation, JWS signing and verification, JWE encryption and decryption, and JWK/JWKS key management.

It is built for applications that need explicit control over trusted algorithms, keys, and token validation, with consistent JOSE behavior across JOSE Suite implementations.

## Getting started

### Installation

```bash
npm install @josesuite/node
```

Requires Node.js `>=20.20.0 <21 || ^22.11.0 || ^24.11.0 || ^26.0.0`. The package uses ESM and includes TypeScript declarations.

### Usage

Sign a message with an ES256 private key, then verify it with the corresponding public key:

```ts
import { AlgorithmPolicy, generateKeyPair, LIMITS_V1, signCompact, verifyCompact } from '@josesuite/node';

const generated = await generateKeyPair({ algorithm: 'ES256' });
if (!generated.ok) throw new Error(generated.reason);
const { privateKey, publicKey } = generated.keys;

const payload = new TextEncoder().encode('Order 123 is ready to ship');
const signed = await signCompact(payload, {
  key: privateKey,
  policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
  limits: LIMITS_V1,
});
if (!signed.ok) throw new Error(signed.reason);

const verified = await verifyCompact(signed.token, {
  key: publicKey,
  policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
  principalId: 'order-service',
  limits: LIMITS_V1,
});
if (!verified.ok) throw new Error(verified.reason);

console.log(new TextDecoder().decode(verified.payload));
// Order 123 is ready to ship
```

The signing and verification policies explicitly allow `ES256`; the token cannot enable another algorithm. For JWTs that require issuer, audience, type, and time validation, use `validateJwt`.

See the [JOSE Suite documentation](https://docs.josesuite.com) for further usage.

## Features

- Sign and verify JWS messages, including detached payloads and opt-in unencoded payloads.
- Encrypt and decrypt JWE payloads, including messages addressed to multiple recipients.
- Use Compact, Flattened JSON, and General JSON serializations for JWS and JWE.
- Create and validate signed JWTs and nested signed-and-encrypted JWTs with application profiles for issuer, audience, token type, and time checks.
- Generate asymmetric key pairs and symmetric secrets, validate imported JWKs, and export public keys.
- Work with JWKS snapshots and calculate SHA-256 JWK thumbprints and thumbprint URIs.
- Require named signers or a threshold of distinct signers when verifying General JWS messages.

The package has zero runtime dependencies and uses Node.js cryptographic APIs. Algorithm selection is explicit; registered algorithms are not automatically enabled.

## Encryption

Encrypt a message for a recipient using RSA-OAEP-256 and authenticated AES-CBC encryption, then decrypt it with the recipient's private key:

```ts
import { randomBytes } from 'node:crypto';
import { AlgorithmPolicy, decryptCompact, encryptCompact, generateKeyPair, LIMITS_V1 } from '@josesuite/node';

const generated = await generateKeyPair({
  algorithm: 'RSA-OAEP-256',
  contentAlgorithms: ['A128CBC-HS256'],
});
if (!generated.ok) throw new Error(generated.reason);
const { privateKey, publicKey } = generated.keys;

const encrypted = await encryptCompact(new TextEncoder().encode('Your delivery code is 4821'), {
  recipients: [{ key: publicKey }],
  contentAlgorithm: 'A128CBC-HS256',
  keyPolicy: AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-256'], 'create'),
  contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
  limits: LIMITS_V1,
  random: { randomBytes: (length) => ({ ok: true, value: randomBytes(length) }) },
});
if (!encrypted.ok) throw new Error(encrypted.reason);

const decrypted = await decryptCompact(encrypted.token, {
  recipients: [{ principalId: 'delivery-service', key: privateKey }],
  principalId: 'delivery-service',
  keyPolicy: AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-256'], 'receive'),
  contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'receive'),
  limits: LIMITS_V1,
});
if (!decrypted.ok) throw new Error(decrypted.reason);

console.log(new TextDecoder().decode(decrypted.plaintext));
// Your delivery code is 4821
```

## Standards

The package implements JOSE operations based on these standards, subject to JOSE Suite's algorithm and validation policies:

| Standard                                           | Purpose                      |
| -------------------------------------------------- | ---------------------------- |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature           |
| [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption          |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key and JWK Sets    |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms          |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token               |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprints              |
| [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) | JWS Unencoded Payload Option |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT Best Current Practices   |
| [RFC 9278](https://www.rfc-editor.org/rfc/rfc9278) | JWK Thumbprint URI           |

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report vulnerabilities privately.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, required checks, and how to submit a pull request.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations and how to report concerns.

## License

Licensed under the [MIT License](LICENSE).
