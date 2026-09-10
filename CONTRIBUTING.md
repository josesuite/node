# Contributing

Thank you for contributing to JOSE Suite for Node.js. This library handles untrusted cryptographic
input, so changes must preserve security, standards conformance, and exact authenticated bytes.

## Before you start

Search existing issues before opening a new one. Use the bug report or change request template when
creating an issue.

Report suspected vulnerabilities through the private process in [SECURITY.md](SECURITY.md). Do not
include sensitive reports in issues, discussions, or pull requests.

## Requirements

| Tool    | Supported version | Purpose                 |
| ------- | ----------------- | ----------------------- |
| Node.js | `>=20.20 <21`     | Runtime and test runner |
| Node.js | `>=22.11 <23`     | Runtime and test runner |
| Node.js | `>=24.11 <25`     | Runtime and test runner |
| Node.js | `>=26`            | Runtime and test runner |
| Bun     | `1.4.x`           | Packages and scripts    |

Install dependencies from the lockfile:

```sh
bun install --frozen-lockfile
```

## Making changes

Keep each change focused. Preserve public APIs and observable behavior unless the change explicitly
requires otherwise. Reuse existing project patterns and platform cryptography. Never implement
cryptographic primitives manually.

Before changing protocol behavior, security policy, error semantics, or conformance, read the
relevant requirements in [research-next/specification.md](research-next/specification.md). The
specification takes precedence over backend defaults and implementation convenience. If a
requirement appears inconsistent or technically wrong, raise the conflict instead of changing the
implementation to a convenient interpretation.

Treat tokens, headers, claims, keys, certificates, resolver results, and fixtures as untrusted
input. Do not add permissive fallbacks or infer algorithms, trust, or key identity from
attacker-controlled data.

## Tests

Add tests for observable behavior changes and regression fixes. Cover relevant failure paths,
malformed input, policy rejection, algorithm and key mismatches, and exact encoding behavior.
Prefer focused tests under `tests/unit/`; use shared conformance fixtures when the specification
requires cross-language behavior.

Run these checks before opening a pull request:

| Command                 | What it does                                    |
| ----------------------- | ----------------------------------------------- |
| `bun run typecheck`     | Type-checks source and test code                |
| `bun run test`          | Runs the Node.js test suite                     |
| `bun run lint`          | Checks source with Oxlint                       |
| `bun run format`        | Checks formatting with Oxfmt                    |
| `bun run build`         | Compiles JavaScript and TypeScript declarations |
| `bun run test:coverage` | Runs tests and writes an LCOV coverage report   |
| `bun run lint:fix`      | Applies fixes supported by Oxlint               |
| `bun run format:fix`    | Formats supported files with Oxfmt              |

The first five commands are required for every pull request. Run coverage when a change may leave
security-sensitive branches untested.

## Pull requests

Explain the problem, the resulting behavior, and the validation you ran. Link the relevant issue
when one exists. For changes that affect JOSE behavior, list the applicable requirement IDs, RFC
sections, or conformance fixtures and state whether observable behavior changed.

Keep the diff limited to the requested change. Do not include generated coverage files, debugging
output, unrelated formatting, or temporary artifacts.

Never include real keys, tokens, credentials, private key material, or confidential plaintext in
code, tests, issues, or pull requests.
