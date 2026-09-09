import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { defaultEligibleAlgorithms, isProhibitedAlgorithm, lookupAlgorithm } from '../../../src/algorithms/registry.ts';
import { AlgorithmPolicy, decideAlgorithm } from '../../../src/policy/algorithms.ts';

describe('ALG-08 JWS matrix', () => {
  test('required algorithms are default eligible for both directions', () => {
    for (const identifier of ['HS256', 'RS256', 'PS256', 'ES256']) {
      const descriptor = lookupAlgorithm(identifier, 'jws');
      assert.notStrictEqual(descriptor, undefined);
      assert.strictEqual(descriptor!.category, 'required');
      assert.strictEqual(descriptor!.defaultEligible, true);
      assert.strictEqual(descriptor!.canCreate, true);
      assert.strictEqual(descriptor!.canReceive, true);
    }
  });

  test('optional algorithms are recognized but off by default', () => {
    for (const identifier of ['HS384', 'RS384', 'PS512', 'ES512', 'ES256K', 'Ed448']) {
      assert.strictEqual(lookupAlgorithm(identifier, 'jws')!.defaultEligible, false);
    }
  });

  test('recommended algorithms are eligible', () => {
    assert.strictEqual(lookupAlgorithm('HS512', 'jws')!.defaultEligible, true);
    assert.strictEqual(lookupAlgorithm('ES384', 'jws')!.defaultEligible, true);
  });

  test('deprecated EdDSA is receive-only and never creatable', () => {
    const descriptor = lookupAlgorithm('EdDSA', 'jws')!;
    assert.strictEqual(descriptor.category, 'legacy');
    assert.strictEqual(descriptor.canCreate, false);
    assert.strictEqual(descriptor.canReceive, true);
    assert.strictEqual(descriptor.defaultEligible, false);
  });

  test('none is prohibited in both directions', () => {
    const descriptor = lookupAlgorithm('none', 'jws')!;
    assert.strictEqual(descriptor.category, 'prohibited');
    assert.strictEqual(descriptor.canCreate, false);
    assert.strictEqual(descriptor.canReceive, false);
    assert.strictEqual(isProhibitedAlgorithm('none', 'jws'), true);
  });
});

describe('ALG-09 JWE matrices', () => {
  test('required key management is eligible', () => {
    for (const identifier of ['dir', 'A128KW', 'A256KW', 'RSA-OAEP-256']) {
      assert.strictEqual(lookupAlgorithm(identifier, 'jwe_alg')!.defaultEligible, true);
    }
  });

  test('RSA1_5 is prohibited', () => {
    assert.strictEqual(isProhibitedAlgorithm('RSA1_5', 'jwe_alg'), true);
    assert.strictEqual(lookupAlgorithm('RSA1_5', 'jwe_alg')!.canReceive, false);
  });

  test('legacy key management is receive-only', () => {
    for (const identifier of ['RSA-OAEP', 'PBES2-HS256+A128KW', 'PBES2-HS512+A256KW']) {
      const descriptor = lookupAlgorithm(identifier, 'jwe_alg')!;
      assert.strictEqual(descriptor.category, 'legacy');
      assert.strictEqual(descriptor.canCreate, false);
      assert.strictEqual(descriptor.canReceive, true);
    }
  });

  test('RSA-OAEP-384/512 are unavailable in both directions until specified', () => {
    for (const identifier of ['RSA-OAEP-384', 'RSA-OAEP-512']) {
      const descriptor = lookupAlgorithm(identifier, 'jwe_alg')!;
      assert.strictEqual(descriptor.category, 'unspecified');
      assert.strictEqual(descriptor.canCreate, false);
      assert.strictEqual(descriptor.canReceive, false);
    }
  });

  test('required content encryption is eligible and CBC-HMAC is supported', () => {
    for (const identifier of ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']) {
      assert.strictEqual(lookupAlgorithm(identifier, 'jwe_enc')!.defaultEligible, true);
    }
    assert.strictEqual(lookupAlgorithm('A192GCM', 'jwe_enc')!.defaultEligible, false);
    assert.strictEqual(lookupAlgorithm('A192CBC-HS384', 'jwe_enc')!.defaultEligible, false);
  });
});

describe('ALG-07 JWK-only identifiers', () => {
  test('are prohibited in every algorithm-selector position', () => {
    for (const identifier of ['RS1', 'HS1', 'A128CBC', 'A192CBC', 'A256CBC', 'A128CTR', 'A192CTR', 'A256CTR']) {
      assert.strictEqual(isProhibitedAlgorithm(identifier, 'jws'), true);
      assert.strictEqual(isProhibitedAlgorithm(identifier, 'jwe_alg'), true);
      assert.strictEqual(isProhibitedAlgorithm(identifier, 'jwe_enc'), true);
    }
  });

  test('raw CBC identifiers are not accepted as a content algorithm', () => {
    // The AES-CBC-HMAC constructions are distinct authenticated-encryption
    // algorithms; a raw CBC identifier names an unauthenticated mode and must
    // never be accepted in its place.
    assert.strictEqual(lookupAlgorithm('A128CBC', 'jwe_enc')!.canReceive, false);
    assert.strictEqual(lookupAlgorithm('A128CBC-HS256', 'jwe_enc')!.canReceive, true);
  });
});

describe('usage-context scoping', () => {
  test('an identifier is only defined in its registered context', () => {
    // `enc` is registered for JWE only, so a JWS-borne
    // content-encryption name selects no JWS capability.
    assert.strictEqual(lookupAlgorithm('A128GCM', 'jws'), undefined);
    assert.strictEqual(lookupAlgorithm('HS256', 'jwe_alg'), undefined);
    assert.strictEqual(lookupAlgorithm('dir', 'jws'), undefined);
    assert.notStrictEqual(lookupAlgorithm('A128GCM', 'jwe_enc'), undefined);
  });

  test('a JWE-only enc name in a JWS is not a prohibited-algorithm trigger', () => {
    assert.strictEqual(isProhibitedAlgorithm('A128GCM', 'jws'), false);
  });

  test('unknown identifiers are absent rather than dynamically admitted', () => {
    assert.strictEqual(lookupAlgorithm('HS256 ', 'jws'), undefined);
    assert.strictEqual(lookupAlgorithm('hs256', 'jws'), undefined);
    assert.strictEqual(lookupAlgorithm('FN-DSA-512', 'jws'), undefined);
    assert.strictEqual(lookupAlgorithm('ESP256', 'jws'), undefined);
  });
});

describe('defaultEligibleAlgorithms', () => {
  test('excludes prohibited, legacy, and optional identifiers', () => {
    const eligible = defaultEligibleAlgorithms('jws');
    assert.ok(eligible.includes('ES256'));
    assert.ok(!eligible.includes('none'));
    assert.ok(!eligible.includes('EdDSA'));
    assert.ok(!eligible.includes('ES256K'));
  });
});

describe('AlgorithmPolicy configuration validation', () => {
  test('accepts a supported allowlist', () => {
    const policy = AlgorithmPolicy.create('jws', ['ES256', 'HS256'], 'receive');
    assert.deepStrictEqual(policy.identifiers(), ['ES256', 'HS256']);
    assert.strictEqual(policy.has('ES256'), true);
  });

  test('rejects prohibited, unknown, and empty configuration before token work', () => {
    assert.throws(() => AlgorithmPolicy.create('jws', ['none'], 'receive'), RangeError);
    assert.throws(() => AlgorithmPolicy.create('jwe_alg', ['RSA1_5'], 'receive'), RangeError);
    assert.throws(() => AlgorithmPolicy.create('jws', ['MADE-UP'], 'receive'), RangeError);
    assert.throws(() => AlgorithmPolicy.create('jws', [], 'receive'), RangeError);
  });

  test('rejects a receive-only algorithm configured for creation', () => {
    assert.throws(() => AlgorithmPolicy.create('jws', ['EdDSA'], 'create'), RangeError);
    assert.throws(() => AlgorithmPolicy.create('jws', ['EdDSA'], 'receive'), 'not qualified');
    assert.throws(() => AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP'], 'create'), RangeError);
  });

  test('rejects an unspecified algorithm in either direction', () => {
    assert.throws(() => AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-384'], 'receive'), RangeError);
    assert.throws(() => AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-384'], 'create'), RangeError);
  });

  test('rejects implemented algorithms that have not passed backend qualification', () => {
    assert.throws(() => AlgorithmPolicy.create('jws', ['Ed25519'], 'receive'), 'not qualified');
    assert.throws(() => AlgorithmPolicy.create('jws', ['Ed448'], 'receive'), 'not qualified');
  });
});

describe('decideAlgorithm dispositions', () => {
  const policy = AlgorithmPolicy.create('jws', ['ES256', 'HS256'], 'receive');

  test('permits an allowlisted algorithm', () => {
    const decision = decideAlgorithm(policy, 'ES256');
    assert.strictEqual(decision.ok, true);
    if (decision.ok) {
      assert.strictEqual(decision.descriptor.identifier, 'ES256');
    }
  });

  test('separates the three dispositions into distinct categories', () => {
    // Implemented but outside the caller's allowlist.
    const excluded = decideAlgorithm(policy, 'RS256');
    assert.strictEqual(excluded.ok, false);
    if (!excluded.ok) {
      assert.strictEqual(excluded.category, 'policy_violation');
    }

    // No implemented and specified capability.
    const unsupported = decideAlgorithm(policy, 'MADE-UP');
    assert.strictEqual(unsupported.ok, false);
    if (!unsupported.ok) {
      assert.strictEqual(unsupported.category, 'unsupported_algorithm');
    }

    // Project prohibited.
    const prohibited = decideAlgorithm(policy, 'none');
    assert.strictEqual(prohibited.ok, false);
    if (!prohibited.ok) {
      assert.strictEqual(prohibited.category, 'prohibited_algorithm');
    }
  });

  test('reports an out-of-context identifier as unsupported, not prohibited', () => {
    const decision = decideAlgorithm(policy, 'A128GCM');
    assert.strictEqual(decision.ok, false);
    if (!decision.ok) {
      assert.strictEqual(decision.category, 'unsupported_algorithm');
    }
  });

  test('bounds the identifier length before lookup', () => {
    const decision = decideAlgorithm(policy, 'A'.repeat(65));
    assert.strictEqual(decision.ok, false);
    if (!decision.ok) {
      assert.strictEqual(decision.category, 'resource_limit');
    }

    // Exactly at the 64-octet boundary it is a normal unsupported identifier.
    const boundary = decideAlgorithm(policy, 'A'.repeat(64));
    assert.strictEqual(boundary.ok, false);
    if (!boundary.ok) {
      assert.strictEqual(boundary.category, 'unsupported_algorithm');
    }
  });

  test('is case-sensitive', () => {
    const decision = decideAlgorithm(policy, 'es256');
    assert.strictEqual(decision.ok, false);
    if (!decision.ok) {
      assert.strictEqual(decision.category, 'unsupported_algorithm');
    }
  });
});
