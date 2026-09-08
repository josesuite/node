import { describe, expect, test } from 'bun:test';

import { defaultEligibleAlgorithms, isProhibitedAlgorithm, lookupAlgorithm } from '../../../src/algorithms/registry.ts';
import { AlgorithmPolicy, decideAlgorithm } from '../../../src/policy/algorithms.ts';

describe('ALG-08 JWS matrix', () => {
  test('required algorithms are default eligible for both directions', () => {
    for (const identifier of ['HS256', 'RS256', 'PS256', 'ES256']) {
      const descriptor = lookupAlgorithm(identifier, 'jws');
      expect(descriptor).toBeDefined();
      expect(descriptor!.category).toBe('required');
      expect(descriptor!.defaultEligible).toBe(true);
      expect(descriptor!.canCreate).toBe(true);
      expect(descriptor!.canReceive).toBe(true);
    }
  });

  test('optional algorithms are recognized but off by default', () => {
    for (const identifier of ['HS384', 'RS384', 'PS512', 'ES512', 'ES256K', 'Ed448']) {
      expect(lookupAlgorithm(identifier, 'jws')!.defaultEligible).toBe(false);
    }
  });

  test('recommended algorithms are eligible', () => {
    expect(lookupAlgorithm('HS512', 'jws')!.defaultEligible).toBe(true);
    expect(lookupAlgorithm('ES384', 'jws')!.defaultEligible).toBe(true);
  });

  test('deprecated EdDSA is receive-only and never creatable', () => {
    const descriptor = lookupAlgorithm('EdDSA', 'jws')!;
    expect(descriptor.category).toBe('legacy');
    expect(descriptor.canCreate).toBe(false);
    expect(descriptor.canReceive).toBe(true);
    expect(descriptor.defaultEligible).toBe(false);
  });

  test('none is prohibited in both directions', () => {
    const descriptor = lookupAlgorithm('none', 'jws')!;
    expect(descriptor.category).toBe('prohibited');
    expect(descriptor.canCreate).toBe(false);
    expect(descriptor.canReceive).toBe(false);
    expect(isProhibitedAlgorithm('none', 'jws')).toBe(true);
  });
});

describe('ALG-09 JWE matrices', () => {
  test('required key management is eligible', () => {
    for (const identifier of ['dir', 'A128KW', 'A256KW', 'RSA-OAEP-256']) {
      expect(lookupAlgorithm(identifier, 'jwe_alg')!.defaultEligible).toBe(true);
    }
  });

  test('RSA1_5 is prohibited', () => {
    expect(isProhibitedAlgorithm('RSA1_5', 'jwe_alg')).toBe(true);
    expect(lookupAlgorithm('RSA1_5', 'jwe_alg')!.canReceive).toBe(false);
  });

  test('legacy key management is receive-only', () => {
    for (const identifier of ['RSA-OAEP', 'PBES2-HS256+A128KW', 'PBES2-HS512+A256KW']) {
      const descriptor = lookupAlgorithm(identifier, 'jwe_alg')!;
      expect(descriptor.category).toBe('legacy');
      expect(descriptor.canCreate).toBe(false);
      expect(descriptor.canReceive).toBe(true);
    }
  });

  test('RSA-OAEP-384/512 are unavailable in both directions until specified', () => {
    for (const identifier of ['RSA-OAEP-384', 'RSA-OAEP-512']) {
      const descriptor = lookupAlgorithm(identifier, 'jwe_alg')!;
      expect(descriptor.category).toBe('unspecified');
      expect(descriptor.canCreate).toBe(false);
      expect(descriptor.canReceive).toBe(false);
    }
  });

  test('required content encryption is eligible and CBC-HMAC is supported', () => {
    for (const identifier of ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']) {
      expect(lookupAlgorithm(identifier, 'jwe_enc')!.defaultEligible).toBe(true);
    }
    expect(lookupAlgorithm('A192GCM', 'jwe_enc')!.defaultEligible).toBe(false);
    expect(lookupAlgorithm('A192CBC-HS384', 'jwe_enc')!.defaultEligible).toBe(false);
  });
});

describe('ALG-07 JWK-only identifiers', () => {
  test('are prohibited in every algorithm-selector position', () => {
    for (const identifier of ['RS1', 'HS1', 'A128CBC', 'A192CBC', 'A256CBC', 'A128CTR', 'A192CTR', 'A256CTR']) {
      expect(isProhibitedAlgorithm(identifier, 'jws')).toBe(true);
      expect(isProhibitedAlgorithm(identifier, 'jwe_alg')).toBe(true);
      expect(isProhibitedAlgorithm(identifier, 'jwe_enc')).toBe(true);
    }
  });

  test('raw CBC identifiers are not accepted as a content algorithm', () => {
    // The AES-CBC-HMAC constructions are distinct authenticated-encryption
    // algorithms; a raw CBC identifier names an unauthenticated mode and must
    // never be accepted in its place.
    expect(lookupAlgorithm('A128CBC', 'jwe_enc')!.canReceive).toBe(false);
    expect(lookupAlgorithm('A128CBC-HS256', 'jwe_enc')!.canReceive).toBe(true);
  });
});

describe('usage-context scoping', () => {
  test('an identifier is only defined in its registered context', () => {
    // `enc` is registered for JWE only, so a JWS-borne
    // content-encryption name selects no JWS capability.
    expect(lookupAlgorithm('A128GCM', 'jws')).toBeUndefined();
    expect(lookupAlgorithm('HS256', 'jwe_alg')).toBeUndefined();
    expect(lookupAlgorithm('dir', 'jws')).toBeUndefined();
    expect(lookupAlgorithm('A128GCM', 'jwe_enc')).toBeDefined();
  });

  test('a JWE-only enc name in a JWS is not a prohibited-algorithm trigger', () => {
    expect(isProhibitedAlgorithm('A128GCM', 'jws')).toBe(false);
  });

  test('unknown identifiers are absent rather than dynamically admitted', () => {
    expect(lookupAlgorithm('HS256 ', 'jws')).toBeUndefined();
    expect(lookupAlgorithm('hs256', 'jws')).toBeUndefined();
    expect(lookupAlgorithm('FN-DSA-512', 'jws')).toBeUndefined();
    expect(lookupAlgorithm('ESP256', 'jws')).toBeUndefined();
  });
});

describe('defaultEligibleAlgorithms', () => {
  test('excludes prohibited, legacy, and optional identifiers', () => {
    const eligible = defaultEligibleAlgorithms('jws');
    expect(eligible).toContain('ES256');
    expect(eligible).not.toContain('none');
    expect(eligible).not.toContain('EdDSA');
    expect(eligible).not.toContain('ES256K');
  });
});

describe('AlgorithmPolicy configuration validation', () => {
  test('accepts a supported allowlist', () => {
    const policy = AlgorithmPolicy.create('jws', ['ES256', 'HS256'], 'receive');
    expect(policy.identifiers()).toEqual(['ES256', 'HS256']);
    expect(policy.has('ES256')).toBe(true);
  });

  test('rejects prohibited, unknown, and empty configuration before token work', () => {
    expect(() => AlgorithmPolicy.create('jws', ['none'], 'receive')).toThrow(RangeError);
    expect(() => AlgorithmPolicy.create('jwe_alg', ['RSA1_5'], 'receive')).toThrow(RangeError);
    expect(() => AlgorithmPolicy.create('jws', ['MADE-UP'], 'receive')).toThrow(RangeError);
    expect(() => AlgorithmPolicy.create('jws', [], 'receive')).toThrow(RangeError);
  });

  test('rejects a receive-only algorithm configured for creation', () => {
    expect(() => AlgorithmPolicy.create('jws', ['EdDSA'], 'create')).toThrow(RangeError);
    expect(() => AlgorithmPolicy.create('jws', ['EdDSA'], 'receive')).toThrow('not qualified');
    expect(() => AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP'], 'create')).toThrow(RangeError);
  });

  test('rejects an unspecified algorithm in either direction', () => {
    expect(() => AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-384'], 'receive')).toThrow(RangeError);
    expect(() => AlgorithmPolicy.create('jwe_alg', ['RSA-OAEP-384'], 'create')).toThrow(RangeError);
  });

  test('rejects implemented algorithms that have not passed backend qualification', () => {
    expect(() => AlgorithmPolicy.create('jws', ['Ed25519'], 'receive')).toThrow('not qualified');
    expect(() => AlgorithmPolicy.create('jws', ['Ed448'], 'receive')).toThrow('not qualified');
  });
});

describe('decideAlgorithm dispositions', () => {
  const policy = AlgorithmPolicy.create('jws', ['ES256', 'HS256'], 'receive');

  test('permits an allowlisted algorithm', () => {
    const decision = decideAlgorithm(policy, 'ES256');
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.descriptor.identifier).toBe('ES256');
    }
  });

  test('separates the three dispositions into distinct categories', () => {
    // Implemented but outside the caller's allowlist.
    const excluded = decideAlgorithm(policy, 'RS256');
    expect(excluded.ok).toBe(false);
    if (!excluded.ok) {
      expect(excluded.category).toBe('policy_violation');
    }

    // No implemented and specified capability.
    const unsupported = decideAlgorithm(policy, 'MADE-UP');
    expect(unsupported.ok).toBe(false);
    if (!unsupported.ok) {
      expect(unsupported.category).toBe('unsupported_algorithm');
    }

    // Project prohibited.
    const prohibited = decideAlgorithm(policy, 'none');
    expect(prohibited.ok).toBe(false);
    if (!prohibited.ok) {
      expect(prohibited.category).toBe('prohibited_algorithm');
    }
  });

  test('reports an out-of-context identifier as unsupported, not prohibited', () => {
    const decision = decideAlgorithm(policy, 'A128GCM');
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.category).toBe('unsupported_algorithm');
    }
  });

  test('bounds the identifier length before lookup', () => {
    const decision = decideAlgorithm(policy, 'A'.repeat(65));
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.category).toBe('resource_limit');
    }

    // Exactly at the 64-octet boundary it is a normal unsupported identifier.
    const boundary = decideAlgorithm(policy, 'A'.repeat(64));
    expect(boundary.ok).toBe(false);
    if (!boundary.ok) {
      expect(boundary.category).toBe('unsupported_algorithm');
    }
  });

  test('is case-sensitive', () => {
    const decision = decideAlgorithm(policy, 'es256');
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.category).toBe('unsupported_algorithm');
    }
  });
});
