import { describe, expect, test } from 'bun:test';

import {
  allRequiredSigners,
  isSatisfied,
  namedSigner,
  referencedPrincipals,
  thresholdOfSigners,
} from '../../../src/jws/aggregate.ts';

function policyOf(result: ReturnType<typeof namedSigner>) {
  if (!result.ok) {
    throw new Error(`bad fixture: ${result.reason}`);
  }
  return result.policy;
}

describe('configuration validation', () => {
  test('rejects an empty required or eligible set', () => {
    expect(allRequiredSigners([]).ok).toBe(false);
    expect(thresholdOfSigners([], 1).ok).toBe(false);
  });

  test('rejects duplicate principals in a set', () => {
    // The predicate counts distinct principals, so a duplicate makes the
    // intended set size ambiguous.
    const required = allRequiredSigners(['a', 'a']);
    expect(required.ok).toBe(false);
    if (!required.ok) {
      expect(required.reason).toBe('required_set_duplicate');
      expect(required.category).toBe('policy_violation');
    }

    expect(thresholdOfSigners(['a', 'a'], 1).ok).toBe(false);
  });

  test('rejects an out-of-range threshold', () => {
    expect(thresholdOfSigners(['a', 'b'], 0).ok).toBe(false);
    expect(thresholdOfSigners(['a', 'b'], 3).ok).toBe(false);
    expect(thresholdOfSigners(['a', 'b'], 1.5).ok).toBe(false);

    // The boundaries themselves are valid.
    expect(thresholdOfSigners(['a', 'b'], 1).ok).toBe(true);
    expect(thresholdOfSigners(['a', 'b'], 2).ok).toBe(true);
  });

  test('rejects an empty principal identifier', () => {
    expect(namedSigner('').ok).toBe(false);
    expect(allRequiredSigners(['a', '']).ok).toBe(false);
    expect(thresholdOfSigners(['a', ''], 1).ok).toBe(false);
  });
});

describe('named signer predicate', () => {
  const policy = policyOf(namedSigner('alice'));

  test('accepts only when the named principal is established', () => {
    expect(isSatisfied(policy, new Set(['alice']))).toBe(true);
    expect(isSatisfied(policy, new Set())).toBe(false);
  });

  test('an unrelated valid signer does not satisfy it', () => {
    expect(isSatisfied(policy, new Set(['mallory']))).toBe(false);
    expect(isSatisfied(policy, new Set(['bob', 'carol']))).toBe(false);
  });

  test('other principals alongside the named one do not prevent acceptance', () => {
    expect(isSatisfied(policy, new Set(['alice', 'mallory']))).toBe(true);
  });
});

describe('all-required predicate', () => {
  const policy = policyOf(allRequiredSigners(['alice', 'bob']));

  test('requires every member', () => {
    expect(isSatisfied(policy, new Set(['alice', 'bob']))).toBe(true);
    expect(isSatisfied(policy, new Set(['alice']))).toBe(false);
    expect(isSatisfied(policy, new Set(['bob']))).toBe(false);
  });

  test('principals outside the set do not substitute for a missing member', () => {
    expect(isSatisfied(policy, new Set(['alice', 'carol', 'dave']))).toBe(false);
  });
});

describe('threshold predicate', () => {
  const policy = policyOf(thresholdOfSigners(['alice', 'bob', 'carol'], 2));

  test('counts distinct eligible principals', () => {
    expect(isSatisfied(policy, new Set(['alice', 'bob']))).toBe(true);
    expect(isSatisfied(policy, new Set(['alice', 'carol']))).toBe(true);
    expect(isSatisfied(policy, new Set(['alice']))).toBe(false);
  });

  test('successful principals outside the eligible set do not count', () => {
    // Two established principals, but only one is eligible.
    expect(isSatisfied(policy, new Set(['alice', 'mallory']))).toBe(false);
    expect(isSatisfied(policy, new Set(['mallory', 'trent']))).toBe(false);
  });

  test('exceeding the threshold still accepts', () => {
    expect(isSatisfied(policy, new Set(['alice', 'bob', 'carol']))).toBe(true);
  });
});

describe('referenced principals', () => {
  test('reports the principals each policy depends on', () => {
    expect([...referencedPrincipals(policyOf(namedSigner('alice')))]).toEqual(['alice']);
    expect([...referencedPrincipals(policyOf(allRequiredSigners(['a', 'b'])))].toSorted()).toEqual(['a', 'b']);
    expect([...referencedPrincipals(policyOf(thresholdOfSigners(['a', 'b'], 1)))].toSorted()).toEqual(['a', 'b']);
  });
});
