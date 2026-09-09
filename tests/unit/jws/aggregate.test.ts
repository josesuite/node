import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

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
    assert.strictEqual(allRequiredSigners([]).ok, false);
    assert.strictEqual(thresholdOfSigners([], 1).ok, false);
  });

  test('rejects duplicate principals in a set', () => {
    // The predicate counts distinct principals, so a duplicate makes the
    // intended set size ambiguous.
    const required = allRequiredSigners(['a', 'a']);
    assert.strictEqual(required.ok, false);
    if (!required.ok) {
      assert.strictEqual(required.reason, 'required_set_duplicate');
      assert.strictEqual(required.category, 'policy_violation');
    }

    assert.strictEqual(thresholdOfSigners(['a', 'a'], 1).ok, false);
  });

  test('rejects an out-of-range threshold', () => {
    assert.strictEqual(thresholdOfSigners(['a', 'b'], 0).ok, false);
    assert.strictEqual(thresholdOfSigners(['a', 'b'], 3).ok, false);
    assert.strictEqual(thresholdOfSigners(['a', 'b'], 1.5).ok, false);

    // The boundaries themselves are valid.
    assert.strictEqual(thresholdOfSigners(['a', 'b'], 1).ok, true);
    assert.strictEqual(thresholdOfSigners(['a', 'b'], 2).ok, true);
  });

  test('rejects an empty principal identifier', () => {
    assert.strictEqual(namedSigner('').ok, false);
    assert.strictEqual(allRequiredSigners(['a', '']).ok, false);
    assert.strictEqual(thresholdOfSigners(['a', ''], 1).ok, false);
  });
});

describe('named signer predicate', () => {
  const policy = policyOf(namedSigner('alice'));

  test('accepts only when the named principal is established', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['alice'])), true);
    assert.strictEqual(isSatisfied(policy, new Set()), false);
  });

  test('an unrelated valid signer does not satisfy it', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['mallory'])), false);
    assert.strictEqual(isSatisfied(policy, new Set(['bob', 'carol'])), false);
  });

  test('other principals alongside the named one do not prevent acceptance', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'mallory'])), true);
  });
});

describe('all-required predicate', () => {
  const policy = policyOf(allRequiredSigners(['alice', 'bob']));

  test('requires every member', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'bob'])), true);
    assert.strictEqual(isSatisfied(policy, new Set(['alice'])), false);
    assert.strictEqual(isSatisfied(policy, new Set(['bob'])), false);
  });

  test('principals outside the set do not substitute for a missing member', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'carol', 'dave'])), false);
  });
});

describe('threshold predicate', () => {
  const policy = policyOf(thresholdOfSigners(['alice', 'bob', 'carol'], 2));

  test('counts distinct eligible principals', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'bob'])), true);
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'carol'])), true);
    assert.strictEqual(isSatisfied(policy, new Set(['alice'])), false);
  });

  test('successful principals outside the eligible set do not count', () => {
    // Two established principals, but only one is eligible.
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'mallory'])), false);
    assert.strictEqual(isSatisfied(policy, new Set(['mallory', 'trent'])), false);
  });

  test('exceeding the threshold still accepts', () => {
    assert.strictEqual(isSatisfied(policy, new Set(['alice', 'bob', 'carol'])), true);
  });
});

describe('referenced principals', () => {
  test('reports the principals each policy depends on', () => {
    assert.deepStrictEqual([...referencedPrincipals(policyOf(namedSigner('alice')))], ['alice']);
    assert.deepStrictEqual([...referencedPrincipals(policyOf(allRequiredSigners(['a', 'b'])))].toSorted(), ['a', 'b']);
    assert.deepStrictEqual([...referencedPrincipals(policyOf(thresholdOfSigners(['a', 'b'], 1)))].toSorted(), [
      'a',
      'b',
    ]);
  });
});
