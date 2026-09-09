/**
 * `typ` and `cty` decide whether a token is the kind the caller expected, so
 * every spelling of one type must reduce to a single value and distinct types
 * must never collide.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { normalizeMediaType } from '../../../src/internal/headers/media-type.ts';

describe('equivalent spellings reduce to one value', () => {
  test('supplies the implied application/ prefix', () => {
    assert.strictEqual(normalizeMediaType('JWT'), 'application/jwt');
    assert.strictEqual(normalizeMediaType('application/JWT'), 'application/jwt');
    assert.strictEqual(normalizeMediaType('project+jwt'), 'application/project+jwt');
    assert.strictEqual(normalizeMediaType('application/project+jwt'), 'application/project+jwt');
  });

  test('folds type and subtype case', () => {
    assert.strictEqual(normalizeMediaType('APPLICATION/PROJECT+JWT'), 'application/project+jwt');
    assert.strictEqual(normalizeMediaType('Application/Project+Jwt'), 'application/project+jwt');
  });

  test('leaves an explicit non-application type on its own tree', () => {
    // Only a value without a slash gains the prefix; prefixing an explicit type
    // would map it onto a different one.
    assert.strictEqual(normalizeMediaType('text/plain'), 'text/plain');
    assert.strictEqual(normalizeMediaType('application/text/plain'), undefined);
  });
});

describe('distinct types stay distinct', () => {
  test('does not treat a longer subtype as a match for a shorter one', () => {
    assert.notStrictEqual(normalizeMediaType('project+jwt'), normalizeMediaType('project+jwt2'));
    assert.notStrictEqual(normalizeMediaType('application/jwt'), normalizeMediaType('application/jwt+inner'));
  });

  test('refuses a value carrying parameters rather than stripping them', () => {
    // Stripping would equate two types differing only in a parameter, and a
    // parameter value is not case-foldable into the comparison.
    assert.strictEqual(normalizeMediaType('application/jwt;charset=utf-8'), undefined);
    assert.strictEqual(normalizeMediaType('application/jwt; charset=utf-8'), undefined);
  });
});

describe('malformed values are refused rather than repaired', () => {
  test('rejects structurally invalid media types', () => {
    for (const value of ['', '/', 'a/', '/b', 'application//jwt', 'app lication/jwt', 'application/jwt extra']) {
      assert.strictEqual(normalizeMediaType(value), undefined);
    }
  });

  test('rejects surrounding whitespace instead of trimming it', () => {
    // The received bytes are what a producer authenticated, so trimming would
    // accept two encodings of one value.
    assert.strictEqual(normalizeMediaType(' application/jwt'), undefined);
    assert.strictEqual(normalizeMediaType('application/jwt '), undefined);
    assert.strictEqual(normalizeMediaType('application/jwt\n'), undefined);
  });
});
