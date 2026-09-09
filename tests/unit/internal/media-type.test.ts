/**
 * `typ` and `cty` decide whether a token is the kind the caller expected, so
 * every spelling of one type must reduce to a single value and distinct types
 * must never collide.
 */

import { describe, expect, test } from 'bun:test';

import { normalizeMediaType } from '../../../src/internal/headers/media-type.ts';

describe('equivalent spellings reduce to one value', () => {
  test('supplies the implied application/ prefix', () => {
    expect(normalizeMediaType('JWT')).toBe('application/jwt');
    expect(normalizeMediaType('application/JWT')).toBe('application/jwt');
    expect(normalizeMediaType('project+jwt')).toBe('application/project+jwt');
    expect(normalizeMediaType('application/project+jwt')).toBe('application/project+jwt');
  });

  test('folds type and subtype case', () => {
    expect(normalizeMediaType('APPLICATION/PROJECT+JWT')).toBe('application/project+jwt');
    expect(normalizeMediaType('Application/Project+Jwt')).toBe('application/project+jwt');
  });

  test('leaves an explicit non-application type on its own tree', () => {
    // Only a value without a slash gains the prefix; prefixing an explicit type
    // would map it onto a different one.
    expect(normalizeMediaType('text/plain')).toBe('text/plain');
    expect(normalizeMediaType('application/text/plain')).toBeUndefined();
  });
});

describe('distinct types stay distinct', () => {
  test('does not treat a longer subtype as a match for a shorter one', () => {
    expect(normalizeMediaType('project+jwt')).not.toBe(normalizeMediaType('project+jwt2'));
    expect(normalizeMediaType('application/jwt')).not.toBe(normalizeMediaType('application/jwt+inner'));
  });

  test('refuses a value carrying parameters rather than stripping them', () => {
    // Stripping would equate two types differing only in a parameter, and a
    // parameter value is not case-foldable into the comparison.
    expect(normalizeMediaType('application/jwt;charset=utf-8')).toBeUndefined();
    expect(normalizeMediaType('application/jwt; charset=utf-8')).toBeUndefined();
  });
});

describe('malformed values are refused rather than repaired', () => {
  test('rejects structurally invalid media types', () => {
    for (const value of ['', '/', 'a/', '/b', 'application//jwt', 'app lication/jwt', 'application/jwt extra']) {
      expect(normalizeMediaType(value)).toBeUndefined();
    }
  });

  test('rejects surrounding whitespace instead of trimming it', () => {
    // The received bytes are what a producer authenticated, so trimming would
    // accept two encodings of one value.
    expect(normalizeMediaType(' application/jwt')).toBeUndefined();
    expect(normalizeMediaType('application/jwt ')).toBeUndefined();
    expect(normalizeMediaType('application/jwt\n')).toBeUndefined();
  });
});
