import { describe, expect, test } from 'bun:test';
import { inspect } from 'node:util';

import { ERROR_CATEGORIES, failure, isErrorCategory, isJoseError, JoseError, ok } from '../../../src/errors/index.ts';

describe('ERROR-01 categories', () => {
  test('exposes exactly the ERROR-01 category names', () => {
    expect([...ERROR_CATEGORIES]).toEqual([
      'malformed_input',
      'unsupported_serialization',
      'invalid_encoding',
      'invalid_header',
      'unsupported_critical_parameter',
      'unsupported_algorithm',
      'prohibited_algorithm',
      'invalid_key',
      'incompatible_key',
      'key_resolution_failure',
      'signature_verification_failure',
      'authentication_failure',
      'claim_validation_failure',
      'expired_token',
      'token_not_yet_valid',
      'issuer_mismatch',
      'audience_mismatch',
      'token_type_mismatch',
      'replay_detected',
      'resource_limit',
      'policy_violation',
      'backend_failure',
    ]);
  });

  test('keeps `not_selected` out of the error categories', () => {
    // `not_selected` is a General JWE entry status, never a category.
    expect(isErrorCategory('not_selected')).toBe(false);
    expect(isErrorCategory('decryption_failure')).toBe(false);
    expect(isErrorCategory('invalid_key')).toBe(true);
  });
});

describe('ERROR-02 sanitized diagnostics', () => {
  test('omits the backend cause and stack from serialized output', () => {
    const error = new JoseError({
      category: 'backend_failure',
      stage: 'cryptographic',
      reason: 'provider_unavailable',
      cause: new Error('secret-bearing provider detail'),
    });

    const serialized = JSON.stringify(error);
    expect(serialized).not.toContain('secret-bearing');
    expect(JSON.parse(serialized)).toEqual({
      category: 'backend_failure',
      stage: 'cryptographic',
      reason: 'provider_unavailable',
    });
    // The cause stays reachable in-process for trusted debugging.
    expect(error.cause).toBeInstanceOf(Error);
  });

  test('omits the backend cause from Node inspection', () => {
    const error = new JoseError({
      category: 'backend_failure',
      stage: 'cryptographic',
      reason: 'provider_unavailable',
      cause: new Error('secret-bearing provider detail'),
    });

    const inspected = inspect(error);
    expect(inspected).toContain("category: 'backend_failure'");
    expect(inspected).not.toContain('secret-bearing');
    expect(inspected).not.toContain('cause');
  });

  test('message carries only the category and reason slug', () => {
    const error = new JoseError({
      category: 'invalid_header',
      stage: 'header',
      reason: 'missing_alg',
      location: 'protected.alg',
    });

    expect(error.message).toBe('invalid_header: missing_alg');
    expect(error.toDiagnostic()).toEqual({
      category: 'invalid_header',
      stage: 'header',
      reason: 'missing_alg',
      location: 'protected.alg',
    });
  });

  test('omits an absent location rather than emitting undefined', () => {
    const error = new JoseError({
      category: 'resource_limit',
      stage: 'syntax',
      reason: 'payload_too_large',
    });

    expect(Object.hasOwn(error.toDiagnostic(), 'location')).toBe(false);
  });

  test('is recognizable as a JoseError', () => {
    const error = new JoseError({
      category: 'policy_violation',
      stage: 'configuration',
      reason: 'invalid_threshold',
    });

    expect(isJoseError(error)).toBe(true);
    expect(isJoseError(new Error('other'))).toBe(false);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('JoseError');
  });
});

describe('JoseResult', () => {
  test('success carries a value and failure carries an error only', () => {
    const success = ok(42);
    expect(success.ok).toBe(true);
    if (success.ok) {
      expect(success.value).toBe(42);
    }

    const failed = failure<number>({
      category: 'expired_token',
      stage: 'claims_semantics',
      reason: 'exp_boundary',
    });

    expect(failed.ok).toBe(false);
    // A failed result has no value-shaped branch to read.
    if (!failed.ok) {
      expect(failed.error.category).toBe('expired_token');
    }
    expect(Object.hasOwn(failed, 'value')).toBe(false);
  });
});
