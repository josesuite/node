import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { inspect } from 'node:util';

import { ERROR_CATEGORIES, failure, isErrorCategory, isJoseError, JoseError, ok } from '../../../src/errors/index.ts';

describe('ERROR-01 categories', () => {
  test('exposes exactly the ERROR-01 category names', () => {
    assert.deepStrictEqual(
      [...ERROR_CATEGORIES],
      [
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
      ],
    );
  });

  test('keeps `not_selected` out of the error categories', () => {
    // `not_selected` is a General JWE entry status, never a category.
    assert.strictEqual(isErrorCategory('not_selected'), false);
    assert.strictEqual(isErrorCategory('decryption_failure'), false);
    assert.strictEqual(isErrorCategory('invalid_key'), true);
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
    assert.ok(!serialized.includes('secret-bearing'));
    assert.deepStrictEqual(JSON.parse(serialized), {
      category: 'backend_failure',
      stage: 'cryptographic',
      reason: 'provider_unavailable',
    });
    // The cause stays reachable in-process for trusted debugging.
    assert.ok(error.cause instanceof Error);
  });

  test('omits the backend cause from Node inspection', () => {
    const error = new JoseError({
      category: 'backend_failure',
      stage: 'cryptographic',
      reason: 'provider_unavailable',
      cause: new Error('secret-bearing provider detail'),
    });

    const inspected = inspect(error);
    assert.ok(inspected.includes("category: 'backend_failure'"));
    assert.ok(!inspected.includes('secret-bearing'));
    assert.ok(!inspected.includes('cause'));
  });

  test('message carries only the category and reason slug', () => {
    const error = new JoseError({
      category: 'invalid_header',
      stage: 'header',
      reason: 'missing_alg',
      location: 'protected.alg',
    });

    assert.strictEqual(error.message, 'invalid_header: missing_alg');
    assert.deepStrictEqual(error.toDiagnostic(), {
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

    assert.strictEqual(Object.hasOwn(error.toDiagnostic(), 'location'), false);
  });

  test('is recognizable as a JoseError', () => {
    const error = new JoseError({
      category: 'policy_violation',
      stage: 'configuration',
      reason: 'invalid_threshold',
    });

    assert.strictEqual(isJoseError(error), true);
    assert.strictEqual(isJoseError(new Error('other')), false);
    assert.ok(error instanceof Error);
    assert.strictEqual(error.name, 'JoseError');
  });
});

describe('JoseResult', () => {
  test('success carries a value and failure carries an error only', () => {
    const success = ok(42);
    assert.strictEqual(success.ok, true);
    if (success.ok) {
      assert.strictEqual(success.value, 42);
    }

    const failed = failure<number>({
      category: 'expired_token',
      stage: 'claims_semantics',
      reason: 'exp_boundary',
    });

    assert.strictEqual(failed.ok, false);
    // A failed result has no value-shaped branch to read.
    if (!failed.ok) {
      assert.strictEqual(failed.error.category, 'expired_token');
    }
    assert.strictEqual(Object.hasOwn(failed, 'value'), false);
  });
});
