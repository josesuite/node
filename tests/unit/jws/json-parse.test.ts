import { describe, expect, test } from 'bun:test';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonValue } from '../../../src/internal/json/types.ts';
import { parseJsonJws } from '../../../src/jws/parse.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

function json(text: string): JsonValue {
  const result = parseJson(new TextEncoder().encode(text), LIMITS_V1);
  if (!result.ok) {
    throw new Error(`bad fixture: ${result.failure}`);
  }
  return result.value;
}

function parse(text: string) {
  return parseJsonJws(json(text), LIMITS_V1);
}

const HEADER = 'eyJhbGciOiJFUzI1NiJ9';

describe('form selection', () => {
  test('reads the general form from a signatures array', () => {
    const result = parse(`{"payload":"cGF5","signatures":[{"protected":"${HEADER}","signature":"c2ln"}]}`);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('general');
      expect(result.value.signatures).toHaveLength(1);
      expect(result.value.signatures[0]!.protectedComponent).toBe(HEADER);
    }
  });

  test('reads the flattened form from top-level members', () => {
    const result = parse(`{"payload":"cGF5","protected":"${HEADER}","signature":"c2ln"}`);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('flattened');
      expect(result.value.signatures).toHaveLength(1);
    }
  });

  test('rejects a hybrid carrying both forms', () => {
    // The object names one signature twice with no rule for which wins.
    const result = parse(
      `{"payload":"cGF5","protected":"${HEADER}","signature":"c2ln","signatures":[{"protected":"${HEADER}","signature":"b3Ro"}]}`,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('hybrid_serialization');
      expect(result.category).toBe('invalid_header');
    }
  });

  test('rejects a hybrid naming only one flattened member', () => {
    for (const member of ['protected', 'header', 'signature']) {
      const value = member === 'header' ? '{"kid":"a"}' : '"x"';
      const result = parse(
        `{"payload":"cGF5","${member}":${value},"signatures":[{"protected":"${HEADER}","signature":"c2ln"}]}`,
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('hybrid_serialization');
      }
    }
  });
});

describe('structural requirements', () => {
  test('rejects an empty signatures array', () => {
    // Zero entries can never satisfy the requirement that one signature
    // validate, so it is refused structurally rather than reaching a
    // zero-iteration loop that a vacuous policy could call success.
    const result = parse('{"payload":"cGF5","signatures":[]}');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('signatures_empty');
      expect(result.category).toBe('malformed_input');
    }
  });

  test('requires the signature member', () => {
    const result = parse(`{"payload":"cGF5","signatures":[{"protected":"${HEADER}"}]}`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('signature_missing');
    }
  });

  test('rejects an empty signature', () => {
    const result = parse(`{"payload":"cGF5","protected":"${HEADER}","signature":""}`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('empty_signature');
    }
  });

  test('requires a nonempty protected header', () => {
    const missing = parse('{"payload":"cGF5","signature":"c2ln"}');
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.reason).toBe('protected_missing');
    }

    const empty = parse('{"payload":"cGF5","protected":"","signature":"c2ln"}');
    expect(empty.ok).toBe(false);
    if (!empty.ok) {
      expect(empty.reason).toBe('protected_empty');
    }
  });

  test('rejects an explicitly empty unprotected header', () => {
    // An empty optional value must be omitted, not written as `{}`.
    const result = parse(`{"payload":"cGF5","protected":"${HEADER}","header":{},"signature":"c2ln"}`);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('header_empty');
    }
  });

  test('rejects wrong member types', () => {
    const cases: readonly [string, string][] = [
      [`{"payload":123,"protected":"${HEADER}","signature":"c2ln"}`, 'payload_not_a_string'],
      [`{"payload":"cGF5","protected":{"alg":"ES256"},"signature":"c2ln"}`, 'protected_not_a_string'],
      [`{"payload":"cGF5","protected":"${HEADER}","signature":["c2ln"]}`, 'signature_not_a_string'],
      [`{"payload":"cGF5","signatures":{"protected":"${HEADER}"}}`, 'signatures_not_an_array'],
      [`{"payload":"cGF5","protected":"${HEADER}","header":"nope","signature":"c2ln"}`, 'header_not_an_object'],
    ];

    for (const [text, reason] of cases) {
      const result = parse(text);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(reason);
      }
    }
  });

  test('rejects a non-object entry inside signatures', () => {
    const result = parse('{"payload":"cGF5","signatures":["not-an-object"]}');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('signature_entry_not_an_object');
    }
  });

  test('rejects a top-level value that is not an object', () => {
    for (const text of ['[]', '"string"', '42', 'null']) {
      const result = parse(text);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('jws_not_an_object');
      }
    }
  });
});

describe('payload presence', () => {
  test('distinguishes an absent payload from an empty one', () => {
    const absent = parse(`{"protected":"${HEADER}","signature":"c2ln"}`);
    expect(absent.ok).toBe(true);
    if (absent.ok) {
      // Absence marks detached form; it is not an empty payload.
      expect(absent.value.payloadComponent).toBeUndefined();
    }

    const empty = parse(`{"payload":"","protected":"${HEADER}","signature":"c2ln"}`);
    expect(empty.ok).toBe(true);
    if (empty.ok) {
      expect(empty.value.payloadComponent).toBe('');
    }
  });
});

describe('ignorable members', () => {
  test('keeps unknown noncritical members from changing the parse', () => {
    const result = parse(`{"payload":"cGF5","protected":"${HEADER}","signature":"c2ln","x-vendor":"anything"}`);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('flattened');
    }
  });
});

describe('resource bounds', () => {
  test('bounds the number of signature entries', () => {
    const entry = `{"protected":"${HEADER}","signature":"c2ln"}`;
    const many = Array.from({ length: LIMITS_V1.signatures + 1 }, () => entry).join(',');
    const result = parse(`{"payload":"cGF5","signatures":[${many}]}`);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
      expect(result.reason).toBe('too_many_signature_entries');
    }
  });
});
