import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { type JsonBudget, parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject, JsonValue } from '../../../src/internal/json/types.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

const BUDGET: JsonBudget = LIMITS_V1;

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function parse(text: string, budget: JsonBudget = BUDGET): JsonValue {
  const result = parseJson(bytes(text), budget);
  if (!result.ok) {
    throw new Error(`expected success, got ${result.failure} for ${text}`);
  }
  return result.value;
}

function failure(text: string, budget: JsonBudget = BUDGET): string {
  const result = parseJson(bytes(text), budget);
  if (result.ok) {
    throw new Error(`expected failure for ${text}`);
  }
  return result.failure;
}

function asObject(value: JsonValue): JsonObject {
  if (value.kind !== 'object') {
    throw new Error(`expected object, got ${value.kind}`);
  }
  return value;
}

function member(text: string, name: string): JsonValue {
  const value = asObject(parse(text)).members.get(name);
  if (value === undefined) {
    throw new Error(`missing member ${name}`);
  }
  return value;
}

/** Narrows to a string node, projecting away positional fields the assertions do not cover. */
function stringMember(object: JsonObject, name: string): { kind: string; value: string } {
  const value = object.members.get(name);
  if (value === undefined || value.kind !== 'string') {
    throw new Error(`expected string member ${name}`);
  }
  return { kind: value.kind, value: value.value };
}

/** The decoded text of a string member, for assertions that only cover the value. */
function stringValue(text: string, name: string): string {
  const value = member(text, name);
  if (value.kind !== 'string') {
    throw new Error(`expected string, got ${value.kind}`);
  }
  return value.value;
}

/** The verbatim lexeme of a number member, preserved exactly as it appeared in the source. */
function numberLexeme(text: string, name: string): string {
  const value = member(text, name);
  if (value.kind !== 'number') {
    throw new Error(`expected number, got ${value.kind}`);
  }
  return value.lexeme;
}

describe('structure', () => {
  test('parses the JOSE header shapes', () => {
    const header = asObject(parse('{"alg":"HS256","typ":"JWT"}'));
    assert.strictEqual(header.members.size, 2);
    assert.deepStrictEqual(stringMember(header, 'alg'), { kind: 'string', value: 'HS256' });
  });

  test('parses empty containers and nested values', () => {
    assert.strictEqual(asObject(parse('{}')).members.size, 0);
    const array = parse('[]');
    assert.strictEqual(array.kind, 'array');
    assert.strictEqual(parse('{"a":{"b":[1,true,null]}}').kind, 'object');
  });

  test('accepts insignificant whitespace between tokens', () => {
    assert.strictEqual(asObject(parse(' {\t"a"\n:\r1 } ')).members.size, 1);
  });

  test('records source spans covering the original bytes', () => {
    const source = '{"alg":"HS256"}';
    const header = asObject(parse(source));
    assert.deepStrictEqual(header.span, { start: 0, end: source.length });
    assert.deepStrictEqual(header.members.get('alg')!.span, { start: 7, end: 14 });
  });

  test('rejects trailing data after the root value', () => {
    assert.strictEqual(failure('{} {}'), 'malformed');
    assert.strictEqual(failure('{}x'), 'malformed');
    assert.strictEqual(failure('1 2'), 'malformed');
  });

  test('rejects comments and trailing commas', () => {
    assert.strictEqual(failure('{"a":1} // note'), 'malformed');
    assert.strictEqual(failure('{/*x*/"a":1}'), 'malformed');
    assert.strictEqual(failure('{"a":1,}'), 'malformed');
    assert.strictEqual(failure('[1,]'), 'malformed');
  });

  test('rejects truncated and unbalanced documents', () => {
    assert.strictEqual(failure(''), 'malformed');
    assert.strictEqual(failure('{'), 'malformed');
    assert.strictEqual(failure('{"a"'), 'malformed');
    assert.strictEqual(failure('{"a":}'), 'malformed');
    assert.strictEqual(failure('[1'), 'malformed');
    assert.strictEqual(failure('{"a":1]'), 'malformed');
  });

  test('rejects a byte-order mark', () => {
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, ...bytes('{}')]);
    const result = parseJson(withBom, BUDGET);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'invalid_encoding');
    }
  });
});

describe('JSON-02 duplicate members', () => {
  test('rejects duplicate names in the root object', () => {
    assert.strictEqual(failure('{"alg":"HS256","alg":"none"}'), 'duplicate_member');
  });

  test('rejects duplicates in nested and unknown objects', () => {
    assert.strictEqual(failure('{"h":{"alg":"HS256","alg":"none"}}'), 'duplicate_member');
    assert.strictEqual(failure('{"unknown":{"x":1,"x":2}}'), 'duplicate_member');
    assert.strictEqual(failure('[{"a":1,"a":2}]'), 'duplicate_member');
  });

  test('compares names after escape decoding', () => {
    // "\u0061lg" decodes to "alg" and must collide with a literal "alg".
    assert.strictEqual(failure('{"alg":"HS256","\\u0061lg":"none"}'), 'duplicate_member');
    assert.strictEqual(failure('{"\\u0061lg":"none","alg":"HS256"}'), 'duplicate_member');
  });

  test('does not Unicode-normalize names', () => {
    // U+00E9 and "e" + U+0301 are distinct member names, not duplicates.
    const value = asObject(parse('{"é":1,"e\\u0301":2}'));
    assert.strictEqual(value.members.size, 2);
  });

  test('treats prototype-polluting names as ordinary data', () => {
    const value = asObject(parse('{"__proto__":{"polluted":true},"constructor":1}'));
    assert.notStrictEqual(value.members.get('__proto__'), undefined);
    assert.notStrictEqual(value.members.get('constructor'), undefined);
    assert.strictEqual(({} as Record<string, unknown>)['polluted'], undefined);
    assert.strictEqual(Object.getPrototypeOf({}), Object.prototype);
  });

  test('rejects duplicate prototype-like names', () => {
    assert.strictEqual(failure('{"__proto__":1,"__proto__":2}'), 'duplicate_member');
  });
});

describe('strings', () => {
  test('decodes the standard escape sequences', () => {
    assert.strictEqual(stringValue('{"a":"\\"\\\\\\/\\b\\f\\n\\r\\t"}', 'a'), '"\\/\b\f\n\r\t');
  });

  test('decodes a surrogate pair escape into one scalar value', () => {
    assert.strictEqual(stringValue('{"a":"\\ud83d\\udd10"}', 'a'), '\u{1f510}');
  });

  test('rejects lone surrogate escapes', () => {
    assert.strictEqual(failure('{"a":"\\ud800"}'), 'invalid_encoding');
    assert.strictEqual(failure('{"a":"\\udc00"}'), 'invalid_encoding');
    assert.strictEqual(failure('{"a":"\\ud800x"}'), 'invalid_encoding');
    assert.strictEqual(failure('{"a":"\\ud800\\u0041"}'), 'invalid_encoding');
  });

  test('rejects invalid escapes and unescaped control characters', () => {
    assert.strictEqual(failure('{"a":"\\x41"}'), 'malformed');
    assert.strictEqual(failure('{"a":"\\u00zz"}'), 'malformed');
    assert.strictEqual(failure('{"a":"\\u00"}'), 'malformed');
    assert.strictEqual(failure('{"a":"raw\u0001"}'), 'malformed');
    assert.strictEqual(failure('{"a":"raw\nnewline"}'), 'malformed');
  });

  test('rejects invalid UTF-8 inside a string', () => {
    const source = new Uint8Array([...bytes('{"a":"'), 0xc0, 0xaf, ...bytes('"}')]);
    const result = parseJson(source, BUDGET);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'invalid_encoding');
    }
  });

  test('accepts multi-byte scalar values verbatim', () => {
    assert.strictEqual(stringValue('{"a":"héllo €"}', 'a'), 'héllo €');
  });

  test('distinguishes a JSON string containing JSON from an object', () => {
    // A string containing JSON is not a JSON object.
    assert.strictEqual(member('{"a":"{\\"b\\":1}"}', 'a').kind, 'string');
  });
});

describe('LIMIT-02 exact numbers', () => {
  test('preserves the exact lexeme rather than an IEEE-754 value', () => {
    // This value is not representable as a double; the lexeme must survive.
    assert.strictEqual(member('{"a":9007199254740993}', 'a').kind, 'number');
    assert.strictEqual(numberLexeme('{"a":9007199254740993}', 'a'), '9007199254740993');
    assert.strictEqual(numberLexeme('{"a":1.0}', 'a'), '1.0');
    assert.strictEqual(numberLexeme('{"a":-0}', 'a'), '-0');
    assert.strictEqual(numberLexeme('{"a":1e2}', 'a'), '1e2');
  });

  test('accepts the RFC 8259 number grammar', () => {
    for (const lexeme of ['0', '-0', '1', '-1', '1.5', '1e2', '1E+2', '1e-2', '0.5', '-1.5e-3']) {
      assert.strictEqual(numberLexeme(`{"a":${lexeme}}`, 'a'), lexeme);
    }
  });

  test('rejects non-JSON numeric forms', () => {
    for (const lexeme of ['NaN', 'Infinity', '-Infinity', '+1', '01', '-01', '.5', '1.', '1e', 'Ox1']) {
      assert.strictEqual(failure(`{"a":${lexeme}}`), 'malformed');
    }
  });

  test('bounds the number lexeme and exponent magnitude', () => {
    assert.strictEqual(failure(`{"a":1e${'9'.repeat(4)}}`), 'resource_limit');
    assert.strictEqual(numberLexeme('{"a":1e308}', 'a'), '1e308');
    assert.strictEqual(failure('{"a":1e309}'), 'resource_limit');
    assert.strictEqual(failure(`{"a":${'1'.repeat(129)}}`), 'resource_limit');
    assert.notStrictEqual(member(`{"a":${'1'.repeat(128)}}`, 'a'), undefined);
  });
});

describe('LIMIT-01 structural budgets', () => {
  test('enforces depth counting the root as one', () => {
    // The budget counts container nesting; a scalar leaf occupies no level of
    // its own, so the deepest permitted containers may still hold one.
    const budget: JsonBudget = { ...BUDGET, jsonDepth: 3 };
    assert.notStrictEqual(parse('{"a":{"b":1}}', budget), undefined);
    assert.notStrictEqual(parse('{"a":{"b":{"c":1}}}', budget), undefined);
    assert.strictEqual(failure('{"a":{"b":{"c":{"d":1}}}}', budget), 'resource_limit');

    const single: JsonBudget = { ...BUDGET, jsonDepth: 1 };
    assert.notStrictEqual(parse('{"a":1}', single), undefined);
    assert.strictEqual(failure('{"a":{"b":1}}', single), 'resource_limit');
  });

  test('enforces object member and array element counts', () => {
    const members = Array.from({ length: 129 }, (_, i) => `"k${i}":1`).join(',');
    assert.strictEqual(failure(`{${members}}`), 'resource_limit');

    const elements = Array.from({ length: 1025 }, () => '1').join(',');
    assert.strictEqual(failure(`[${elements}]`), 'resource_limit');
  });

  test('accepts counts exactly at the boundary', () => {
    const members = Array.from({ length: 128 }, (_, i) => `"k${i}":1`).join(',');
    assert.strictEqual(asObject(parse(`{${members}}`)).members.size, 128);

    const elements = Array.from({ length: 1024 }, () => '1').join(',');
    assert.strictEqual(parse(`[${elements}]`).kind, 'array');
  });

  test('enforces the total node budget', () => {
    const budget: JsonBudget = { ...BUDGET, jsonNodes: 5 };
    assert.notStrictEqual(parse('[1,2,3,4]', budget), undefined);
    assert.strictEqual(failure('[1,2,3,4,5]', budget), 'resource_limit');
  });

  test('enforces the decoded string budget on both parse paths', () => {
    const budget: JsonBudget = { ...BUDGET, jsonString: 4 };
    assert.notStrictEqual(parse('{"a":"abcd"}', budget), undefined);
    assert.strictEqual(failure('{"a":"abcde"}', budget), 'resource_limit');
    // Escape path: five decoded characters from escape sequences.
    assert.strictEqual(failure('{"a":"\\n\\n\\n\\n\\n"}', budget), 'resource_limit');

    // Both paths measure decoded UTF-8 octets, so the escaped and literal
    // spellings of one string consume the same budget. `é` is two octets.
    const twoOctets: JsonBudget = { ...BUDGET, jsonString: 2 };
    assert.notStrictEqual(parse('{"a":"é"}', twoOctets), undefined);
    assert.notStrictEqual(parse('{"a":"\\u00e9"}', twoOctets), undefined);

    const oneOctet: JsonBudget = { ...BUDGET, jsonString: 1 };
    assert.strictEqual(failure('{"a":"é"}', oneOctet), 'resource_limit');
    assert.strictEqual(failure('{"a":"\\u00e9"}', oneOctet), 'resource_limit');
  });

  test('reports the node budget for a deeply nested document', () => {
    const depth = 40;
    const nested = '['.repeat(depth) + ']'.repeat(depth);
    assert.strictEqual(failure(nested), 'resource_limit');
  });
});

describe('parse result metadata', () => {
  test('reports the number of parsed nodes', () => {
    const result = parseJson(bytes('{"a":[1,2]}'), BUDGET);
    assert.strictEqual(result.ok, true);
    // object + array + two numbers.
    if (result.ok) {
      assert.strictEqual(result.nodes, 4);
    }
  });
});
