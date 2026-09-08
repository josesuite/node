import { describe, expect, test } from 'bun:test';

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

describe('structure', () => {
  test('parses the JOSE header shapes', () => {
    const header = asObject(parse('{"alg":"HS256","typ":"JWT"}'));
    expect(header.members.size).toBe(2);
    expect(header.members.get('alg')).toMatchObject({ kind: 'string', value: 'HS256' });
  });

  test('parses empty containers and nested values', () => {
    expect(asObject(parse('{}')).members.size).toBe(0);
    const array = parse('[]');
    expect(array.kind).toBe('array');
    expect(parse('{"a":{"b":[1,true,null]}}').kind).toBe('object');
  });

  test('accepts insignificant whitespace between tokens', () => {
    expect(asObject(parse(' {\t"a"\n:\r1 } ')).members.size).toBe(1);
  });

  test('records source spans covering the original bytes', () => {
    const source = '{"alg":"HS256"}';
    const header = asObject(parse(source));
    expect(header.span).toEqual({ start: 0, end: source.length });
    expect(header.members.get('alg')!.span).toEqual({ start: 7, end: 14 });
  });

  test('rejects trailing data after the root value', () => {
    expect(failure('{} {}')).toBe('malformed');
    expect(failure('{}x')).toBe('malformed');
    expect(failure('1 2')).toBe('malformed');
  });

  test('rejects comments and trailing commas', () => {
    expect(failure('{"a":1} // note')).toBe('malformed');
    expect(failure('{/*x*/"a":1}')).toBe('malformed');
    expect(failure('{"a":1,}')).toBe('malformed');
    expect(failure('[1,]')).toBe('malformed');
  });

  test('rejects truncated and unbalanced documents', () => {
    expect(failure('')).toBe('malformed');
    expect(failure('{')).toBe('malformed');
    expect(failure('{"a"')).toBe('malformed');
    expect(failure('{"a":}')).toBe('malformed');
    expect(failure('[1')).toBe('malformed');
    expect(failure('{"a":1]')).toBe('malformed');
  });

  test('rejects a byte-order mark', () => {
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, ...bytes('{}')]);
    const result = parseJson(withBom, BUDGET);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('invalid_encoding');
    }
  });
});

describe('JSON-02 duplicate members', () => {
  test('rejects duplicate names in the root object', () => {
    expect(failure('{"alg":"HS256","alg":"none"}')).toBe('duplicate_member');
  });

  test('rejects duplicates in nested and unknown objects', () => {
    expect(failure('{"h":{"alg":"HS256","alg":"none"}}')).toBe('duplicate_member');
    expect(failure('{"unknown":{"x":1,"x":2}}')).toBe('duplicate_member');
    expect(failure('[{"a":1,"a":2}]')).toBe('duplicate_member');
  });

  test('compares names after escape decoding', () => {
    // "\u0061lg" decodes to "alg" and must collide with a literal "alg".
    expect(failure('{"alg":"HS256","\\u0061lg":"none"}')).toBe('duplicate_member');
    expect(failure('{"\\u0061lg":"none","alg":"HS256"}')).toBe('duplicate_member');
  });

  test('does not Unicode-normalize names', () => {
    // U+00E9 and "e" + U+0301 are distinct member names, not duplicates.
    const value = asObject(parse('{"é":1,"e\\u0301":2}'));
    expect(value.members.size).toBe(2);
  });

  test('treats prototype-polluting names as ordinary data', () => {
    const value = asObject(parse('{"__proto__":{"polluted":true},"constructor":1}'));
    expect(value.members.get('__proto__')).toBeDefined();
    expect(value.members.get('constructor')).toBeDefined();
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
  });

  test('rejects duplicate prototype-like names', () => {
    expect(failure('{"__proto__":1,"__proto__":2}')).toBe('duplicate_member');
  });
});

describe('strings', () => {
  test('decodes the standard escape sequences', () => {
    expect(member('{"a":"\\"\\\\\\/\\b\\f\\n\\r\\t"}', 'a')).toMatchObject({
      value: '"\\/\b\f\n\r\t',
    });
  });

  test('decodes a surrogate pair escape into one scalar value', () => {
    expect(member('{"a":"\\ud83d\\udd10"}', 'a')).toMatchObject({ value: '\u{1f510}' });
  });

  test('rejects lone surrogate escapes', () => {
    expect(failure('{"a":"\\ud800"}')).toBe('invalid_encoding');
    expect(failure('{"a":"\\udc00"}')).toBe('invalid_encoding');
    expect(failure('{"a":"\\ud800x"}')).toBe('invalid_encoding');
    expect(failure('{"a":"\\ud800\\u0041"}')).toBe('invalid_encoding');
  });

  test('rejects invalid escapes and unescaped control characters', () => {
    expect(failure('{"a":"\\x41"}')).toBe('malformed');
    expect(failure('{"a":"\\u00zz"}')).toBe('malformed');
    expect(failure('{"a":"\\u00"}')).toBe('malformed');
    expect(failure('{"a":"raw\u0001"}')).toBe('malformed');
    expect(failure('{"a":"raw\nnewline"}')).toBe('malformed');
  });

  test('rejects invalid UTF-8 inside a string', () => {
    const source = new Uint8Array([...bytes('{"a":"'), 0xc0, 0xaf, ...bytes('"}')]);
    const result = parseJson(source, BUDGET);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('invalid_encoding');
    }
  });

  test('accepts multi-byte scalar values verbatim', () => {
    expect(member('{"a":"héllo €"}', 'a')).toMatchObject({ value: 'héllo €' });
  });

  test('distinguishes a JSON string containing JSON from an object', () => {
    // A string containing JSON is not a JSON object.
    expect(member('{"a":"{\\"b\\":1}"}', 'a').kind).toBe('string');
  });
});

describe('LIMIT-02 exact numbers', () => {
  test('preserves the exact lexeme rather than an IEEE-754 value', () => {
    // This value is not representable as a double; the lexeme must survive.
    expect(member('{"a":9007199254740993}', 'a')).toMatchObject({
      kind: 'number',
      lexeme: '9007199254740993',
    });
    expect(member('{"a":1.0}', 'a')).toMatchObject({ lexeme: '1.0' });
    expect(member('{"a":-0}', 'a')).toMatchObject({ lexeme: '-0' });
    expect(member('{"a":1e2}', 'a')).toMatchObject({ lexeme: '1e2' });
  });

  test('accepts the RFC 8259 number grammar', () => {
    for (const lexeme of ['0', '-0', '1', '-1', '1.5', '1e2', '1E+2', '1e-2', '0.5', '-1.5e-3']) {
      expect(member(`{"a":${lexeme}}`, 'a')).toMatchObject({ lexeme });
    }
  });

  test('rejects non-JSON numeric forms', () => {
    for (const lexeme of ['NaN', 'Infinity', '-Infinity', '+1', '01', '-01', '.5', '1.', '1e', 'Ox1']) {
      expect(failure(`{"a":${lexeme}}`)).toBe('malformed');
    }
  });

  test('bounds the number lexeme and exponent magnitude', () => {
    expect(failure(`{"a":1e${'9'.repeat(4)}}`)).toBe('resource_limit');
    expect(member('{"a":1e308}', 'a')).toMatchObject({ lexeme: '1e308' });
    expect(failure('{"a":1e309}')).toBe('resource_limit');
    expect(failure(`{"a":${'1'.repeat(129)}}`)).toBe('resource_limit');
    expect(member(`{"a":${'1'.repeat(128)}}`, 'a')).toBeDefined();
  });
});

describe('LIMIT-01 structural budgets', () => {
  test('enforces depth counting the root as one', () => {
    // The budget counts container nesting; a scalar leaf occupies no level of
    // its own, so the deepest permitted containers may still hold one.
    const budget: JsonBudget = { ...BUDGET, jsonDepth: 3 };
    expect(parse('{"a":{"b":1}}', budget)).toBeDefined();
    expect(parse('{"a":{"b":{"c":1}}}', budget)).toBeDefined();
    expect(failure('{"a":{"b":{"c":{"d":1}}}}', budget)).toBe('resource_limit');

    const single: JsonBudget = { ...BUDGET, jsonDepth: 1 };
    expect(parse('{"a":1}', single)).toBeDefined();
    expect(failure('{"a":{"b":1}}', single)).toBe('resource_limit');
  });

  test('enforces object member and array element counts', () => {
    const members = Array.from({ length: 129 }, (_, i) => `"k${i}":1`).join(',');
    expect(failure(`{${members}}`)).toBe('resource_limit');

    const elements = Array.from({ length: 1025 }, () => '1').join(',');
    expect(failure(`[${elements}]`)).toBe('resource_limit');
  });

  test('accepts counts exactly at the boundary', () => {
    const members = Array.from({ length: 128 }, (_, i) => `"k${i}":1`).join(',');
    expect(asObject(parse(`{${members}}`)).members.size).toBe(128);

    const elements = Array.from({ length: 1024 }, () => '1').join(',');
    expect(parse(`[${elements}]`).kind).toBe('array');
  });

  test('enforces the total node budget', () => {
    const budget: JsonBudget = { ...BUDGET, jsonNodes: 5 };
    expect(parse('[1,2,3,4]', budget)).toBeDefined();
    expect(failure('[1,2,3,4,5]', budget)).toBe('resource_limit');
  });

  test('enforces the decoded string budget on both parse paths', () => {
    const budget: JsonBudget = { ...BUDGET, jsonString: 4 };
    expect(parse('{"a":"abcd"}', budget)).toBeDefined();
    expect(failure('{"a":"abcde"}', budget)).toBe('resource_limit');
    // Escape path: five decoded characters from escape sequences.
    expect(failure('{"a":"\\n\\n\\n\\n\\n"}', budget)).toBe('resource_limit');

    // Both paths measure decoded UTF-8 octets, so the escaped and literal
    // spellings of one string consume the same budget. `é` is two octets.
    const twoOctets: JsonBudget = { ...BUDGET, jsonString: 2 };
    expect(parse('{"a":"é"}', twoOctets)).toBeDefined();
    expect(parse('{"a":"\\u00e9"}', twoOctets)).toBeDefined();

    const oneOctet: JsonBudget = { ...BUDGET, jsonString: 1 };
    expect(failure('{"a":"é"}', oneOctet)).toBe('resource_limit');
    expect(failure('{"a":"\\u00e9"}', oneOctet)).toBe('resource_limit');
  });

  test('reports the node budget for a deeply nested document', () => {
    const depth = 40;
    const nested = '['.repeat(depth) + ']'.repeat(depth);
    expect(failure(nested)).toBe('resource_limit');
  });
});

describe('parse result metadata', () => {
  test('reports the number of parsed nodes', () => {
    const result = parseJson(bytes('{"a":[1,2]}'), BUDGET);
    expect(result.ok).toBe(true);
    // object + array + two numbers.
    if (result.ok) {
      expect(result.nodes).toBe(4);
    }
  });
});
