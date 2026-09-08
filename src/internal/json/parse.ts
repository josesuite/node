/**
 * Bounded, duplicate-rejecting, source-preserving JSON parser for untrusted
 * JOSE input.
 *
 * `JSON.parse` cannot satisfy this contract. It silently keeps one of several
 * duplicate member names, which would let an attacker hide a second `alg` that
 * a different implementation reads instead; it converts every number to
 * IEEE-754, losing exact integer values; and it reports no source offsets, so
 * byte-accurate size accounting is impossible. None of that can be recovered by
 * re-serializing afterwards, because the information is already gone by then.
 *
 * The parser therefore runs directly over the source octets. That also lets
 * sizes be measured in bytes including internal whitespace, which is what the
 * header size budgets are defined over.
 *
 * Budgets are enforced during traversal so that a hostile document is rejected
 * while being read rather than after a complete value graph exists.
 */

import { utf8Length } from '../encoding/utf8.ts';
import type { JsonArray, JsonObject, JsonValue } from './types.ts';

export type JsonFailure =
  /** Structurally invalid JSON, including trailing data and bad escapes. */
  | 'malformed'
  /** Duplicate member name within one object, compared after escape decoding. */
  | 'duplicate_member'
  /** A depth, count, or size budget was exceeded. */
  | 'resource_limit'
  /** Invalid UTF-8 in a string, or a lone surrogate escape. */
  | 'invalid_encoding';

export type JsonParseResult =
  | { readonly ok: true; readonly value: JsonValue; readonly nodes: number }
  | { readonly ok: false; readonly failure: JsonFailure };

export interface JsonBudget {
  readonly jsonDepth: number;
  readonly jsonObjectMembers: number;
  readonly jsonArrayElements: number;
  readonly jsonNodes: number;
  readonly jsonString: number;
  readonly numberLexeme: number;
  readonly numberExponentMagnitude: number;
}

/** Thrown internally to unwind the recursive descent; never escapes `parseJson`. */
class ParseFailure extends Error {
  readonly failure: JsonFailure;

  constructor(failure: JsonFailure) {
    super(failure);
    this.failure = failure;
  }
}

const TAB = 0x09;
const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const SPACE = 0x20;
const QUOTE = 0x22;
const PLUS = 0x2b;
const COMMA = 0x2c;
const MINUS = 0x2d;
const PERIOD = 0x2e;
const SOLIDUS = 0x2f;
const DIGIT_ZERO = 0x30;
const DIGIT_NINE = 0x39;
const COLON = 0x3a;
const OPEN_BRACKET = 0x5b;
const BACKSLASH = 0x5c;
const CLOSE_BRACKET = 0x5d;
const OPEN_BRACE = 0x7b;
const CLOSE_BRACE = 0x7d;

function isDigit(byte: number): boolean {
  return byte >= DIGIT_ZERO && byte <= DIGIT_NINE;
}

class JsonParser {
  private readonly source: Uint8Array;
  private readonly budget: JsonBudget;
  private readonly decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  private offset = 0;
  private nodes = 0;

  constructor(source: Uint8Array, budget: JsonBudget) {
    this.source = source;
    this.budget = budget;
  }

  parse(): { value: JsonValue; nodes: number } {
    this.skipWhitespace();
    const value = this.parseValue(1);
    this.skipWhitespace();

    // Trailing non-whitespace data is rejected: a second value or a
    // stray byte after the root must not be ignored, since a lenient parser
    // and a strict one would then disagree about what the document contains.
    if (this.offset !== this.source.length) {
      throw new ParseFailure('malformed');
    }

    return { value, nodes: this.nodes };
  }

  private fail(failure: JsonFailure): never {
    throw new ParseFailure(failure);
  }

  private countNode(): void {
    this.nodes += 1;
    if (this.nodes > this.budget.jsonNodes) {
      this.fail('resource_limit');
    }
  }

  private peek(): number {
    if (this.offset >= this.source.length) {
      this.fail('malformed');
    }
    return this.source[this.offset]!;
  }

  private skipWhitespace(): void {
    while (this.offset < this.source.length) {
      const byte = this.source[this.offset]!;
      if (byte !== SPACE && byte !== TAB && byte !== LINE_FEED && byte !== CARRIAGE_RETURN) {
        return;
      }
      this.offset += 1;
    }
  }

  private expect(byte: number): void {
    if (this.offset >= this.source.length || this.source[this.offset] !== byte) {
      this.fail('malformed');
    }
    this.offset += 1;
  }

  private parseValue(depth: number): JsonValue {
    this.countNode();

    switch (this.peek()) {
      // The budget counts container nesting, so it is checked where a container
      // is entered rather than for every value. Checking scalars too would make
      // `{"a":1}` consume two levels while containing one.
      case OPEN_BRACE:
        this.enterContainer(depth);
        return this.parseObject(depth);
      case OPEN_BRACKET:
        this.enterContainer(depth);
        return this.parseArray(depth);
      case QUOTE: {
        const start = this.offset;
        const value = this.parseString();
        return { kind: 'string', value, span: { start, end: this.offset } };
      }
      default:
        return this.parseLiteralOrNumber();
    }
  }

  /** `depth` is 1 for the root value, so it is already this container's level. */
  private enterContainer(depth: number): void {
    if (depth > this.budget.jsonDepth) {
      this.fail('resource_limit');
    }
  }

  private parseObject(depth: number): JsonObject {
    const start = this.offset;
    this.expect(OPEN_BRACE);
    const members = new Map<string, JsonValue>();

    this.skipWhitespace();
    if (this.peek() === CLOSE_BRACE) {
      this.offset += 1;
      return { kind: 'object', members, span: { start, end: this.offset } };
    }

    for (;;) {
      this.skipWhitespace();
      if (this.peek() !== QUOTE) {
        this.fail('malformed');
      }
      const name = this.parseString();

      // Names are compared after escape decoding, so a literal
      // `"alg"` and an escaped `"\u0061lg"` collide. Detection has to happen
      // here, during parsing, because no later pass can observe a name that
      // has already been collapsed into a single member.
      if (members.has(name)) {
        this.fail('duplicate_member');
      }
      if (members.size + 1 > this.budget.jsonObjectMembers) {
        this.fail('resource_limit');
      }

      this.skipWhitespace();
      this.expect(COLON);
      this.skipWhitespace();
      members.set(name, this.parseValue(depth + 1));

      this.skipWhitespace();
      const byte = this.peek();
      if (byte === COMMA) {
        this.offset += 1;
        this.skipWhitespace();
        if (this.peek() === CLOSE_BRACE) {
          this.fail('malformed');
        }
        continue;
      }
      if (byte === CLOSE_BRACE) {
        this.offset += 1;
        return { kind: 'object', members, span: { start, end: this.offset } };
      }
      this.fail('malformed');
    }
  }

  private parseArray(depth: number): JsonArray {
    const start = this.offset;
    this.expect(OPEN_BRACKET);
    const elements: JsonValue[] = [];

    this.skipWhitespace();
    if (this.peek() === CLOSE_BRACKET) {
      this.offset += 1;
      return { kind: 'array', elements, span: { start, end: this.offset } };
    }

    for (;;) {
      this.skipWhitespace();
      if (elements.length + 1 > this.budget.jsonArrayElements) {
        this.fail('resource_limit');
      }
      elements.push(this.parseValue(depth + 1));

      this.skipWhitespace();
      const byte = this.peek();
      if (byte === COMMA) {
        this.offset += 1;
        this.skipWhitespace();
        if (this.peek() === CLOSE_BRACKET) {
          this.fail('malformed');
        }
        continue;
      }
      if (byte === CLOSE_BRACKET) {
        this.offset += 1;
        return { kind: 'array', elements, span: { start, end: this.offset } };
      }
      this.fail('malformed');
    }
  }

  private parseString(): string {
    this.expect(QUOTE);
    const contentStart = this.offset;

    // Fast path: scan for a closing quote with no escape. Most JOSE strings are
    // short, unescaped, and ASCII, so this avoids per-character assembly.
    let index = this.offset;
    while (index < this.source.length) {
      const byte = this.source[index]!;
      if (byte === QUOTE) {
        const slice = this.source.subarray(contentStart, index);
        if (slice.length > this.budget.jsonString) {
          this.fail('resource_limit');
        }
        this.offset = index + 1;
        return this.decodeSlice(slice);
      }
      if (byte === BACKSLASH) {
        break;
      }
      if (byte < SPACE) {
        this.fail('malformed');
      }
      index += 1;
    }

    if (index >= this.source.length) {
      this.fail('malformed');
    }
    return this.parseEscapedString(contentStart, index);
  }

  /**
   * Slow path for strings containing at least one escape sequence. `literalFrom`
   * is the offset of the first backslash; bytes before it are already known to
   * be escape-free.
   */
  private parseEscapedString(contentStart: number, literalFrom: number): string {
    let result = this.decodeSlice(this.source.subarray(contentStart, literalFrom));
    let literalStart = literalFrom;
    this.offset = literalFrom;

    for (;;) {
      if (this.offset >= this.source.length) {
        this.fail('malformed');
      }
      const byte = this.source[this.offset]!;

      if (byte === QUOTE) {
        result += this.decodeSlice(this.source.subarray(literalStart, this.offset));
        this.offset += 1;
        // Measured as decoded UTF-8 octets, matching the unescaped path. Using
        // the UTF-16 length here would let an escaped and a literal spelling of
        // the same decoded string consume different budgets.
        if (utf8Length(result) > this.budget.jsonString) {
          this.fail('resource_limit');
        }
        return result;
      }

      if (byte === BACKSLASH) {
        result += this.decodeSlice(this.source.subarray(literalStart, this.offset));
        this.offset += 1;
        result += this.parseEscape();
        literalStart = this.offset;
        // Bound the assembled value during construction so a long escape run
        // cannot build an oversized string before any check applies.
        if (result.length > this.budget.jsonString) {
          this.fail('resource_limit');
        }
        continue;
      }

      if (byte < SPACE) {
        this.fail('malformed');
      }
      this.offset += 1;
    }
  }

  private parseEscape(): string {
    if (this.offset >= this.source.length) {
      this.fail('malformed');
    }
    const byte = this.source[this.offset]!;
    this.offset += 1;

    switch (byte) {
      case QUOTE:
        return '"';
      case BACKSLASH:
        return '\\';
      case SOLIDUS:
        return '/';
      case 0x62:
        return '\b';
      case 0x66:
        return '\f';
      case 0x6e:
        return '\n';
      case 0x72:
        return '\r';
      case 0x74:
        return '\t';
      case 0x75:
        return this.parseUnicodeEscape();
      default:
        this.fail('malformed');
    }
  }

  private parseUnicodeEscape(): string {
    const first = this.readHex4();

    if (first >= 0xd800 && first <= 0xdbff) {
      // A high surrogate must be followed by an escaped low surrogate. A lone
      // surrogate escape has no valid UTF-8 encoding, so it is rejected rather
      // than silently replaced, which would change the decoded value.
      if (
        this.offset + 1 >= this.source.length ||
        this.source[this.offset] !== BACKSLASH ||
        this.source[this.offset + 1] !== 0x75
      ) {
        this.fail('invalid_encoding');
      }
      this.offset += 2;
      const second = this.readHex4();
      if (second < 0xdc00 || second > 0xdfff) {
        this.fail('invalid_encoding');
      }
      return String.fromCharCode(first, second);
    }

    if (first >= 0xdc00 && first <= 0xdfff) {
      this.fail('invalid_encoding');
    }

    return String.fromCharCode(first);
  }

  private readHex4(): number {
    if (this.offset + 4 > this.source.length) {
      this.fail('malformed');
    }
    let value = 0;

    for (let i = 0; i < 4; i += 1) {
      const byte = this.source[this.offset + i]!;
      let digit: number;
      if (byte >= DIGIT_ZERO && byte <= DIGIT_NINE) {
        digit = byte - DIGIT_ZERO;
      } else if (byte >= 0x61 && byte <= 0x66) {
        digit = byte - 0x61 + 10;
      } else if (byte >= 0x41 && byte <= 0x46) {
        digit = byte - 0x41 + 10;
      } else {
        this.fail('malformed');
      }
      value = value * 16 + digit;
    }

    this.offset += 4;
    return value;
  }

  private decodeSlice(slice: Uint8Array): string {
    try {
      return this.decoder.decode(slice);
    } catch {
      return this.fail('invalid_encoding');
    }
  }

  private parseLiteralOrNumber(): JsonValue {
    const start = this.offset;
    const byte = this.peek();

    if (byte === 0x74) {
      this.expectLiteral('true');
      return { kind: 'boolean', value: true, span: { start, end: this.offset } };
    }
    if (byte === 0x66) {
      this.expectLiteral('false');
      return { kind: 'boolean', value: false, span: { start, end: this.offset } };
    }
    if (byte === 0x6e) {
      this.expectLiteral('null');
      return { kind: 'null', span: { start, end: this.offset } };
    }

    return this.parseNumber();
  }

  private expectLiteral(literal: string): void {
    for (let i = 0; i < literal.length; i += 1) {
      if (this.source[this.offset + i] !== literal.charCodeAt(i)) {
        this.fail('malformed');
      }
    }
    this.offset += literal.length;
  }

  /**
   * Parses a JSON number and keeps its exact lexeme. `NaN`, `Infinity`, a
   * leading `+`, leading zeros, and a bare `.` are not valid JSON; the grammar
   * below admits none of them.
   */
  private parseNumber(): JsonValue {
    const start = this.offset;

    if (this.peek() === MINUS) {
      this.offset += 1;
    }

    // Integer part: a single zero, or a nonzero digit followed by digits.
    if (this.offset >= this.source.length) {
      this.fail('malformed');
    }
    const first = this.source[this.offset]!;
    if (first === DIGIT_ZERO) {
      this.offset += 1;
    } else if (isDigit(first)) {
      while (this.offset < this.source.length && isDigit(this.source[this.offset]!)) {
        this.offset += 1;
      }
    } else {
      this.fail('malformed');
    }

    if (this.offset < this.source.length && this.source[this.offset] === PERIOD) {
      this.offset += 1;
      if (this.offset >= this.source.length || !isDigit(this.source[this.offset]!)) {
        this.fail('malformed');
      }
      while (this.offset < this.source.length && isDigit(this.source[this.offset]!)) {
        this.offset += 1;
      }
    }

    let exponentStart = -1;
    if (this.offset < this.source.length && (this.source[this.offset] === 0x65 || this.source[this.offset] === 0x45)) {
      this.offset += 1;
      if (
        this.offset < this.source.length &&
        (this.source[this.offset] === PLUS || this.source[this.offset] === MINUS)
      ) {
        this.offset += 1;
      }
      exponentStart = this.offset;
      if (this.offset >= this.source.length || !isDigit(this.source[this.offset]!)) {
        this.fail('malformed');
      }
      while (this.offset < this.source.length && isDigit(this.source[this.offset]!)) {
        this.offset += 1;
      }
    }

    const lexemeBytes = this.source.subarray(start, this.offset);
    if (lexemeBytes.length > this.budget.numberLexeme) {
      this.fail('resource_limit');
    }

    if (exponentStart >= 0) {
      // The exponent magnitude is bounded regardless of whether the value
      // would underflow or overflow this runtime, so that acceptance does not
      // depend on the host's floating-point range.
      const digits = this.decodeSlice(this.source.subarray(exponentStart, this.offset));
      const magnitude = Number(digits);
      if (!Number.isFinite(magnitude) || magnitude > this.budget.numberExponentMagnitude) {
        this.fail('resource_limit');
      }
    }

    return {
      kind: 'number',
      lexeme: this.decodeSlice(lexemeBytes),
      span: { start, end: this.offset },
    };
  }
}

/**
 * Parses `source` as a complete JSON document under `budget`.
 *
 * The caller enforces the container's own size limit before calling; this
 * function enforces the structural budgets. It performs no network, filesystem,
 * or database access, so parsing an untrusted document can never trigger a
 * lookup derived from its contents.
 */
export function parseJson(source: Uint8Array, budget: JsonBudget): JsonParseResult {
  // A byte-order mark is rejected rather than skipped, so that two
  // documents differing only by a BOM cannot decode to the same value. It is
  // checked here rather than in the scanner so the root-value scan cannot
  // mistake it for whitespace.
  if (source.length >= 3 && source[0] === 0xef && source[1] === 0xbb && source[2] === 0xbf) {
    return { ok: false, failure: 'invalid_encoding' };
  }

  try {
    const { value, nodes } = new JsonParser(source, budget).parse();
    return { ok: true, value, nodes };
  } catch (error) {
    if (error instanceof ParseFailure) {
      return { ok: false, failure: error.failure };
    }
    throw error;
  }
}
