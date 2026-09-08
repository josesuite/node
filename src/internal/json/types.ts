/**
 * Exact JSON value model.
 *
 * Numbers are retained as their original decimal lexeme rather than converted
 * to IEEE-754. Timestamp claims must be compared with exact integer arithmetic,
 * and an unknown numeric claim has no defined use until some schema gives it
 * one, so neither should be rounded at parse time. Converting here would make
 * acceptance depend on runtime floating-point behaviour and would silently
 * alter integers beyond 2^53.
 */

export type JsonValue = JsonObject | JsonArray | JsonString | JsonNumber | JsonBoolean | JsonNull;

export interface JsonSpan {
  /** Inclusive start offset into the source octets. */
  readonly start: number;
  /** Exclusive end offset into the source octets. */
  readonly end: number;
}

export interface JsonObject {
  readonly kind: 'object';
  /**
   * Members keyed by their escape-decoded name. A `Map` is used rather than a
   * plain object so that names such as `__proto__` and `constructor` remain
   * ordinary data and cannot reach the prototype chain.
   */
  readonly members: ReadonlyMap<string, JsonValue>;
  readonly span: JsonSpan;
}

export interface JsonArray {
  readonly kind: 'array';
  readonly elements: readonly JsonValue[];
  readonly span: JsonSpan;
}

export interface JsonString {
  readonly kind: 'string';
  /**
   * Escape-decoded value. Deliberately never Unicode-normalized:
   * normalizing would make two distinct names or values compare equal, erasing
   * a difference the sender actually encoded.
   */
  readonly value: string;
  readonly span: JsonSpan;
}

export interface JsonNumber {
  readonly kind: 'number';
  /** Exact source lexeme, preserved verbatim for schema-specific validation. */
  readonly lexeme: string;
  readonly span: JsonSpan;
}

export interface JsonBoolean {
  readonly kind: 'boolean';
  readonly value: boolean;
  readonly span: JsonSpan;
}

export interface JsonNull {
  readonly kind: 'null';
  readonly span: JsonSpan;
}
