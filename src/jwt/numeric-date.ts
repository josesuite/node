import type { JsonValue } from '../internal/json/types.ts';

const MAX = 9_007_199_254_740_991n;
const LEXEME = /^(?:0|[1-9][0-9]*)$/;

export function numericDate(value: JsonValue | undefined): bigint | undefined {
  if (value?.kind !== 'number' || !LEXEME.test(value.lexeme)) {
    return undefined;
  }
  const parsed = BigInt(value.lexeme);
  return parsed <= MAX ? parsed : undefined;
}
