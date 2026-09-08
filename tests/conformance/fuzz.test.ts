import { describe, expect, test } from 'bun:test';

import { decodeBase64url, encodeBase64url } from '../../src/internal/encoding/base64url.ts';
import { parseJson } from '../../src/internal/json/parse.ts';
import { isJsonObject } from '../../src/internal/json/types.ts';
import { parseJsonJwe } from '../../src/jwe/parse.ts';
import { importKey } from '../../src/key/import.ts';
import { parseJsonJws } from '../../src/jws/parse.ts';
import { LIMITS_V1 } from '../../src/policy/limits.ts';

const SEED = 0x6a6f7365;
const ITERATIONS = 2_000;

function generator(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

describe('bounded parser fuzz regressions', () => {
  test('arbitrary bytes never escape the JSON or Base64url result boundary', () => {
    const next = generator(SEED);
    for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
      const input = Uint8Array.from({ length: next() % 257 }, () => next() & 0xff);
      const before = input.slice();

      const json = parseJson(input, LIMITS_V1);
      if (json.ok) {
        expect(() => parseJsonJws(json.value, LIMITS_V1)).not.toThrow();
        expect(() => parseJsonJwe(json.value, LIMITS_V1)).not.toThrow();
        if (isJsonObject(json.value)) {
          expect(() => importKey(json.value, { algorithm: 'HS256', operation: 'verify' })).not.toThrow();
        }
      }
      expect(() => decodeBase64url(new TextDecoder().decode(input), LIMITS_V1.payload)).not.toThrow();
      expect(input).toEqual(before);
    }
  });

  test('mutated JWK input never escapes the parser or importer result boundary', () => {
    const next = generator(SEED ^ 0x6a776b);
    const valid = new TextEncoder().encode('{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}');

    for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
      const input = valid.slice();
      for (let mutation = 0; mutation <= next() % 3; mutation += 1) {
        input[next() % input.length] = next() & 0xff;
      }
      const before = input.slice();
      const json = parseJson(input, LIMITS_V1);

      if (json.ok && isJsonObject(json.value)) {
        expect(() => parseJsonJws(json.value, LIMITS_V1)).not.toThrow();
        expect(() => parseJsonJwe(json.value, LIMITS_V1)).not.toThrow();
        expect(() => importKey(json.value, { algorithm: 'HS256', operation: 'verify' })).not.toThrow();
      }
      expect(input).toEqual(before);
    }
  });

  test('generated octets have one canonical Base64url encoding', () => {
    const next = generator(SEED ^ 0xb64);
    for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
      const input = Uint8Array.from({ length: next() % 257 }, () => next() & 0xff);
      const encoded = encodeBase64url(input);
      const decoded = decodeBase64url(encoded, LIMITS_V1.payload);

      if (!decoded.ok) {
        throw new Error(`seed ${SEED} iteration ${iteration}: ${decoded.failure}`);
      }
      expect(decoded.bytes).toEqual(input);
      expect(encodeBase64url(decoded.bytes)).toBe(encoded);
    }
  });
});
