import { describe, expect, test } from 'bun:test';

import { decodeUtf8, encodeUtf8, utf8Length } from '../../../src/internal/encoding/utf8.ts';
import { encodeAscii, isAscii } from '../../../src/internal/encoding/ascii.ts';

function failure(bytes: number[]): string {
  const result = decodeUtf8(new Uint8Array(bytes));
  if (result.ok) {
    throw new Error(`expected failure, decoded ${JSON.stringify(result.text)}`);
  }
  return result.failure;
}

function text(bytes: number[]): string {
  const result = decodeUtf8(new Uint8Array(bytes));
  if (!result.ok) {
    throw new Error(`expected success, got ${result.failure}`);
  }
  return result.text;
}

describe('decodeUtf8', () => {
  test('decodes ASCII and multi-byte scalar values', () => {
    expect(text([0x7b, 0x7d])).toBe('{}');
    expect(text([0xc3, 0xa9])).toBe('é');
    expect(text([0xe2, 0x82, 0xac])).toBe('€');
    expect(text([0xf0, 0x9f, 0x94, 0x90])).toBe('\u{1f510}');
  });

  test('rejects a leading byte-order mark rather than stripping it', () => {
    expect(failure([0xef, 0xbb, 0xbf, 0x7b, 0x7d])).toBe('byte_order_mark');
  });

  test('permits U+FEFF that is not in leading position', () => {
    expect(text([0x7b, 0xef, 0xbb, 0xbf, 0x7d])).toBe('{﻿}');
  });

  test('rejects overlong encodings', () => {
    // Overlong two-byte encoding of U+002F, the classic path-traversal evasion.
    expect(failure([0xc0, 0xaf])).toBe('malformed');
    // Overlong three-byte encoding of U+002F.
    expect(failure([0xe0, 0x80, 0xaf])).toBe('malformed');
    // Overlong encoding of NUL.
    expect(failure([0xc0, 0x80])).toBe('malformed');
  });

  test('rejects surrogate code points encoded as UTF-8', () => {
    // CESU-8 style encoding of the lone surrogate U+D800.
    expect(failure([0xed, 0xa0, 0x80])).toBe('malformed');
  });

  test('rejects truncated and stray continuation bytes', () => {
    expect(failure([0xe2, 0x82])).toBe('malformed');
    expect(failure([0x80])).toBe('malformed');
    expect(failure([0xf5, 0x80, 0x80, 0x80])).toBe('malformed');
  });

  test('empty input decodes to the empty string', () => {
    expect(text([])).toBe('');
  });
});

describe('utf8Length', () => {
  test('matches the encoder across scalar-value classes', () => {
    const samples = ['', 'abc', 'é', '€', '\u{1f510}', '{"iss":"https://example.test"}', 'a\u{1f510}é€z', '﻿'];

    for (const sample of samples) {
      expect(utf8Length(sample)).toBe(encodeUtf8(sample).length);
    }
  });

  test('counts an unpaired surrogate as the replacement-length three octets', () => {
    // A lone surrogate cannot be encoded; TextEncoder substitutes U+FFFD, which
    // is three octets, so the accounting stays consistent with the encoder.
    expect(utf8Length('\ud800')).toBe(encodeUtf8('\ud800').length);
    expect(utf8Length('a\udc00b')).toBe(encodeUtf8('a\udc00b').length);
  });
});

describe('encodeAscii', () => {
  test('encodes ASCII to its octets', () => {
    const result = encodeAscii('eyJ0eXAiOiJKV1QifQ.QUJD');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(new TextDecoder().decode(result.bytes)).toBe('eyJ0eXAiOiJKV1QifQ.QUJD');
    }
  });

  test('rejects non-ASCII instead of transcoding it', () => {
    const result = encodeAscii('é');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('non_ascii');
    }
    expect(isAscii('é')).toBe(false);
    expect(isAscii('~')).toBe(true);
  });

  test('accepts the full ASCII range including control characters', () => {
    for (let code = 0; code < 128; code += 1) {
      expect(encodeAscii(String.fromCharCode(code)).ok).toBe(true);
    }
    expect(encodeAscii(String.fromCharCode(128)).ok).toBe(false);
  });
});
