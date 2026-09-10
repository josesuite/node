import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

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
    assert.strictEqual(text([0x7b, 0x7d]), '{}');
    assert.strictEqual(text([0xc3, 0xa9]), 'é');
    assert.strictEqual(text([0xe2, 0x82, 0xac]), '€');
    assert.strictEqual(text([0xf0, 0x9f, 0x94, 0x90]), '\u{1f510}');
  });

  test('rejects a leading byte-order mark rather than stripping it', () => {
    assert.strictEqual(failure([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), 'byte_order_mark');
  });

  test('permits U+FEFF that is not in leading position', () => {
    assert.strictEqual(text([0x7b, 0xef, 0xbb, 0xbf, 0x7d]), '{﻿}');
  });

  test('rejects overlong encodings', () => {
    // Overlong two-byte encoding of U+002F, the classic path-traversal evasion.
    assert.strictEqual(failure([0xc0, 0xaf]), 'malformed');
    // Overlong three-byte encoding of U+002F.
    assert.strictEqual(failure([0xe0, 0x80, 0xaf]), 'malformed');
    // Overlong encoding of NUL.
    assert.strictEqual(failure([0xc0, 0x80]), 'malformed');
  });

  test('rejects surrogate code points encoded as UTF-8', () => {
    // CESU-8 style encoding of the lone surrogate U+D800.
    assert.strictEqual(failure([0xed, 0xa0, 0x80]), 'malformed');
  });

  test('rejects truncated and stray continuation bytes', () => {
    assert.strictEqual(failure([0xe2, 0x82]), 'malformed');
    assert.strictEqual(failure([0x80]), 'malformed');
    assert.strictEqual(failure([0xf5, 0x80, 0x80, 0x80]), 'malformed');
  });

  test('empty input decodes to the empty string', () => {
    assert.strictEqual(text([]), '');
  });
});

describe('utf8Length', () => {
  test('matches the encoder across scalar-value classes', () => {
    const samples = ['', 'abc', 'é', '€', '\u{1f510}', '{"iss":"https://example.test"}', 'a\u{1f510}é€z', '﻿'];

    for (const sample of samples) {
      assert.strictEqual(utf8Length(sample), encodeUtf8(sample).length);
    }
  });

  test('counts an unpaired surrogate as the replacement-length three octets', () => {
    // A lone surrogate cannot be encoded; TextEncoder substitutes U+FFFD, which
    // is three octets, so the accounting stays consistent with the encoder.
    assert.strictEqual(utf8Length('\ud800'), encodeUtf8('\ud800').length);
    assert.strictEqual(utf8Length('a\udc00b'), encodeUtf8('a\udc00b').length);
  });

  test('matches UTF-8 encoding for every UTF-16 code unit and surrogate boundary', () => {
    for (let code = 0; code <= 0xffff; code += 1) {
      const sample = String.fromCharCode(code);
      assert.strictEqual(utf8Length(sample), encodeUtf8(sample).length);
    }
    for (const sample of ['\ud800\udc00', '\udbff\udfff', '\ud800\ud800', '\udc00\ud800', 'x'.repeat(8192) + 'é😀']) {
      assert.strictEqual(utf8Length(sample), encodeUtf8(sample).length);
    }
  });
});

describe('encodeAscii', () => {
  test('preserves exact bytes and rejects non-ASCII around the native-path boundary', () => {
    for (const length of [255, 256, 257, 8192]) {
      const input = 'a'.repeat(length);
      const result = encodeAscii(input);
      assert.deepStrictEqual(result, { ok: true, bytes: encodeUtf8(input) });
      for (const position of [0, Math.floor(length / 2), length - 1]) {
        for (const character of ['\u0080', 'é', '\ud800', '\udc00', '😀', '\ufeff']) {
          assert.deepStrictEqual(encodeAscii(input.slice(0, position) + character + input.slice(position + 1)), {
            ok: false,
            failure: 'non_ascii',
          });
        }
      }
    }
    const controls = String.fromCharCode(...Array.from({ length: 128 }, (_, code) => code)).repeat(4);
    assert.deepStrictEqual(encodeAscii(controls), { ok: true, bytes: encodeUtf8(controls) });
  });

  test('encodes ASCII to its octets', () => {
    const result = encodeAscii('eyJ0eXAiOiJKV1QifQ.QUJD');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.bytes), 'eyJ0eXAiOiJKV1QifQ.QUJD');
    }
  });

  test('rejects non-ASCII instead of transcoding it', () => {
    const result = encodeAscii('é');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'non_ascii');
    }
    assert.strictEqual(isAscii('é'), false);
    assert.strictEqual(isAscii('~'), true);
  });

  test('accepts the full ASCII range including control characters', () => {
    for (let code = 0; code < 128; code += 1) {
      assert.strictEqual(encodeAscii(String.fromCharCode(code)).ok, true);
    }
    assert.strictEqual(encodeAscii(String.fromCharCode(128)).ok, false);
  });
});
