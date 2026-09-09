import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { encodedLengthFor } from '../../../src/internal/encoding/base64url.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonValue } from '../../../src/internal/json/types.ts';
import { parseCompactJwe, parseJsonJwe } from '../../../src/jwe/parse.ts';
import { buildAdditionalData } from '../../../src/jwe/types.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';

function json(text: string): JsonValue {
  const result = parseJson(new TextEncoder().encode(text), LIMITS_V1);
  if (!result.ok) {
    throw new Error(`bad fixture: ${result.failure}`);
  }
  return result.value;
}

function parse(text: string) {
  return parseJsonJwe(json(text), LIMITS_V1);
}

/** A JWE whose protected component is a filler string of a chosen length. */
function withProtected(length: number): string {
  return `{"protected":"${'A'.repeat(length)}","iv":"aXY","ciphertext":"Y3Q","tag":"dGFn"}`;
}

const HEADER = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0';
const BASE = `"protected":"${HEADER}","iv":"aXYtdmFsdWU","ciphertext":"Y3Q","tag":"dGFn"`;

describe('compact form', () => {
  test('reads exactly five components', () => {
    const result = parseCompactJwe(`${HEADER}.ZWs.aXY.Y3Q.dGFn`, LIMITS_V1);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value.form, 'compact');
      assert.strictEqual(result.value.protectedComponent, HEADER);
      assert.strictEqual(result.value.recipients.length, 1);
      assert.strictEqual(result.value.recipients[0]!.encryptedKeyComponent, 'ZWs');
      assert.strictEqual(result.value.aadComponent, undefined);
    }
  });

  test('rejects any count other than five', () => {
    for (const token of [`${HEADER}.ZWs.aXY.Y3Q`, `${HEADER}.ZWs.aXY.Y3Q.dGFn.ZXh0cmE`, `${HEADER}.ZWs.aXY`, HEADER]) {
      const result = parseCompactJwe(token, LIMITS_V1);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'compact_component_count');
      }
    }
  });

  test('treats an empty encrypted key as absent', () => {
    // Direct modes carry no encrypted key; Compact spells that as an empty
    // component and JSON spells it as an omitted member.
    const result = parseCompactJwe(`${HEADER}..aXY.Y3Q.dGFn`, LIMITS_V1);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value.recipients[0]!.encryptedKeyComponent, undefined);
    }
  });

  test('accepts an empty ciphertext', () => {
    // An empty plaintext under GCM produces no ciphertext octets.
    const result = parseCompactJwe(`${HEADER}.ZWs.aXY..dGFn`, LIMITS_V1);
    assert.strictEqual(result.ok, true);
  });

  test('requires nonempty protected, iv and tag', () => {
    assert.strictEqual(parseCompactJwe(`.ZWs.aXY.Y3Q.dGFn`, LIMITS_V1).ok, false);
    assert.strictEqual(parseCompactJwe(`${HEADER}.ZWs..Y3Q.dGFn`, LIMITS_V1).ok, false);
    assert.strictEqual(parseCompactJwe(`${HEADER}.ZWs.aXY.Y3Q.`, LIMITS_V1).ok, false);
  });
});

describe('JSON form selection', () => {
  test('reads the general form from a recipients array', () => {
    const result = parse(`{${BASE},"recipients":[{"encrypted_key":"ZWs"}]}`);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value.form, 'general');
      assert.strictEqual(result.value.recipients.length, 1);
    }
  });

  test('reads the flattened form when recipients is absent', () => {
    const result = parse(`{${BASE},"encrypted_key":"ZWs"}`);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value.form, 'flattened');
      assert.strictEqual(result.value.recipients[0]!.encryptedKeyComponent, 'ZWs');
    }
  });

  test('rejects a hybrid carrying both forms', () => {
    for (const member of ['"encrypted_key":"ZWs"', '"header":{"kid":"a"}']) {
      const result = parse(`{${BASE},${member},"recipients":[{"encrypted_key":"b3Ro"}]}`);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'hybrid_serialization');
        assert.strictEqual(result.category, 'invalid_header');
      }
    }
  });

  test('rejects an empty recipients array rather than reading it as flattened', () => {
    // A present-but-empty array is a rejected General JWE, never an implicit
    // Flattened one; zero recipients can never yield a decryptable object.
    const result = parse(`{${BASE},"recipients":[]}`);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'recipients_empty');
    }
  });

  test('bounds the number of recipients', () => {
    const many = Array.from({ length: LIMITS_V1.recipients + 1 }, () => '{"encrypted_key":"ZWs"}').join(',');
    const result = parse(`{${BASE},"recipients":[${many}]}`);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }
  });
});

describe('required members', () => {
  test('requires protected, iv, ciphertext and tag', () => {
    const members: Record<string, string> = {
      protected: `"${HEADER}"`,
      iv: '"aXY"',
      ciphertext: '"Y3Q"',
      tag: '"dGFn"',
    };

    for (const omitted of Object.keys(members)) {
      const body = Object.entries(members)
        .filter(([name]) => name !== omitted)
        .map(([name, value]) => `"${name}":${value}`)
        .join(',');

      const result = parse(`{${body}}`);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, `${omitted}_missing`);
      }
    }
  });

  test('keeps ciphertext present but allows it to be empty', () => {
    const result = parse(`{"protected":"${HEADER}","iv":"aXY","ciphertext":"","tag":"dGFn"}`);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value.ciphertextComponent, '');
    }
  });

  test('rejects wrong member types', () => {
    const cases: readonly [string, string][] = [
      [`{"protected":{"a":1},"iv":"aXY","ciphertext":"Y3Q","tag":"dGFn"}`, 'protected_not_a_string'],
      [`{"protected":"${HEADER}","iv":42,"ciphertext":"Y3Q","tag":"dGFn"}`, 'iv_not_a_string'],
      [`{${BASE},"recipients":{"a":1}}`, 'recipients_not_an_array'],
      [`{${BASE},"recipients":["nope"]}`, 'recipient_not_an_object'],
    ];

    for (const [text, reason] of cases) {
      const result = parse(text);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, reason);
      }
    }
  });

  test('rejects a top-level value that is not an object', () => {
    for (const text of ['[]', '"s"', '42', 'null']) {
      const result = parse(text);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'jwe_not_an_object');
      }
    }
  });
});

describe('empty optional values must be omitted', () => {
  test('rejects an explicit empty aad', () => {
    // An absent `aad` and a present one build different authenticated data, so
    // an empty member is malformed rather than an alias for absence.
    const result = parse(`{${BASE},"aad":"","encrypted_key":"ZWs"}`);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'aad_empty');
    }
  });

  test('rejects an explicit empty encrypted_key', () => {
    const result = parse(`{${BASE},"encrypted_key":""}`);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'encrypted_key_empty');
    }
  });

  test('rejects an empty unprotected or recipient header', () => {
    assert.strictEqual(parse(`{${BASE},"unprotected":{},"encrypted_key":"ZWs"}`).ok, false);
    assert.strictEqual(parse(`{${BASE},"recipients":[{"header":{},"encrypted_key":"ZWs"}]}`).ok, false);
  });

  test('accepts the same object with those members omitted', () => {
    assert.strictEqual(parse(`{${BASE},"encrypted_key":"ZWs"}`).ok, true);
  });
});

describe('ignorable members', () => {
  test('keeps an unknown noncritical member from changing the parse', () => {
    const result = parse(`{${BASE},"encrypted_key":"ZWs","x-vendor":"anything"}`);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.value.form, 'flattened');
    }
  });
});

describe('authenticated data construction', () => {
  test('uses the protected component alone when aad is absent', () => {
    const result = buildAdditionalData(HEADER, undefined);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.bytes), HEADER);
    }
  });

  test('joins the protected component and aad with a period', () => {
    const result = buildAdditionalData(HEADER, 'YWFk');

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.bytes), `${HEADER}.YWFk`);
    }
  });

  test('separates the two components unambiguously', () => {
    // Without the separator these would produce identical authenticated data,
    // letting an attacker move characters across the boundary undetected.
    const a = buildAdditionalData('AB', 'CD');
    const b = buildAdditionalData('ABC', 'D');

    assert.strictEqual(a.ok && b.ok, true);
    if (a.ok && b.ok) {
      assert.notDeepStrictEqual(a.bytes, b.bytes);
    }
  });

  test('distinguishes absent aad from present aad', () => {
    const absent = buildAdditionalData(HEADER, undefined);
    const present = buildAdditionalData(HEADER, 'YWFk');

    assert.strictEqual(absent.ok && present.ok, true);
    if (absent.ok && present.ok) {
      assert.notDeepStrictEqual(absent.bytes, present.bytes);
    }
  });

  test('rejects a component holding non-ASCII', () => {
    const result = buildAdditionalData('héader', undefined);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'non_ascii_component');
    }
  });
});

describe('component size bounds', () => {
  /**
   * `headerSource` bounds the decoded header. The encoded component is a
   * separate quantity, so parsing applies the encoded equivalent and the
   * decoded bound is applied where the component is actually decoded.
   */
  test('bounds the protected component by the encoded equivalent of its limit', () => {
    const limits = lowerLimits({ headerSource: 64 });

    // A component that could not decode to more than the limit is a size the
    // parser has no reason to refuse.
    assert.strictEqual(parseJsonJwe(json(withProtected(encodedLengthFor(limits.headerSource))), limits).ok, true);

    const oversized = parseJsonJwe(json(withProtected(encodedLengthFor(limits.headerSource) + 1)), limits);
    assert.strictEqual(oversized.ok, false);
    if (!oversized.ok) {
      assert.strictEqual(oversized.category, 'resource_limit');
      assert.strictEqual(oversized.reason, 'protected_too_large');
    }
  });

  test('rejects a non-canonical aad component', () => {
    // The component enters the authenticated data verbatim, so it is never
    // replaced by its decoded value; it must still be well formed.
    const result = parse(`{${BASE},"aad":"!"}`);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_encoding');
      assert.strictEqual(result.reason, 'aad_invalid_base64url');
    }
  });
});
