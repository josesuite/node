import { describe, expect, test } from 'bun:test';

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

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('compact');
      expect(result.value.protectedComponent).toBe(HEADER);
      expect(result.value.recipients).toHaveLength(1);
      expect(result.value.recipients[0]!.encryptedKeyComponent).toBe('ZWs');
      expect(result.value.aadComponent).toBeUndefined();
    }
  });

  test('rejects any count other than five', () => {
    for (const token of [`${HEADER}.ZWs.aXY.Y3Q`, `${HEADER}.ZWs.aXY.Y3Q.dGFn.ZXh0cmE`, `${HEADER}.ZWs.aXY`, HEADER]) {
      const result = parseCompactJwe(token, LIMITS_V1);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('compact_component_count');
      }
    }
  });

  test('treats an empty encrypted key as absent', () => {
    // Direct modes carry no encrypted key; Compact spells that as an empty
    // component and JSON spells it as an omitted member.
    const result = parseCompactJwe(`${HEADER}..aXY.Y3Q.dGFn`, LIMITS_V1);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.recipients[0]!.encryptedKeyComponent).toBeUndefined();
    }
  });

  test('accepts an empty ciphertext', () => {
    // An empty plaintext under GCM produces no ciphertext octets.
    const result = parseCompactJwe(`${HEADER}.ZWs.aXY..dGFn`, LIMITS_V1);
    expect(result.ok).toBe(true);
  });

  test('requires nonempty protected, iv and tag', () => {
    expect(parseCompactJwe(`.ZWs.aXY.Y3Q.dGFn`, LIMITS_V1).ok).toBe(false);
    expect(parseCompactJwe(`${HEADER}.ZWs..Y3Q.dGFn`, LIMITS_V1).ok).toBe(false);
    expect(parseCompactJwe(`${HEADER}.ZWs.aXY.Y3Q.`, LIMITS_V1).ok).toBe(false);
  });
});

describe('JSON form selection', () => {
  test('reads the general form from a recipients array', () => {
    const result = parse(`{${BASE},"recipients":[{"encrypted_key":"ZWs"}]}`);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('general');
      expect(result.value.recipients).toHaveLength(1);
    }
  });

  test('reads the flattened form when recipients is absent', () => {
    const result = parse(`{${BASE},"encrypted_key":"ZWs"}`);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('flattened');
      expect(result.value.recipients[0]!.encryptedKeyComponent).toBe('ZWs');
    }
  });

  test('rejects a hybrid carrying both forms', () => {
    for (const member of ['"encrypted_key":"ZWs"', '"header":{"kid":"a"}']) {
      const result = parse(`{${BASE},${member},"recipients":[{"encrypted_key":"b3Ro"}]}`);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('hybrid_serialization');
        expect(result.category).toBe('invalid_header');
      }
    }
  });

  test('rejects an empty recipients array rather than reading it as flattened', () => {
    // A present-but-empty array is a rejected General JWE, never an implicit
    // Flattened one; zero recipients can never yield a decryptable object.
    const result = parse(`{${BASE},"recipients":[]}`);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('recipients_empty');
    }
  });

  test('bounds the number of recipients', () => {
    const many = Array.from({ length: LIMITS_V1.recipients + 1 }, () => '{"encrypted_key":"ZWs"}').join(',');
    const result = parse(`{${BASE},"recipients":[${many}]}`);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
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
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(`${omitted}_missing`);
      }
    }
  });

  test('keeps ciphertext present but allows it to be empty', () => {
    const result = parse(`{"protected":"${HEADER}","iv":"aXY","ciphertext":"","tag":"dGFn"}`);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.ciphertextComponent).toBe('');
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
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(reason);
      }
    }
  });

  test('rejects a top-level value that is not an object', () => {
    for (const text of ['[]', '"s"', '42', 'null']) {
      const result = parse(text);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('jwe_not_an_object');
      }
    }
  });
});

describe('empty optional values must be omitted', () => {
  test('rejects an explicit empty aad', () => {
    // An absent `aad` and a present one build different authenticated data, so
    // an empty member is malformed rather than an alias for absence.
    const result = parse(`{${BASE},"aad":"","encrypted_key":"ZWs"}`);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('aad_empty');
    }
  });

  test('rejects an explicit empty encrypted_key', () => {
    const result = parse(`{${BASE},"encrypted_key":""}`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('encrypted_key_empty');
    }
  });

  test('rejects an empty unprotected or recipient header', () => {
    expect(parse(`{${BASE},"unprotected":{},"encrypted_key":"ZWs"}`).ok).toBe(false);
    expect(parse(`{${BASE},"recipients":[{"header":{},"encrypted_key":"ZWs"}]}`).ok).toBe(false);
  });

  test('accepts the same object with those members omitted', () => {
    expect(parse(`{${BASE},"encrypted_key":"ZWs"}`).ok).toBe(true);
  });
});

describe('ignorable members', () => {
  test('keeps an unknown noncritical member from changing the parse', () => {
    const result = parse(`{${BASE},"encrypted_key":"ZWs","x-vendor":"anything"}`);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.form).toBe('flattened');
    }
  });
});

describe('authenticated data construction', () => {
  test('uses the protected component alone when aad is absent', () => {
    const result = buildAdditionalData(HEADER, undefined);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(new TextDecoder().decode(result.bytes)).toBe(HEADER);
    }
  });

  test('joins the protected component and aad with a period', () => {
    const result = buildAdditionalData(HEADER, 'YWFk');

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(new TextDecoder().decode(result.bytes)).toBe(`${HEADER}.YWFk`);
    }
  });

  test('separates the two components unambiguously', () => {
    // Without the separator these would produce identical authenticated data,
    // letting an attacker move characters across the boundary undetected.
    const a = buildAdditionalData('AB', 'CD');
    const b = buildAdditionalData('ABC', 'D');

    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(a.bytes).not.toEqual(b.bytes);
    }
  });

  test('distinguishes absent aad from present aad', () => {
    const absent = buildAdditionalData(HEADER, undefined);
    const present = buildAdditionalData(HEADER, 'YWFk');

    expect(absent.ok && present.ok).toBe(true);
    if (absent.ok && present.ok) {
      expect(absent.bytes).not.toEqual(present.bytes);
    }
  });

  test('rejects a component holding non-ASCII', () => {
    const result = buildAdditionalData('héader', undefined);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('non_ascii_component');
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
    expect(parseJsonJwe(json(withProtected(encodedLengthFor(limits.headerSource))), limits).ok).toBe(true);

    const oversized = parseJsonJwe(json(withProtected(encodedLengthFor(limits.headerSource) + 1)), limits);
    expect(oversized.ok).toBe(false);
    if (!oversized.ok) {
      expect(oversized.category).toBe('resource_limit');
      expect(oversized.reason).toBe('protected_too_large');
    }
  });

  test('rejects a non-canonical aad component', () => {
    // The component enters the authenticated data verbatim, so it is never
    // replaced by its decoded value; it must still be well formed.
    const result = parse(`{${BASE},"aad":"!"}`);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_encoding');
      expect(result.reason).toBe('aad_invalid_base64url');
    }
  });
});
