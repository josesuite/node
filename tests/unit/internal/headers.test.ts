import { describe, expect, test } from 'bun:test';

import {
  checkSuppliedParameterType,
  resolveB64,
  validateCritical,
  validateParameterTypes,
} from '../../../src/internal/headers/critical.ts';
import {
  type HeaderBudget,
  type HeaderSource,
  mergeHeaders,
  requireHeaderObject,
} from '../../../src/internal/headers/merge.ts';
import type { HeaderOrigin, MergedHeader } from '../../../src/internal/headers/types.ts';
import { headerValue, isProtected } from '../../../src/internal/headers/types.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

const BUDGET: HeaderBudget = LIMITS_V1;

function object(json: string): JsonObject {
  const result = parseJson(new TextEncoder().encode(json), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error(`bad fixture: ${json}`);
  }
  return result.value;
}

function source(json: string, origin: HeaderOrigin): HeaderSource {
  return { origin, object: object(json), sourceBytes: new TextEncoder().encode(json).length };
}

function merge(sources: readonly HeaderSource[], budget: HeaderBudget = BUDGET): MergedHeader {
  const result = mergeHeaders(sources, budget);
  if (!result.ok) {
    throw new Error(`expected merge, got ${result.reason}`);
  }
  return result.header;
}

function header(json: string, origin: HeaderOrigin = 'protected'): MergedHeader {
  return merge([source(json, origin)]);
}

describe('HDR-01 disjoint names', () => {
  test('merges disjoint protected and unprotected sources with provenance', () => {
    const merged = merge([source('{"alg":"ES256"}', 'protected'), source('{"kid":"k1"}', 'shared_unprotected')]);

    expect(merged.parameters.size).toBe(2);
    expect(isProtected(merged, 'alg')).toBe(true);
    expect(isProtected(merged, 'kid')).toBe(false);
    expect(headerValue(merged, 'kid')).toMatchObject({ kind: 'string', value: 'k1' });
  });

  test('rejects a name present in two sources even when values are equal', () => {
    const result = mergeHeaders(
      [source('{"alg":"ES256"}', 'protected'), source('{"alg":"ES256"}', 'shared_unprotected')],
      BUDGET,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_header');
      expect(result.reason).toBe('header_name_collision');
    }
  });

  test('rejects a per-entry name colliding with a shared one', () => {
    const result = mergeHeaders(
      [
        source('{"alg":"ES256"}', 'protected'),
        source('{"kid":"shared"}', 'shared_unprotected'),
        source('{"kid":"entry"}', 'per_entry_unprotected'),
      ],
      BUDGET,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_header');
    }
  });

  test('header names are case-sensitive and do not collide across cases', () => {
    const merged = merge([source('{"alg":"ES256"}', 'protected'), source('{"ALG":"x"}', 'shared_unprotected')]);
    expect(merged.parameters.size).toBe(2);
  });
});

describe('LIMIT-01 header source accounting', () => {
  test('counts source octets including internal whitespace', () => {
    const json = '{ "alg" : "ES256" }';
    expect(header(json).sourceBytes).toBe(json.length);
    // Decoded member count is 1, but the source is far larger; the two are
    // deliberately not derived from each other.
    expect(header(json).parameters.size).toBe(1);
  });

  test('rejects one oversized header source', () => {
    const budget: HeaderBudget = { ...BUDGET, headerSource: 10 };
    const result = mergeHeaders([source('{"alg":"ES256"}', 'protected')], budget);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
    }
  });

  test('rejects an oversized total across sources', () => {
    const budget: HeaderBudget = { ...BUDGET, headerSource: 20, totalHeaderSource: 20 };
    const result = mergeHeaders(
      [source('{"alg":"ES256"}', 'protected'), source('{"kid":"k1"}', 'shared_unprotected')],
      budget,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('total_header_source_too_large');
    }
  });

  test('rejects too many merged members', () => {
    const budget: HeaderBudget = { ...BUDGET, mergedHeaderMembers: 2 };
    const result = mergeHeaders([source('{"a":1,"b":2,"c":3}', 'protected')], budget);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('merged_header_too_many_members');
    }
  });
});

describe('requireHeaderObject', () => {
  test('rejects non-object header containers', () => {
    const parsed = parseJson(new TextEncoder().encode('["alg"]'), LIMITS_V1);
    if (!parsed.ok) {
      throw new Error('fixture');
    }
    const result = requireHeaderObject(parsed.value);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_header');
    }
  });
});

describe('HDR-05 recognized parameter types', () => {
  test('accepts correctly typed recognized parameters', () => {
    expect(validateParameterTypes(header('{"alg":"ES256","kid":"k","typ":"JWT"}')).ok).toBe(true);
    expect(validateParameterTypes(header('{"jwk":{},"epk":{}}')).ok).toBe(true);
    expect(validateParameterTypes(header('{"x5c":["MAA="]}')).ok).toBe(true);
    expect(validateParameterTypes(header('{"p2c":100000}')).ok).toBe(true);
  });

  test('rejects a recognized string parameter with a non-string value', () => {
    for (const json of ['{"alg":1}', '{"kid":null}', '{"typ":[]}', '{"enc":{}}', '{"cty":true}']) {
      const result = validateParameterTypes(header(json));
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe('invalid_header');
      }
    }
  });

  test('rejects wrong types for object, array, and numeric parameters', () => {
    expect(validateParameterTypes(header('{"jwk":"not-an-object"}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"epk":[]}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"x5c":"cert"}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"x5c":[]}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"x5c":[1]}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"x5c":["not base64"]}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"p2c":"100000"}')).ok).toBe(false);
  });

  test('bounds the certificate chain by the active limit', () => {
    // The chain is an ignored hint here, but it is attacker-supplied: the count
    // is enforced before the entries are decoded so an unbounded array cannot
    // impose work regardless of whether trust is evaluated from it.
    const certificate = Buffer.from(new Uint8Array(32).fill(1)).toString('base64');
    const within = JSON.stringify({ x5c: Array.from({ length: LIMITS_V1.certificateChain }, () => certificate) });
    expect(validateParameterTypes(header(within), LIMITS_V1).ok).toBe(true);

    const over = JSON.stringify({ x5c: Array.from({ length: LIMITS_V1.certificateChain + 1 }, () => certificate) });
    const result = validateParameterTypes(header(over), LIMITS_V1);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
      expect(result.reason).toBe('x5c_chain_too_long');
    }
  });

  test('bounds a supplied certificate chain at creation', () => {
    const certificate = Buffer.from(new Uint8Array(32).fill(1)).toString('base64');
    const within = Array.from({ length: LIMITS_V1.certificateChain }, () => certificate);
    expect(checkSuppliedParameterType('x5c', within, LIMITS_V1)).toBe(true);
    expect(checkSuppliedParameterType('x5c', [...within, certificate], LIMITS_V1)).toBe(false);
  });

  test('validates a recognized type even when the parameter is otherwise ignored', () => {
    // A JWE-only parameter carried noncritically in a JWS still has its type
    // validated, though it selects no JWS backend.
    expect(validateParameterTypes(header('{"alg":"ES256","enc":1}')).ok).toBe(false);
    expect(validateParameterTypes(header('{"alg":"ES256","enc":"A128GCM"}')).ok).toBe(true);
  });

  test('ignores unknown noncritical parameters', () => {
    expect(validateParameterTypes(header('{"alg":"ES256","unknown":{"any":[1,2]}}')).ok).toBe(true);
  });

  test('bounds kid length', () => {
    const long = JSON.stringify({ kid: 'k'.repeat(257) });
    const result = validateParameterTypes(header(long));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
    }

    expect(validateParameterTypes(header(JSON.stringify({ kid: 'k'.repeat(256) }))).ok).toBe(true);
  });
});

describe('HDR-04 and HDR-06 critical extensions', () => {
  test('absent crit yields no critical names', () => {
    const result = validateCritical(header('{"alg":"ES256"}'), 'jws');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.names).toEqual([]);
    }
  });

  test('accepts a well-formed crit naming an implemented extension', () => {
    const result = validateCritical(header('{"alg":"ES256","b64":false,"crit":["b64"]}'), 'jws');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.names).toEqual(['b64']);
    }
  });

  test('rejects unprotected crit', () => {
    const merged = merge([
      source('{"alg":"ES256","b64":false}', 'protected'),
      source('{"crit":["b64"]}', 'shared_unprotected'),
    ]);
    const result = validateCritical(merged, 'jws');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('crit_not_protected');
    }
  });

  test('rejects malformed crit lists', () => {
    const cases: readonly [string, string][] = [
      ['{"alg":"ES256","crit":[]}', 'crit_empty'],
      ['{"alg":"ES256","crit":"b64"}', 'crit_not_an_array'],
      ['{"alg":"ES256","crit":[1]}', 'crit_entry_not_a_string'],
      ['{"alg":"ES256","b64":false,"crit":["b64","b64"]}', 'crit_duplicate_name'],
      ['{"alg":"ES256","crit":["ext"]}', 'crit_names_absent_parameter'],
    ];

    for (const [json, reason] of cases) {
      const result = validateCritical(header(json), 'jws');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe('invalid_header');
        expect(result.reason).toBe(reason);
      }
    }
  });

  test('rejects crit naming a base JOSE/JWA parameter', () => {
    for (const name of ['alg', 'kid', 'crit', 'typ', 'x5c', 'jwk']) {
      const json = JSON.stringify({ alg: 'ES256', [name]: 'x', crit: [name] });
      const result = validateCritical(header(json), 'jws');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('crit_names_base_parameter');
      }
    }

    // `enc` and `zip` are base parameters in JWE, where they select behaviour.
    for (const name of ['enc', 'zip']) {
      const json = JSON.stringify({ alg: 'A128KW', enc: 'A128GCM', [name]: 'x', crit: [name] });
      const result = validateCritical(header(json), 'jwe');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('crit_names_base_parameter');
      }
    }
  });

  test('classifies a JWE-only key-management name as an extension request in JWS', () => {
    // These names define key-management semantics no JWS extension implements.
    // Naming one critical in a JWS is a well-formed request for semantics that
    // do not exist, which the specification distinguishes from redeclaring a
    // base parameter.
    for (const name of ['epk', 'apu', 'apv', 'iv', 'tag', 'p2s', 'p2c']) {
      const json = JSON.stringify({ alg: 'ES256', [name]: 'x', crit: [name] });
      const result = validateCritical(header(json), 'jws');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe('unsupported_critical_parameter');
      }

      // In JWE the same name is a base parameter, so redeclaring it is malformed.
      const inJwe = validateCritical(header(JSON.stringify({ alg: 'A128KW', [name]: 'x', crit: [name] })), 'jwe');
      expect(inJwe.ok).toBe(false);
      if (!inJwe.ok) {
        expect(inJwe.reason).toBe('crit_names_base_parameter');
      }
    }
  });

  test('rejects a present extension with no implemented semantics', () => {
    // Recognition is not understanding: the name is present and well formed,
    // but no semantics exist for it.
    const result = validateCritical(header('{"alg":"ES256","ext":"v","crit":["ext"]}'), 'jws');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_critical_parameter');
    }
  });

  test('a critical JWE-only parameter in a JWS fails as unsupported critical', () => {
    // `enc` is registered for JWE only, so in a JWS header it selects nothing
    // and is not a base parameter of that context. Naming it critical is an
    // unsupported extension request rather than a malformed list, and the two
    // must stay distinguishable.
    const result = validateCritical(header('{"alg":"ES256","enc":"A128GCM","crit":["enc"]}'), 'jws');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_critical_parameter');
    }
  });

  test('rejects critical b64 in a JWE, where the extension is not defined', () => {
    // RFC 7797 defines `b64` for JWS only. JWE implements no critical
    // extension, so a producer demanding this one must be refused rather than
    // having the demand silently satisfied.
    const result = validateCritical(header('{"alg":"A128KW","enc":"A128GCM","b64":false,"crit":["b64"]}'), 'jwe');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_critical_parameter');
    }
  });
});

describe('JWS-05 b64 resolution', () => {
  test('defaults to encoded when absent', () => {
    const result = resolveB64(header('{"alg":"ES256"}'), [], false);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.encoded).toBe(true);
    }
  });

  test('honors a protected critical b64=false', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":false,"crit":["b64"]}'), ['b64'], true);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.encoded).toBe(false);
    }
  });

  test('refuses b64=false without the caller opt-in', () => {
    // The header is otherwise well formed, so only the missing caller selection
    // rejects it: the token cannot switch on a payload mode by itself.
    const result = resolveB64(header('{"alg":"ES256","b64":false,"crit":["b64"]}'), ['b64'], false);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('policy_violation');
      expect(result.reason).toBe('unencoded_payload_not_accepted');
    }
  });

  test('an explicit b64=true needs no opt-in', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":true,"crit":["b64"]}'), ['b64'], false);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.encoded).toBe(true);
    }
  });

  test('requires crit even when b64 is explicitly true', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":true}'), [], false);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('b64_not_critical');
    }
  });

  test('rejects a non-boolean b64', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":"false","crit":["b64"]}'), ['b64'], true);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('b64_not_a_boolean');
    }
  });

  test('rejects unprotected b64', () => {
    const merged = merge([
      source('{"alg":"ES256","crit":["b64"]}', 'protected'),
      source('{"b64":false}', 'shared_unprotected'),
    ]);
    const result = resolveB64(merged, ['b64'], true);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('b64_not_protected');
    }
  });
});
