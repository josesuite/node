import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

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

    assert.strictEqual(merged.parameters.size, 2);
    assert.strictEqual(isProtected(merged, 'alg'), true);
    assert.strictEqual(isProtected(merged, 'kid'), false);
    const kid = headerValue(merged, 'kid');
    if (kid?.kind !== 'string') {
      throw new Error(`expected a string kid, got ${kid?.kind}`);
    }
    assert.strictEqual(kid.value, 'k1');
  });

  test('rejects a name present in two sources even when values are equal', () => {
    const result = mergeHeaders(
      [source('{"alg":"ES256"}', 'protected'), source('{"alg":"ES256"}', 'shared_unprotected')],
      BUDGET,
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
      assert.strictEqual(result.reason, 'header_name_collision');
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

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
    }
  });

  test('header names are case-sensitive and do not collide across cases', () => {
    const merged = merge([source('{"alg":"ES256"}', 'protected'), source('{"ALG":"x"}', 'shared_unprotected')]);
    assert.strictEqual(merged.parameters.size, 2);
  });
});

describe('LIMIT-01 header source accounting', () => {
  test('counts source octets including internal whitespace', () => {
    const json = '{ "alg" : "ES256" }';
    assert.strictEqual(header(json).sourceBytes, json.length);
    // Decoded member count is 1, but the source is far larger; the two are
    // deliberately not derived from each other.
    assert.strictEqual(header(json).parameters.size, 1);
  });

  test('rejects one oversized header source', () => {
    const budget: HeaderBudget = { ...BUDGET, headerSource: 10 };
    const result = mergeHeaders([source('{"alg":"ES256"}', 'protected')], budget);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }
  });

  test('rejects an oversized total across sources', () => {
    const budget: HeaderBudget = { ...BUDGET, headerSource: 20, totalHeaderSource: 20 };
    const result = mergeHeaders(
      [source('{"alg":"ES256"}', 'protected'), source('{"kid":"k1"}', 'shared_unprotected')],
      budget,
    );
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'total_header_source_too_large');
    }
  });

  test('rejects too many merged members', () => {
    const budget: HeaderBudget = { ...BUDGET, mergedHeaderMembers: 2 };
    const result = mergeHeaders([source('{"a":1,"b":2,"c":3}', 'protected')], budget);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'merged_header_too_many_members');
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
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
    }
  });
});

describe('HDR-05 recognized parameter types', () => {
  test('accepts correctly typed recognized parameters', () => {
    assert.strictEqual(validateParameterTypes(header('{"alg":"ES256","kid":"k","typ":"JWT"}')).ok, true);
    assert.strictEqual(validateParameterTypes(header('{"jwk":{},"epk":{}}')).ok, true);
    assert.strictEqual(validateParameterTypes(header('{"x5c":["MAA="]}')).ok, true);
    assert.strictEqual(validateParameterTypes(header('{"p2c":100000}')).ok, true);
  });

  test('rejects a recognized string parameter with a non-string value', () => {
    for (const json of ['{"alg":1}', '{"kid":null}', '{"typ":[]}', '{"enc":{}}', '{"cty":true}']) {
      const result = validateParameterTypes(header(json));
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'invalid_header');
      }
    }
  });

  test('rejects wrong types for object, array, and numeric parameters', () => {
    assert.strictEqual(validateParameterTypes(header('{"jwk":"not-an-object"}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"epk":[]}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"x5c":"cert"}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"x5c":[]}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"x5c":[1]}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"x5c":["not base64"]}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"p2c":"100000"}')).ok, false);
  });

  test('bounds the certificate chain by the active limit', () => {
    // The chain is an ignored hint here, but it is attacker-supplied: the count
    // is enforced before the entries are decoded so an unbounded array cannot
    // impose work regardless of whether trust is evaluated from it.
    const certificate = Buffer.from(new Uint8Array(32).fill(1)).toString('base64');
    const within = JSON.stringify({ x5c: Array.from({ length: LIMITS_V1.certificateChain }, () => certificate) });
    assert.strictEqual(validateParameterTypes(header(within), LIMITS_V1).ok, true);

    const over = JSON.stringify({ x5c: Array.from({ length: LIMITS_V1.certificateChain + 1 }, () => certificate) });
    const result = validateParameterTypes(header(over), LIMITS_V1);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'x5c_chain_too_long');
    }
  });

  test('bounds a supplied certificate chain at creation', () => {
    const certificate = Buffer.from(new Uint8Array(32).fill(1)).toString('base64');
    const within = Array.from({ length: LIMITS_V1.certificateChain }, () => certificate);
    assert.strictEqual(checkSuppliedParameterType('x5c', within, LIMITS_V1), true);
    assert.strictEqual(checkSuppliedParameterType('x5c', [...within, certificate], LIMITS_V1), false);
  });

  test('validates a recognized type even when the parameter is otherwise ignored', () => {
    // A JWE-only parameter carried noncritically in a JWS still has its type
    // validated, though it selects no JWS backend.
    assert.strictEqual(validateParameterTypes(header('{"alg":"ES256","enc":1}')).ok, false);
    assert.strictEqual(validateParameterTypes(header('{"alg":"ES256","enc":"A128GCM"}')).ok, true);
  });

  test('ignores unknown noncritical parameters', () => {
    assert.strictEqual(validateParameterTypes(header('{"alg":"ES256","unknown":{"any":[1,2]}}')).ok, true);
  });

  test('bounds kid length', () => {
    const long = JSON.stringify({ kid: 'k'.repeat(257) });
    const result = validateParameterTypes(header(long));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
    }

    assert.strictEqual(validateParameterTypes(header(JSON.stringify({ kid: 'k'.repeat(256) }))).ok, true);
  });
});

describe('HDR-04 and HDR-06 critical extensions', () => {
  test('absent crit yields no critical names', () => {
    const result = validateCritical(header('{"alg":"ES256"}'), 'jws');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.names, []);
    }
  });

  test('accepts a well-formed crit naming an implemented extension', () => {
    const result = validateCritical(header('{"alg":"ES256","b64":false,"crit":["b64"]}'), 'jws');
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.names, ['b64']);
    }
  });

  test('rejects unprotected crit', () => {
    const merged = merge([
      source('{"alg":"ES256","b64":false}', 'protected'),
      source('{"crit":["b64"]}', 'shared_unprotected'),
    ]);
    const result = validateCritical(merged, 'jws');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'crit_not_protected');
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
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'invalid_header');
        assert.strictEqual(result.reason, reason);
      }
    }
  });

  test('rejects crit naming a base JOSE/JWA parameter', () => {
    for (const name of ['alg', 'kid', 'crit', 'typ', 'x5c', 'jwk']) {
      const json = JSON.stringify({ alg: 'ES256', [name]: 'x', crit: [name] });
      const result = validateCritical(header(json), 'jws');
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'crit_names_base_parameter');
      }
    }

    // `enc` and `zip` are base parameters in JWE, where they select behaviour.
    for (const name of ['enc', 'zip']) {
      const json = JSON.stringify({ alg: 'A128KW', enc: 'A128GCM', [name]: 'x', crit: [name] });
      const result = validateCritical(header(json), 'jwe');
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'crit_names_base_parameter');
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
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'unsupported_critical_parameter');
      }

      // In JWE the same name is a base parameter, so redeclaring it is malformed.
      const inJwe = validateCritical(header(JSON.stringify({ alg: 'A128KW', [name]: 'x', crit: [name] })), 'jwe');
      assert.strictEqual(inJwe.ok, false);
      if (!inJwe.ok) {
        assert.strictEqual(inJwe.reason, 'crit_names_base_parameter');
      }
    }
  });

  test('an inherited object property does not satisfy a critical name', () => {
    // A presence check reaching the prototype chain would treat these as sent by
    // the producer, silently satisfying an extension nobody declared.
    for (const name of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
      const absent = validateCritical(header(JSON.stringify({ alg: 'ES256', crit: [name] })), 'jws');
      assert.strictEqual(absent.ok, false);
      if (!absent.ok) {
        assert.strictEqual(absent.reason, 'crit_names_absent_parameter');
      }

      // Genuinely present, it is an ordinary extension with no implemented
      // semantics rather than something already understood.
      const present = validateCritical(header(JSON.stringify({ alg: 'ES256', [name]: 'v', crit: [name] })), 'jws');
      assert.strictEqual(present.ok, false);
      if (!present.ok) {
        assert.strictEqual(present.category, 'unsupported_critical_parameter');
      }
    }
  });

  test('rejects a present extension with no implemented semantics', () => {
    // Recognition is not understanding: the name is present and well formed,
    // but no semantics exist for it.
    const result = validateCritical(header('{"alg":"ES256","ext":"v","crit":["ext"]}'), 'jws');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_critical_parameter');
    }
  });

  test('a critical JWE-only parameter in a JWS fails as unsupported critical', () => {
    // `enc` is registered for JWE only, so in a JWS header it selects nothing
    // and is not a base parameter of that context. Naming it critical is an
    // unsupported extension request rather than a malformed list, and the two
    // must stay distinguishable.
    const result = validateCritical(header('{"alg":"ES256","enc":"A128GCM","crit":["enc"]}'), 'jws');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_critical_parameter');
    }
  });

  test('rejects critical b64 in a JWE, where the extension is not defined', () => {
    // RFC 7797 defines `b64` for JWS only. JWE implements no critical
    // extension, so a producer demanding this one must be refused rather than
    // having the demand silently satisfied.
    const result = validateCritical(header('{"alg":"A128KW","enc":"A128GCM","b64":false,"crit":["b64"]}'), 'jwe');
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_critical_parameter');
    }
  });
});

describe('JWS-05 b64 resolution', () => {
  test('defaults to encoded when absent', () => {
    const result = resolveB64(header('{"alg":"ES256"}'), [], false);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.encoded, true);
    }
  });

  test('honors a protected critical b64=false', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":false,"crit":["b64"]}'), ['b64'], true);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.encoded, false);
    }
  });

  test('refuses b64=false without the caller opt-in', () => {
    // The header is otherwise well formed, so only the missing caller selection
    // rejects it: the token cannot switch on a payload mode by itself.
    const result = resolveB64(header('{"alg":"ES256","b64":false,"crit":["b64"]}'), ['b64'], false);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'unencoded_payload_not_accepted');
    }
  });

  test('an explicit b64=true needs no opt-in', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":true,"crit":["b64"]}'), ['b64'], false);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.encoded, true);
    }
  });

  test('requires crit even when b64 is explicitly true', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":true}'), [], false);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'b64_not_critical');
    }
  });

  test('rejects a non-boolean b64', () => {
    const result = resolveB64(header('{"alg":"ES256","b64":"false","crit":["b64"]}'), ['b64'], true);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'b64_not_a_boolean');
    }
  });

  test('rejects unprotected b64', () => {
    const merged = merge([
      source('{"alg":"ES256","crit":["b64"]}', 'protected'),
      source('{"b64":false}', 'shared_unprotected'),
    ]);
    const result = resolveB64(merged, ['b64'], true);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'b64_not_protected');
    }
  });
});
