import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, test } from 'node:test';

import { ecdsaCurve, ecdsaSignatureBytes, signEcdsa, verifyEcdsa } from '../../../src/algorithms/jws/ecdsa.ts';
import { computeHmac, hmacOutputBytes, verifyHmac } from '../../../src/algorithms/jws/hmac.ts';
import { deriveEcPublicPoint, deriveOkpPublicKey, validateEcPointOnCurve } from '../../../src/internal/crypto/node.ts';
import { isJsonArray, isJsonObject, isJsonString } from '../../../src/internal/json/types.ts';
import { encodeUtf8 } from '../../../src/internal/encoding/utf8.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import { buildAdditionalData } from '../../../src/jwe/types.ts';
import {
  buildSigningInput,
  buildSigningInputForOctets,
  validateInlineUnencodedPayload,
} from '../../../src/jws/types.ts';
import { parseThumbprintUri, toThumbprintUri } from '../../../src/jwk/thumbprint.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

const b64 = (value: unknown): Uint8Array => new Uint8Array(Buffer.from(String(value), 'base64url'));

describe('low-level coverage boundaries', () => {
  test('recognizes the parsed JSON value kinds', () => {
    const parsed = parseJson(encodeUtf8('{"object":{},"array":[],"string":"value"}'), LIMITS_V1);
    assert.strictEqual(parsed.ok, true);
    if (!parsed.ok || parsed.value.kind !== 'object') {
      return;
    }
    assert.strictEqual(isJsonObject(parsed.value), true);
    assert.strictEqual(isJsonArray(parsed.value.members.get('array')!), true);
    assert.strictEqual(isJsonString(parsed.value.members.get('string')!), true);
  });

  test('builds and rejects authenticated-data components', () => {
    assert.deepStrictEqual(buildAdditionalData('header', undefined), {
      ok: true,
      bytes: encodeUtf8('header'),
    });
    assert.deepStrictEqual(buildAdditionalData('header', 'aad'), {
      ok: true,
      bytes: encodeUtf8('header.aad'),
    });
    assert.deepStrictEqual(buildAdditionalData('héader', undefined), { ok: false, failure: 'non_ascii_component' });
    assert.deepStrictEqual(buildAdditionalData('header', 'aäd'), { ok: false, failure: 'non_ascii_component' });
  });

  test('builds the exact encoded and unencoded JWS inputs', () => {
    assert.deepStrictEqual(validateInlineUnencodedPayload(new Uint8Array([0x2e]), true), {
      ok: true,
      bytes: new Uint8Array([0x2e]),
    });
    assert.deepStrictEqual(validateInlineUnencodedPayload(new Uint8Array([0x2e]), false), {
      ok: false,
      failure: 'payload_character_not_permitted',
    });
    assert.strictEqual(validateInlineUnencodedPayload(new Uint8Array([0x1f]), true).ok, false);

    assert.strictEqual(buildSigningInput('héader', { component: 'payload' }).ok, false);
    assert.strictEqual(buildSigningInput('header', { component: 'pâyl oad' }).ok, false);
    assert.deepStrictEqual(buildSigningInput('header', { octets: new Uint8Array([1, 2]) }), {
      ok: true,
      bytes: new Uint8Array([104, 101, 97, 100, 101, 114, 46, 1, 2]),
    });
    assert.strictEqual(
      buildSigningInputForOctets('header', new Uint8Array([0xff]), { encoded: true, location: 'attached' }).ok,
      true,
    );
    assert.deepStrictEqual(
      buildSigningInputForOctets('header', new Uint8Array([1, 2]), { encoded: false, location: 'attached' }),
      buildSigningInput('header', { octets: new Uint8Array([1, 2]) }),
    );
  });

  test('distinguishes supported and invalid native curve operations', () => {
    assert.strictEqual(deriveEcPublicPoint('unknown', new Uint8Array(32)).ok, false);
    assert.strictEqual(deriveEcPublicPoint('P-256', new Uint8Array(32)).ok, false);
    assert.strictEqual(deriveOkpPublicKey('Ed25519', new Uint8Array(1)).ok, false);
    assert.strictEqual(validateEcPointOnCurve('unknown', { x: new Uint8Array(32), y: new Uint8Array(32) }).ok, false);
    assert.strictEqual(
      validateEcPointOnCurve('P-256', { x: new Uint8Array(32).fill(9), y: new Uint8Array(32).fill(9) }).ok,
      false,
    );

    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = pair.privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const derived = deriveEcPublicPoint('P-256', b64(jwk['d']));
    assert.strictEqual(derived.ok, true);
    if (derived.ok) {
      assert.strictEqual(validateEcPointOnCurve('P-256', derived.value).ok, true);
    }
  });

  test('covers signature adapter rejection boundaries', async () => {
    assert.strictEqual(hmacOutputBytes('unknown'), undefined);
    assert.deepStrictEqual(await computeHmac('unknown', new Uint8Array(32), new Uint8Array()), {
      ok: false,
      failure: 'unsupported',
    });
    assert.deepStrictEqual(await computeHmac('HS256', new Uint8Array(1), new Uint8Array()), {
      ok: false,
      failure: 'operation_failed',
    });
    assert.deepStrictEqual(await verifyHmac('HS256', new Uint8Array(32), new Uint8Array(), new Uint8Array(1)), {
      ok: true,
      value: false,
    });

    assert.strictEqual(ecdsaSignatureBytes('unknown'), undefined);
    assert.strictEqual(ecdsaCurve('unknown'), undefined);
    assert.deepStrictEqual(
      await signEcdsa(
        'unknown',
        { crv: 'P-256', x: new Uint8Array(32), y: new Uint8Array(32), d: new Uint8Array(32) },
        new Uint8Array(),
      ),
      { ok: false, failure: 'unsupported' },
    );
    assert.deepStrictEqual(
      await signEcdsa(
        'ES256',
        { crv: 'P-384', x: new Uint8Array(48), y: new Uint8Array(48), d: new Uint8Array(48) },
        new Uint8Array(),
      ),
      { ok: false, failure: 'operation_failed' },
    );
    assert.deepStrictEqual(
      await verifyEcdsa(
        'ES256',
        { crv: 'P-384', x: new Uint8Array(48), y: new Uint8Array(48) },
        new Uint8Array(),
        new Uint8Array(64),
      ),
      { ok: false, failure: 'operation_failed' },
    );
  });

  test('validates thumbprint URI syntax', () => {
    const valid = 'A'.repeat(43);
    assert.deepStrictEqual(toThumbprintUri(valid), {
      ok: true,
      thumbprint: valid,
      uri: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${valid}`,
    });
    assert.deepStrictEqual(toThumbprintUri('not-a-digest'), { ok: false, reason: 'digest_invalid' });
    assert.deepStrictEqual(parseThumbprintUri('https://example.test/key'), { ok: false, reason: 'unsupported_prefix' });
    assert.deepStrictEqual(parseThumbprintUri('urn:ietf:params:oauth:jwk-thumbprint:sha-256:short'), {
      ok: false,
      reason: 'digest_wrong_length',
    });
    assert.deepStrictEqual(parseThumbprintUri(`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${'!'.repeat(43)}`), {
      ok: false,
      reason: 'digest_not_base64url',
    });
    assert.strictEqual(parseThumbprintUri(`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${valid}`).ok, true);
  });
});
