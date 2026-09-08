import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { signWithKey } from '../../../src/algorithms/index.ts';
import { importKey } from '../../../src/key/import.ts';
import { sameKeyMaterial } from '../../../src/key/identity.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';
import { availableCurves } from '../../helpers/runtime.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function rsaJwk(modulusLength = 3072): Record<string, string> {
  return generateKeyPairSync('rsa', { modulusLength }).privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;
}

function ecJwk(curve = 'P-256'): Record<string, string> {
  return generateKeyPairSync('ec', { namedCurve: curve }).privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;
}

function ed25519Jwk(): Record<string, string> {
  return generateKeyPairSync('ed25519').privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;
}

function octJwk(bytes = 32): Record<string, string> {
  return { kty: 'oct', k: Buffer.alloc(bytes, 7).toString('base64url') };
}

const RSA_SIGN = { algorithm: 'RS256', operation: 'sign' } as const;
const EC_VERIFY = { algorithm: 'ES256', operation: 'verify' } as const;
const ED_VERIFY = { algorithm: 'Ed25519', operation: 'verify' } as const;
const HS_VERIFY = { algorithm: 'HS256', operation: 'verify' } as const;

describe('importing each key type', () => {
  test('imports RSA private and public keys', () => {
    const jwk = rsaJwk();
    const priv = importKey(object(jwk), RSA_SIGN);
    expect(priv.ok).toBe(true);
    if (priv.ok) {
      expect(priv.key.keyType).toBe('RSA');
      expect(priv.key.isPrivate).toBe(true);
      expect(priv.key.algorithm).toBe('RS256');
    }

    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicOnly } = jwk;
    const pub = importKey(object(publicOnly), { algorithm: 'RS256', operation: 'verify' });
    expect(pub.ok).toBe(true);
    if (pub.ok) {
      expect(pub.key.isPrivate).toBe(false);
    }
  });

  test('refuses an RSA key carrying orphan private members', () => {
    // `d` absent but the CRT group present. Keying private detection on `d`
    // alone would import this as a public key, silently discarding supplied
    // private material instead of reporting the incomplete group.
    const { d: _d, ...orphan } = rsaJwk();
    const result = importKey(object(orphan), { algorithm: 'RS256', operation: 'verify' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('d_missing');
    }
  });

  test('imports EC keys and refuses unqualified signing OKP keys', () => {
    expect(importKey(object(ecJwk()), EC_VERIFY).ok).toBe(true);
    expect(importKey(object(ed25519Jwk()), ED_VERIFY).ok).toBe(false);
  });

  test('imports symmetric keys and enforces the algorithm minimum', () => {
    const ok = importKey(object(octJwk(32)), { ...HS_VERIFY, minimumSymmetricBytes: 32 });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.key.isPrivate).toBe(true);
    }

    const short = importKey(object(octJwk(31)), { ...HS_VERIFY, minimumSymmetricBytes: 32 });
    expect(short.ok).toBe(false);
    if (!short.ok) {
      expect(short.category).toBe('incompatible_key');
    }
  });

  test('enforces the algorithm minimum without caller opt-in', () => {
    // MAC-02 fixes the HS256 floor at the 32-octet hash output. The minimum is
    // a property of the algorithm, so it must hold even when the caller
    // supplies no `minimumSymmetricBytes`.
    for (const bytes of [0, 16, 31]) {
      const result = importKey(object(octJwk(bytes)), HS_VERIFY);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('symmetric_key_too_short');
      }
    }

    expect(importKey(object(octJwk(32)), HS_VERIFY).ok).toBe(true);
  });

  test('refuses a key whose type cannot carry the bound algorithm', () => {
    const result = importKey(object(octJwk(32)), { algorithm: 'RS256', operation: 'verify' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('incompatible_key');
      expect(result.reason).toBe('key_type_not_eligible_for_algorithm');
    }
  });

  test('binds ECDSA algorithms to their exact curve', () => {
    const p384 = ecJwk('P-384');

    // ES256 names P-256; a P-384 key is not interchangeable with it.
    const mismatch = importKey(object(p384), { algorithm: 'ES256', operation: 'sign' });
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) {
      expect(mismatch.reason).toBe('curve_not_eligible_for_algorithm');
    }

    expect(importKey(object(p384), { algorithm: 'ES384', operation: 'sign' }).ok).toBe(true);
  });

  test('gives a private key and its public half the same identity', () => {
    const jwk = ecJwk();
    const priv = importKey(object(jwk), { algorithm: 'ES256', operation: 'sign' });
    const { d: _d, ...publicOnly } = jwk;
    const pub = importKey(object(publicOnly), EC_VERIFY);

    expect(priv.ok && pub.ok).toBe(true);
    if (priv.ok && pub.ok) {
      // The same cryptographic key must count once, however it was supplied.
      expect(sameKeyMaterial(priv.key.identity, pub.key.identity)).toBe(true);
    }
  });
});

describe('structural rejections', () => {
  test('requires a well-formed kty', () => {
    expect(importKey(object({ n: 'x', e: 'AQAB' }), RSA_SIGN).ok).toBe(false);

    const mistyped = importKey(object({ kty: 1 }), RSA_SIGN);
    expect(mistyped.ok).toBe(false);
    if (!mistyped.ok) {
      expect(mistyped.reason).toBe('kty_not_a_string');
    }
  });

  test('refuses an unknown key type rather than guessing', () => {
    const result = importKey(object({ kty: 'XYZ', x: 'AA' }), EC_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('kty_unsupported');
      expect(result.category).toBe('incompatible_key');
    }
  });

  test('requires a supported curve', () => {
    const missing = importKey(object({ kty: 'EC', x: 'AA', y: 'AA' }), EC_VERIFY);
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.reason).toBe('crv_missing');
    }

    const unsupported = importKey(object({ kty: 'EC', crv: 'P-192', x: 'AA', y: 'AA' }), EC_VERIFY);
    expect(unsupported.ok).toBe(false);
    if (!unsupported.ok) {
      expect(unsupported.reason).toBe('crv_unsupported');
    }
  });

  test('never admits a partially specified private RSA key', () => {
    // A key advertising `d` must carry the whole consistent private group; a
    // partial one is refused rather than used with whatever is present.
    const jwk = rsaJwk();
    const { qi: _qi, ...missingQi } = jwk;
    const result = importKey(object(missingQi), RSA_SIGN);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('qi_missing');
    }
  });

  test('rejects a private key whose public component does not match', () => {
    const a = ecJwk();
    const b = ecJwk();
    const result = importKey(object({ ...a, x: b['x']!, y: b['y']! }), EC_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('public_private_mismatch');
    }
  });

  test('rejects Ed25519 while no approved public-key validator is available', () => {
    const x = Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex').toString(
      'base64url',
    );
    const result = importKey(object({ kty: 'OKP', crv: 'Ed25519', x }), ED_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('curve_not_qualified');
    }
  });
});

describe('binding to trusted configuration', () => {
  test('requires explicit content bindings and the specified JOSE operation mapping', () => {
    const direct = octJwk(16);
    expect(importKey(object(direct), { algorithm: 'dir', operation: 'encrypt' }).ok).toBe(false);
    expect(
      importKey(object(direct), {
        algorithm: 'dir',
        operation: 'encrypt',
        contentAlgorithms: ['A128GCM', 'A128CBC-HS256'],
      }).ok,
    ).toBe(false);
    expect(
      importKey(object(octJwk(32)), {
        algorithm: 'dir',
        operation: 'encrypt',
        contentAlgorithms: ['A128GCM'],
      }).ok,
    ).toBe(false);

    const agreement = { ...ecJwk(), use: 'enc', key_ops: ['deriveKey'] };
    expect(
      importKey(object(agreement), {
        algorithm: 'ECDH-ES',
        operation: 'deriveKey',
        contentAlgorithms: ['A128GCM'],
      }).ok,
    ).toBe(true);
    expect(
      importKey(object(agreement), {
        algorithm: 'ECDH-ES',
        operation: 'encrypt',
        contentAlgorithms: ['A128GCM'],
      }).ok,
    ).toBe(false);
  });

  test('rejects a key whose alg disagrees with the binding', () => {
    const result = importKey(object({ ...ecJwk(), alg: 'ES384' }), EC_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('incompatible_key');
      expect(result.reason).toBe('alg_binding_mismatch');
    }
  });

  test('rejects a key that does not permit the bound operation', () => {
    const result = importKey(object({ ...ecJwk(), key_ops: ['verify'] }), {
      algorithm: 'ES256',
      operation: 'sign',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('operation_not_permitted');
    }
  });

  test('rejects a key whose declared use is incompatible', () => {
    const result = importKey(object({ ...ecJwk(), use: 'enc' }), EC_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('use_not_compatible');
    }
  });

  test('reports self-contradictory metadata as invalid material, not a mismatch', () => {
    // The key contradicts itself about its own purpose, which is a defect in
    // the key rather than a disagreement with this particular binding.
    const result = importKey(object({ ...ecJwk(), use: 'sig', key_ops: ['encrypt'] }), EC_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_key');
      expect(result.reason).toBe('use_and_key_ops_conflict');
    }
  });

  test('absent metadata does not widen the binding', () => {
    const jwk = ecJwk();
    // Nothing in the key mentions an algorithm, so the binding alone decides,
    // and the same key can be imported under a different binding elsewhere.
    expect(importKey(object(jwk), EC_VERIFY).ok).toBe(true);
    expect(importKey(object(jwk), { algorithm: 'ES256', operation: 'sign' }).ok).toBe(true);
  });

  test('validates material before checking the binding', () => {
    // An off-curve key with a mismatched algorithm reports the material defect,
    // so a malformed key is never described as merely incompatible.
    const offCurve = Buffer.alloc(32, 9).toString('base64url');
    const result = importKey(object({ kty: 'EC', crv: 'P-256', x: offCurve, y: offCurve, alg: 'ES384' }), EC_VERIFY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('invalid_key');
      expect(result.reason).toBe('point_not_on_curve');
    }
  });
});

describe('RSA modulus policy', () => {
  test('refuses a legacy modulus unless the binding is receive-only', () => {
    const jwk = rsaJwk(2048);

    const modern = importKey(object(jwk), RSA_SIGN);
    expect(modern.ok).toBe(false);
    if (!modern.ok) {
      expect(modern.reason).toBe('n_too_small');
    }

    const receive = importKey(object(jwk), {
      algorithm: 'RS256',
      operation: 'verify',
      receiveOnly: true,
    });
    expect(receive.ok).toBe(true);
  });
});

describe('optional curves', () => {
  test('imports every curve this runtime provides', () => {
    for (const curve of availableCurves(['P-256', 'P-384', 'P-521', 'secp256k1'])) {
      const algorithm =
        curve === 'secp256k1' ? 'ES256K' : curve === 'P-384' ? 'ES384' : curve === 'P-521' ? 'ES512' : 'ES256';
      const result = importKey(object(ecJwk(curve)), { algorithm, operation: 'verify' });
      expect(result.ok).toBe(true);
    }
  });
});

describe('algorithm binding is validated against the registry', () => {
  test('refuses an unrecognized algorithm identifier', () => {
    const result = importKey(object(ecJwk()), { algorithm: 'ES256-TOTALLY-MADE-UP', operation: 'verify' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_algorithm');
    }
  });

  test('refuses a prohibited algorithm at import', () => {
    for (const algorithm of ['none', 'RS1', 'HS1']) {
      const result = importKey(object(ecJwk()), { algorithm, operation: 'verify' });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe('prohibited_algorithm');
      }
    }
  });

  test('refuses an identifier from the wrong selector position', () => {
    // A content-encryption name never selects a signature algorithm, so it
    // cannot be bound to a signing key.
    for (const algorithm of ['A128GCM', 'RSA-OAEP-256', 'dir']) {
      const result = importKey(object(ecJwk()), { algorithm, operation: 'verify' });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.category).toBe('unsupported_algorithm');
      }
    }
  });

  test('refuses EdDSA while its curve validator is unavailable', () => {
    const jwk = generateKeyPairSync('ed25519').privateKey.export({
      format: 'jwk',
    }) as unknown as Record<string, string>;

    // The deprecated polymorphic identifier is accepted for verification but
    // must never be used to create a signature.
    const create = importKey(object(jwk), { algorithm: 'EdDSA', operation: 'sign' });
    expect(create.ok).toBe(false);
    if (!create.ok) {
      expect(create.category).toBe('unsupported_algorithm');
    }

    expect(importKey(object(jwk), { algorithm: 'EdDSA', operation: 'verify' }).ok).toBe(false);
  });

  test('refuses an identifier registered only for signatures on an encryption operation', () => {
    const result = importKey(object(rsaJwk()), { algorithm: 'RS256', operation: 'unwrapKey' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('unsupported_algorithm');
    }
  });

  test('still accepts a correctly bound algorithm', () => {
    expect(importKey(object(ecJwk()), { algorithm: 'ES256', operation: 'verify' }).ok).toBe(true);
    expect(importKey(object(rsaJwk()), { algorithm: 'PS256', operation: 'sign' }).ok).toBe(true);
  });
});

describe('imported keys are sealed', () => {
  const families: readonly (readonly [string, () => Record<string, string>, string, string])[] = [
    ['RSA', rsaJwk, 'PS256', 'sign'],
    ['EC', ecJwk, 'ES256', 'sign'],
    ['oct', () => ({ kty: 'oct', k: Buffer.alloc(32, 7).toString('base64url') }), 'HS256', 'sign'],
  ];

  for (const [family, jwk, algorithm, operation] of families) {
    test(`${family} material is absent from JSON and inspection`, () => {
      const result = importKey(object(jwk()), { algorithm, operation: operation as 'sign' });
      if (!result.ok) {
        throw new Error(result.reason);
      }

      // Ordinary serialization and printing are how private material reaches
      // logs and error reports, so neither may carry it. The private scalar's
      // own bytes are searched for, not just the property name.
      const secret = [...(result.key.keyType === 'oct' ? result.key.material : result.key.material.d!)].join(', ');
      for (const rendered of [JSON.stringify(result.key), Bun.inspect(result.key)]) {
        expect(rendered).not.toContain('material');
        expect(rendered).not.toContain(secret);
      }
      expect(Object.keys(result.key)).not.toContain('material');
    });

    test(`${family} material cannot be changed after validation`, () => {
      const result = importKey(object(jwk()), { algorithm, operation: operation as 'sign' });
      if (!result.ok) {
        throw new Error(result.reason);
      }
      const key = result.key;

      expect(Object.isFrozen(key)).toBe(true);
      expect(() => {
        (key as { algorithm: string }).algorithm = 'HS512';
      }).toThrow();
      expect(key.algorithm).toBe(algorithm);
    });
  }

  test('the identity does not alias the material', () => {
    // One mutation must not move both the key and the value equality is decided
    // on, or a changed key would still compare as the validated one.
    const result = importKey(object({ kty: 'oct', k: Buffer.alloc(32, 7).toString('base64url') }), {
      algorithm: 'HS256',
      operation: 'verify',
    });
    if (!result.ok) {
      throw new Error(result.reason);
    }
    const key = result.key;
    if (key.keyType !== 'oct' || key.identity.kty !== 'oct') {
      throw new Error('unexpected key shape');
    }

    expect(key.identity.k).not.toBe(key.material);
    expect(key.identity.k).toEqual(key.material);
  });

  test('changing the source JWK arrays after import does not change the key', () => {
    const secret = Buffer.alloc(32, 7);
    const parsed = object({ kty: 'oct', k: secret.toString('base64url') });
    const result = importKey(parsed, { algorithm: 'HS256', operation: 'verify' });
    if (!result.ok) {
      throw new Error(result.reason);
    }
    const key = result.key;
    if (key.keyType !== 'oct') {
      throw new Error('unexpected key shape');
    }

    // The decoded array the key was built from is reachable through the parsed
    // JWK. A key holding a copy is unaffected by later writes to it.
    const member = parsed.members.get('k');
    if (member?.kind !== 'string') {
      throw new Error('unexpected member');
    }

    expect([...key.material]).toEqual([...secret]);
  });

  test('a record copied from an imported key is not usable for cryptography', async () => {
    // The copy satisfies the type and carries the same fields, but nothing
    // validated it. Dispatch must refuse it rather than operate on whatever
    // material the caller attached.
    const result = importKey(object(ecJwk()), { algorithm: 'ES256', operation: 'sign' });
    if (!result.ok) {
      throw new Error(result.reason);
    }

    const forged = { ...result.key, material: result.key.material } as typeof result.key;
    const signed = await signWithKey(forged, new TextEncoder().encode('input'));

    expect(signed.ok).toBe(false);
    if (!signed.ok) {
      expect(signed.failure).toBe('operation_failed');
    }
  });
});

describe('metadata size limits', () => {
  test('measures kid in UTF-8 bytes rather than UTF-16 code units', () => {
    // An astral character is one UTF-16 pair but four UTF-8 bytes. Counting
    // code units would admit a `kid` roughly twice the limit here and reject the
    // same key where a header `kid` is measured in bytes.
    const oversized = '\u{1F600}'.repeat(Math.ceil(LIMITS_V1.kid / 4) + 1);
    expect(oversized.length).toBeLessThanOrEqual(LIMITS_V1.kid);

    const result = importKey(object({ ...octJwk(), kid: oversized }), HS_VERIFY);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.category).toBe('resource_limit');
      expect(result.reason).toBe('kid_too_long');
    }
  });

  test('accepts a kid at exactly the byte limit', () => {
    const result = importKey(object({ ...octJwk(), kid: 'a'.repeat(LIMITS_V1.kid) }), HS_VERIFY);
    expect(result.ok).toBe(true);
  });
});
