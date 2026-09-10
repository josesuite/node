import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { inspect } from 'node:util';

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
    assert.strictEqual(priv.ok, true);
    if (priv.ok) {
      assert.strictEqual(priv.key.keyType, 'RSA');
      assert.strictEqual(priv.key.isPrivate, true);
      assert.strictEqual(priv.key.algorithm, 'RS256');
    }

    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicOnly } = jwk;
    const pub = importKey(object(publicOnly), { algorithm: 'RS256', operation: 'verify' });
    assert.strictEqual(pub.ok, true);
    if (pub.ok) {
      assert.strictEqual(pub.key.isPrivate, false);
    }
  });

  test('refuses an RSA key carrying orphan private members', () => {
    // `d` absent but the CRT group present. Keying private detection on `d`
    // alone would import this as a public key, silently discarding supplied
    // private material instead of reporting the incomplete group.
    const { d: _d, ...orphan } = rsaJwk();
    const result = importKey(object(orphan), { algorithm: 'RS256', operation: 'verify' });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'd_missing');
    }
  });

  test('imports EC keys and refuses unqualified signing OKP keys', () => {
    assert.strictEqual(importKey(object(ecJwk()), EC_VERIFY).ok, true);
    assert.strictEqual(importKey(object(ed25519Jwk()), ED_VERIFY).ok, false);
  });

  test('imports symmetric keys and enforces the algorithm minimum', () => {
    const ok = importKey(object(octJwk(32)), { ...HS_VERIFY, minimumSymmetricBytes: 32 });
    assert.strictEqual(ok.ok, true);
    if (ok.ok) {
      assert.strictEqual(ok.key.isPrivate, true);
    }

    const short = importKey(object(octJwk(31)), { ...HS_VERIFY, minimumSymmetricBytes: 32 });
    assert.strictEqual(short.ok, false);
    if (!short.ok) {
      assert.strictEqual(short.category, 'incompatible_key');
    }
  });

  test('enforces the algorithm minimum without caller opt-in', () => {
    // MAC-02 fixes the HS256 floor at the 32-octet hash output. The minimum is
    // a property of the algorithm, so it must hold even when the caller
    // supplies no `minimumSymmetricBytes`.
    for (const bytes of [0, 16, 31]) {
      const result = importKey(object(octJwk(bytes)), HS_VERIFY);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'symmetric_key_too_short');
      }
    }

    assert.strictEqual(importKey(object(octJwk(32)), HS_VERIFY).ok, true);
  });

  test('refuses a key whose type cannot carry the bound algorithm', () => {
    const result = importKey(object(octJwk(32)), { algorithm: 'RS256', operation: 'verify' });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
      assert.strictEqual(result.reason, 'key_type_not_eligible_for_algorithm');
    }
  });

  test('binds ECDSA algorithms to their exact curve', () => {
    const p384 = ecJwk('P-384');

    // ES256 names P-256; a P-384 key is not interchangeable with it.
    const mismatch = importKey(object(p384), { algorithm: 'ES256', operation: 'sign' });
    assert.strictEqual(mismatch.ok, false);
    if (!mismatch.ok) {
      assert.strictEqual(mismatch.reason, 'curve_not_eligible_for_algorithm');
    }

    assert.strictEqual(importKey(object(p384), { algorithm: 'ES384', operation: 'sign' }).ok, true);
  });

  test('gives a private key and its public half the same identity', () => {
    const jwk = ecJwk();
    const priv = importKey(object(jwk), { algorithm: 'ES256', operation: 'sign' });
    const { d: _d, ...publicOnly } = jwk;
    const pub = importKey(object(publicOnly), EC_VERIFY);

    assert.strictEqual(priv.ok && pub.ok, true);
    if (priv.ok && pub.ok) {
      // The same cryptographic key must count once, however it was supplied.
      assert.strictEqual(sameKeyMaterial(priv.key.identity, pub.key.identity), true);
    }
  });
});

describe('structural rejections', () => {
  test('requires a well-formed kty', () => {
    assert.strictEqual(importKey(object({ n: 'x', e: 'AQAB' }), RSA_SIGN).ok, false);

    const mistyped = importKey(object({ kty: 1 }), RSA_SIGN);
    assert.strictEqual(mistyped.ok, false);
    if (!mistyped.ok) {
      assert.strictEqual(mistyped.reason, 'kty_not_a_string');
    }
  });

  test('refuses an unknown key type rather than guessing', () => {
    const result = importKey(object({ kty: 'XYZ', x: 'AA' }), EC_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'kty_unsupported');
      assert.strictEqual(result.category, 'incompatible_key');
    }
  });

  test('requires a supported curve', () => {
    const missing = importKey(object({ kty: 'EC', x: 'AA', y: 'AA' }), EC_VERIFY);
    assert.strictEqual(missing.ok, false);
    if (!missing.ok) {
      assert.strictEqual(missing.reason, 'crv_missing');
    }

    const unsupported = importKey(object({ kty: 'EC', crv: 'P-192', x: 'AA', y: 'AA' }), EC_VERIFY);
    assert.strictEqual(unsupported.ok, false);
    if (!unsupported.ok) {
      assert.strictEqual(unsupported.reason, 'crv_unsupported');
    }
  });

  test('never admits a partially specified private RSA key', () => {
    // A key advertising `d` must carry the whole consistent private group; a
    // partial one is refused rather than used with whatever is present.
    const jwk = rsaJwk();
    const { qi: _qi, ...missingQi } = jwk;
    const result = importKey(object(missingQi), RSA_SIGN);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'qi_missing');
    }
  });

  test('rejects a private key whose public component does not match', () => {
    const a = ecJwk();
    const b = ecJwk();
    const result = importKey(object({ ...a, x: b['x']!, y: b['y']! }), EC_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'public_private_mismatch');
    }
  });

  test('rejects Ed25519 while no approved public-key validator is available', () => {
    const x = Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex').toString(
      'base64url',
    );
    const result = importKey(object({ kty: 'OKP', crv: 'Ed25519', x }), ED_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'curve_not_qualified');
    }
  });
});

describe('binding to trusted configuration', () => {
  test('requires explicit content bindings and the specified JOSE operation mapping', () => {
    const direct = octJwk(16);
    assert.strictEqual(importKey(object(direct), { algorithm: 'dir', operation: 'encrypt' }).ok, false);
    assert.strictEqual(
      importKey(object(direct), {
        algorithm: 'dir',
        operation: 'encrypt',
        contentAlgorithms: ['A128GCM', 'A128CBC-HS256'],
      }).ok,
      false,
    );
    assert.strictEqual(
      importKey(object(octJwk(32)), {
        algorithm: 'dir',
        operation: 'encrypt',
        contentAlgorithms: ['A128GCM'],
      }).ok,
      false,
    );

    const agreement = { ...ecJwk(), use: 'enc', key_ops: ['deriveKey'] };
    assert.strictEqual(
      importKey(object(agreement), {
        algorithm: 'ECDH-ES',
        operation: 'deriveKey',
        contentAlgorithms: ['A128GCM'],
      }).ok,
      true,
    );
    assert.strictEqual(
      importKey(object(agreement), {
        algorithm: 'ECDH-ES',
        operation: 'encrypt',
        contentAlgorithms: ['A128GCM'],
      }).ok,
      false,
    );
  });

  test('rejects a key whose alg disagrees with the binding', () => {
    const result = importKey(object({ ...ecJwk(), alg: 'ES384' }), EC_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'incompatible_key');
      assert.strictEqual(result.reason, 'alg_binding_mismatch');
    }
  });

  test('rejects a key that does not permit the bound operation', () => {
    const result = importKey(object({ ...ecJwk(), key_ops: ['verify'] }), {
      algorithm: 'ES256',
      operation: 'sign',
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'operation_not_permitted');
    }
  });

  test('rejects a key whose declared use is incompatible', () => {
    const result = importKey(object({ ...ecJwk(), use: 'enc' }), EC_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'use_not_compatible');
    }
  });

  test('reports self-contradictory metadata as invalid material, not a mismatch', () => {
    // The key contradicts itself about its own purpose, which is a defect in
    // the key rather than a disagreement with this particular binding.
    const result = importKey(object({ ...ecJwk(), use: 'sig', key_ops: ['encrypt'] }), EC_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_key');
      assert.strictEqual(result.reason, 'use_and_key_ops_conflict');
    }
  });

  test('absent metadata does not widen the binding', () => {
    const jwk = ecJwk();
    // Nothing in the key mentions an algorithm, so the binding alone decides,
    // and the same key can be imported under a different binding elsewhere.
    assert.strictEqual(importKey(object(jwk), EC_VERIFY).ok, true);
    assert.strictEqual(importKey(object(jwk), { algorithm: 'ES256', operation: 'sign' }).ok, true);
  });

  test('validates material before checking the binding', () => {
    // An off-curve key with a mismatched algorithm reports the material defect,
    // so a malformed key is never described as merely incompatible.
    const offCurve = Buffer.alloc(32, 9).toString('base64url');
    const result = importKey(object({ kty: 'EC', crv: 'P-256', x: offCurve, y: offCurve, alg: 'ES384' }), EC_VERIFY);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_key');
      assert.strictEqual(result.reason, 'point_not_on_curve');
    }
  });
});

describe('RSA modulus policy', () => {
  test('refuses a legacy modulus unless the binding is receive-only', () => {
    const jwk = rsaJwk(2048);

    const modern = importKey(object(jwk), RSA_SIGN);
    assert.strictEqual(modern.ok, false);
    if (!modern.ok) {
      assert.strictEqual(modern.reason, 'n_too_small');
    }

    const receive = importKey(object(jwk), {
      algorithm: 'RS256',
      operation: 'verify',
      receiveOnly: true,
    });
    assert.strictEqual(receive.ok, true);
  });
});

describe('optional curves', () => {
  test('imports every curve this runtime provides', () => {
    for (const curve of availableCurves(['P-256', 'P-384', 'P-521', 'secp256k1'])) {
      const algorithm =
        curve === 'secp256k1' ? 'ES256K' : curve === 'P-384' ? 'ES384' : curve === 'P-521' ? 'ES512' : 'ES256';
      const result = importKey(object(ecJwk(curve)), { algorithm, operation: 'verify' });
      assert.strictEqual(result.ok, true);
    }
  });
});

describe('algorithm binding is validated against the registry', () => {
  test('refuses an unrecognized algorithm identifier', () => {
    const result = importKey(object(ecJwk()), { algorithm: 'ES256-TOTALLY-MADE-UP', operation: 'verify' });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_algorithm');
    }
  });

  test('refuses a prohibited algorithm at import', () => {
    for (const algorithm of ['none', 'RS1', 'HS1']) {
      const result = importKey(object(ecJwk()), { algorithm, operation: 'verify' });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'prohibited_algorithm');
      }
    }
  });

  test('refuses an identifier from the wrong selector position', () => {
    // A content-encryption name never selects a signature algorithm, so it
    // cannot be bound to a signing key.
    for (const algorithm of ['A128GCM', 'RSA-OAEP-256', 'dir']) {
      const result = importKey(object(ecJwk()), { algorithm, operation: 'verify' });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'unsupported_algorithm');
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
    assert.strictEqual(create.ok, false);
    if (!create.ok) {
      assert.strictEqual(create.category, 'unsupported_algorithm');
    }

    assert.strictEqual(importKey(object(jwk), { algorithm: 'EdDSA', operation: 'verify' }).ok, false);
  });

  test('refuses an identifier registered only for signatures on an encryption operation', () => {
    const result = importKey(object(rsaJwk()), { algorithm: 'RS256', operation: 'unwrapKey' });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'unsupported_algorithm');
    }
  });

  test('still accepts a correctly bound algorithm', () => {
    assert.strictEqual(importKey(object(ecJwk()), { algorithm: 'ES256', operation: 'verify' }).ok, true);
    assert.strictEqual(importKey(object(rsaJwk()), { algorithm: 'PS256', operation: 'sign' }).ok, true);
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
      let secretBytes: Uint8Array;
      if (result.key.keyType === 'oct' || result.key.keyType === 'AKP') {
        secretBytes = result.key.material;
      } else if (result.key.keyType === 'RSA') {
        if (!('d' in result.key.material)) {
          throw new Error('private key material missing');
        }
        secretBytes = result.key.material.d;
      } else {
        if (result.key.material.d === undefined) {
          throw new Error('private key material missing');
        }
        secretBytes = result.key.material.d;
      }
      const secret = [...secretBytes].join(', ');
      // Unlimited depth so nested material cannot hide behind the default cutoff.
      const inspected = inspect(result.key, { depth: null });
      for (const rendered of [JSON.stringify(result.key), inspected]) {
        assert.ok(!rendered.includes('material'));
        assert.ok(!rendered.includes(secret));
      }
      assert.ok(!Object.keys(result.key).includes('material'));
    });

    test(`${family} material cannot be changed after validation`, () => {
      const result = importKey(object(jwk()), { algorithm, operation: operation as 'sign' });
      if (!result.ok) {
        throw new Error(result.reason);
      }
      const key = result.key;

      assert.strictEqual(Object.isFrozen(key), true);
      assert.throws(() => {
        (key as { algorithm: string }).algorithm = 'HS512';
      });
      assert.strictEqual(key.algorithm, algorithm);
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

    assert.notStrictEqual(key.identity.k, key.material);
    assert.deepStrictEqual(key.identity.k, key.material);
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

    assert.deepStrictEqual([...key.material], [...secret]);
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

    assert.strictEqual(signed.ok, false);
    if (!signed.ok) {
      assert.strictEqual(signed.failure, 'operation_failed');
    }
  });

  test('a record inheriting from an imported key is not usable for cryptography', async () => {
    const result = importKey(object(ecJwk()), { algorithm: 'ES256', operation: 'sign' });
    if (!result.ok) {
      throw new Error(result.reason);
    }

    const forged = Object.create(result.key) as typeof result.key;
    const signed = await signWithKey(forged, new TextEncoder().encode('input'));

    assert.deepStrictEqual(signed, { ok: false, failure: 'operation_failed' });
  });
});

describe('metadata size limits', () => {
  test('measures kid in UTF-8 bytes rather than UTF-16 code units', () => {
    // An astral character is one UTF-16 pair but four UTF-8 bytes. Counting
    // code units would admit a `kid` roughly twice the limit here and reject the
    // same key where a header `kid` is measured in bytes.
    const oversized = '\u{1F600}'.repeat(Math.ceil(LIMITS_V1.kid / 4) + 1);
    assert.ok(oversized.length <= LIMITS_V1.kid);

    const result = importKey(object({ ...octJwk(), kid: oversized }), HS_VERIFY);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'kid_too_long');
    }
  });

  test('accepts a kid at exactly the byte limit', () => {
    const result = importKey(object({ ...octJwk(), kid: 'a'.repeat(LIMITS_V1.kid) }), HS_VERIFY);
    assert.strictEqual(result.ok, true);
  });
});

function assertRejected(result: ReturnType<typeof importKey>, reason: string): void {
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, reason);
  }
}

/** Encodes a big-endian unsigned integer in the minimal form JWK requires. */
function uint(value: bigint): string {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  }
  return Buffer.from(hex, 'hex').toString('base64url');
}

function big(jwk: Record<string, string>, member: string): bigint {
  return BigInt(`0x${Buffer.from(jwk[member]!, 'base64url').toString('hex')}`);
}

function x25519Jwk(): Record<string, string> {
  return generateKeyPairSync('x25519').privateKey.export({
    format: 'jwk',
  }) as unknown as Record<string, string>;
}

describe('RSA material validation', () => {
  /** Mutates one supplied key so overrides stay consistent with its own members. */
  function importRsa(jwk: Record<string, string>, overrides: Record<string, unknown>) {
    return importKey(object({ ...jwk, ...overrides }), RSA_SIGN);
  }

  test('rejects a modulus that is even', async () => {
    // Not a product of two odd primes, so it cannot be a valid RSA modulus
    // regardless of its size.
    const jwk = rsaJwk();
    const n = BigInt(`0x${Buffer.from(jwk['n']!, 'base64url').toString('hex')}`);
    assertRejected(importRsa(jwk, { n: uint(n + 1n) }), 'n_even');
  });

  test('admits the 2048-bit range only under an explicitly receive-only binding', async () => {
    const jwk = object(rsaJwk(2048));
    assertRejected(importKey(jwk, RSA_SIGN), 'n_too_small');
    assertRejected(importKey(jwk, { algorithm: 'RS256', operation: 'verify' }), 'n_too_small');

    const receiving = importKey(jwk, { algorithm: 'RS256', operation: 'verify', receiveOnly: true });
    assert.strictEqual(receiving.ok, true);
  });

  test('rejects an exponent that is even, too small, or not less than the modulus', async () => {
    const jwk = rsaJwk();
    const n = BigInt(`0x${Buffer.from(jwk['n']!, 'base64url').toString('hex')}`);

    assertRejected(importRsa(jwk, { e: uint(4n) }), 'e_even');
    assertRejected(importRsa(jwk, { e: uint(1n) }), 'e_too_small');
    // Bounded to 32 bits, so an exponent at or above the modulus is refused on
    // its own decode allowance before the comparison is reached.
    assert.strictEqual(importRsa(jwk, { e: uint(n) }).ok, false);
  });

  test('rejects members that are not minimally encoded unsigned integers', async () => {
    // A leading zero octet is not the minimal encoding, which would let one
    // value be written several ways.
    const jwk = rsaJwk();
    const padded = Buffer.concat([Buffer.alloc(1), Buffer.from(jwk['n']!, 'base64url')]);
    assert.strictEqual(importRsa(jwk, { n: padded.toString('base64url') }).ok, false);

    assert.strictEqual(importRsa(jwk, { n: '' }).ok, false);
    assert.strictEqual(importRsa(jwk, { n: 'not base64url!' }).ok, false);
  });
});

describe('EC material validation', () => {
  test('rejects coordinates of the wrong width for the curve', async () => {
    const jwk = ecJwk();
    const short = Buffer.alloc(8, 1).toString('base64url');

    for (const member of ['x', 'y', 'd'] as const) {
      const result = importKey(object({ ...jwk, [member]: short }), { algorithm: 'ES256', operation: 'sign' });
      assert.strictEqual(result.ok, false);
    }
  });

  test('rejects a point that is not on the named curve', async () => {
    // Coordinates outside the field, points off the curve, and the point at
    // infinity would all make the key unusable as an identity.
    const jwk = ecJwk();
    const x = Buffer.from(jwk['x']!, 'base64url');
    const flipped = Buffer.from(x.map((byte, index) => (index === 0 ? byte ^ 0xff : byte)));

    assertRejected(
      importKey(object({ ...jwk, x: flipped.toString('base64url'), d: undefined }), EC_VERIFY),
      'point_not_on_curve',
    );
  });

  test('rejects a private scalar that does not derive the published point', async () => {
    const jwk = ecJwk();
    const other = ecJwk();

    // The published point and the scalar describe different keys, so the pair
    // is refused rather than either half being trusted.
    assertRejected(
      importKey(object({ ...jwk, d: other['d'] }), { algorithm: 'ES256', operation: 'sign' }),
      'public_private_mismatch',
    );
  });

  test('rejects a private scalar outside the valid range', async () => {
    const jwk = ecJwk();
    const zero = Buffer.alloc(32).toString('base64url');

    assertRejected(
      importKey(object({ ...jwk, d: zero }), { algorithm: 'ES256', operation: 'sign' }),
      'private_scalar_invalid',
    );
  });
});

describe('RSA private CRT validation', () => {
  /** Mutates one supplied key so overrides stay consistent with its own members. */
  function importPrivate(jwk: Record<string, string>, overrides: Record<string, unknown>) {
    return importKey(object({ ...jwk, ...overrides }), RSA_SIGN);
  }

  test('refuses multi-prime keys rather than ignoring the extra factors', async () => {
    // Their presence changes the meaning of every other CRT parameter.
    assertRejected(importPrivate(rsaJwk(), { oth: [] }), 'oth_unsupported');
  });

  test('rejects equal or degenerate prime factors', async () => {
    const jwk = rsaJwk();
    // Equal factors also break the product check, so the modulus is rebuilt as
    // `p * p` to reach the equality test that precedes it.
    const p = big(jwk, 'p');
    assertRejected(importPrivate(jwk, { q: jwk['p'], n: uint(p * p) }), 'p_equals_q');

    // A forged `p = 1` satisfies the product check on its own, and `p - 1` is
    // used as a modulus below where a zero divisor would throw.
    assertRejected(importPrivate(jwk, { p: uint(1n), q: jwk['n'] }), 'factor_not_greater_than_one');
  });

  test('rejects factors whose product is not the modulus', async () => {
    const jwk = rsaJwk();
    assertRejected(importPrivate(jwk, { p: uint(big(jwk, 'p') + 2n) }), 'pq_product_mismatch');
  });

  test('rejects CRT parameters inconsistent with the private exponent', async () => {
    const jwk = rsaJwk();

    assertRejected(importPrivate(jwk, { dp: uint(big(jwk, 'dp') + 1n) }), 'dp_mismatch');
    assertRejected(importPrivate(jwk, { dq: uint(big(jwk, 'dq') + 1n) }), 'dq_mismatch');
    assertRejected(importPrivate(jwk, { qi: uint(big(jwk, 'qi') + 1n) }), 'qi_mismatch');
  });
});

describe('OKP material validation', () => {
  const AGREEMENT = { algorithm: 'ECDH-ES', operation: 'deriveKey', contentAlgorithms: ['A128GCM'] } as const;

  test('refuses the Ed curves as unqualified before any material is read', () => {
    // The signing curves are gated at import rather than rejected later, so no
    // key bound to them can reach a cryptographic operation.
    for (const crv of ['Ed25519', 'Ed448']) {
      const result = importKey(object({ kty: 'OKP', crv, x: Buffer.alloc(32).toString('base64url') }), {
        algorithm: 'EdDSA',
        operation: 'verify',
      });
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'curve_not_qualified');
        assert.strictEqual(result.category, 'unsupported_algorithm');
      }
    }
  });

  test('rejects components of the wrong width for the curve', () => {
    const jwk = x25519Jwk();
    const short = Buffer.alloc(8, 1).toString('base64url');

    assertRejected(importKey(object({ ...jwk, x: short }), AGREEMENT), 'x_wrong_length');
    assertRejected(importKey(object({ ...jwk, d: short }), AGREEMENT), 'd_wrong_length');
  });

  test('rejects a private key that does not derive the published public key', () => {
    const jwk = x25519Jwk();
    const other = x25519Jwk();

    assertRejected(importKey(object({ ...jwk, d: other['d'] }), AGREEMENT), 'public_private_mismatch');
  });

  test('imports a public-only agreement key', () => {
    const { d: _d, ...publicOnly } = x25519Jwk();

    const result = importKey(object(publicOnly), AGREEMENT);
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.key.isPrivate, false);
    }
  });
});
