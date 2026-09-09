import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { constants, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

import { constantTime } from '../../../src/internal/crypto/constant-time.ts';
import { deriveEcPublicPoint, deriveOkpPublicKey, validateEcPointOnCurve } from '../../../src/internal/crypto/node.ts';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { availableCurves } from '../../helpers/runtime.ts';

const EC_CURVES = availableCurves(['P-256', 'P-384', 'P-521', 'secp256k1']);
const OKP_CURVES = availableCurves(['Ed25519', 'Ed448', 'X25519', 'X448']);

/**
 * These tests record the cryptographic provider's actual behaviour. They are
 * the evidence for which validation this library must perform itself, so a
 * provider upgrade that changes any of it fails here rather than silently
 * altering which keys are accepted.
 */

function b64u(bytes: Uint8Array | Buffer): string {
  return Buffer.from(bytes).toString('base64url');
}

describe('provider gaps this library compensates for', () => {
  test('accepts an RSA private JWK whose CRT parameters are inconsistent', () => {
    const jwk = generateKeyPairSync('rsa', { modulusLength: 3072 }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;

    const qi = Buffer.from(jwk['qi']!, 'base64url');
    qi[qi.length - 1] = qi[qi.length - 1]! ^ 0x01;

    // The provider imports it and signs with it, so the inconsistency has to be
    // caught by this library's own arithmetic checks.
    assert.doesNotThrow(() => createPrivateKey({ key: { ...jwk, qi: b64u(qi) }, format: 'jwk' }));
  });

  test('echoes supplied EC coordinates instead of deriving them from d', () => {
    const a = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;
    const b = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;

    const mixed = createPrivateKey({
      key: { kty: 'EC', crv: 'P-256', x: b['x']!, y: b['y']!, d: a['d']! },
      format: 'jwk',
    });
    const exported = createPublicKey(mixed).export({ format: 'jwk' });

    // The export returns the foreign coordinates, so a round trip proves
    // nothing about consistency; scalar multiplication is used instead.
    assert.strictEqual(exported.x, b['x']!);
    assert.notStrictEqual(exported.x, a['x']!);
  });

  test('accepts an X25519 private JWK whose public component does not match d', () => {
    const a = generateKeyPairSync('x25519').privateKey.export({ format: 'jwk' }) as Record<string, string>;
    const b = generateKeyPairSync('x25519').privateKey.export({ format: 'jwk' }) as Record<string, string>;

    assert.doesNotThrow(() => createPrivateKey({ key: { ...a, x: b['x']! }, format: 'jwk' }));
  });
});

describe('provider capabilities this library relies on', () => {
  test('rejects off-curve EC coordinates at import', () => {
    const result = validateEcPointOnCurve('P-256', {
      x: new Uint8Array(32).fill(9),
      y: new Uint8Array(32).fill(9),
    });
    assert.strictEqual(result.ok, false);
  });

  test('accepts a genuine point on each curve this runtime provides', () => {
    for (const curve of EC_CURVES) {
      const jwk = generateKeyPairSync('ec', { namedCurve: curve }).publicKey.export({
        format: 'jwk',
      }) as Record<string, string>;

      const result = validateEcPointOnCurve(curve, {
        x: new Uint8Array(Buffer.from(jwk['x']!, 'base64url')),
        y: new Uint8Array(Buffer.from(jwk['y']!, 'base64url')),
      });
      assert.strictEqual(result.ok, true);
    }
  });

  test('derives EC public points from the private scalar alone', () => {
    for (const curve of EC_CURVES) {
      const jwk = generateKeyPairSync('ec', { namedCurve: curve }).privateKey.export({
        format: 'jwk',
      }) as Record<string, string>;

      const derived = deriveEcPublicPoint(curve, new Uint8Array(Buffer.from(jwk['d']!, 'base64url')));
      assert.strictEqual(derived.ok, true);
      if (derived.ok) {
        assert.strictEqual(b64u(derived.value.x), jwk['x']!);
        assert.strictEqual(b64u(derived.value.y), jwk['y']!);
      }
    }
  });

  test('derivation ignores any supplied coordinates, detecting a mismatch', () => {
    const a = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;
    const b = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;

    const derived = deriveEcPublicPoint('P-256', new Uint8Array(Buffer.from(a['d']!, 'base64url')));
    assert.strictEqual(derived.ok, true);
    if (derived.ok) {
      assert.notStrictEqual(b64u(derived.value.x), b['x']!);
    }
  });

  test('rejects an out-of-range EC private scalar', () => {
    assert.strictEqual(deriveEcPublicPoint('P-256', new Uint8Array(32)).ok, false);
  });

  test('reports an unsupported curve rather than guessing', () => {
    const result = deriveEcPublicPoint('P-192', new Uint8Array(24).fill(1));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'unsupported');
    }
  });

  test('derives OKP public keys from private material', () => {
    for (const curve of OKP_CURVES) {
      const nodeName = curve.toLowerCase();
      const jwk = generateKeyPairSync(nodeName as 'ed25519').privateKey.export({
        format: 'jwk',
      }) as Record<string, string>;

      const derived = deriveOkpPublicKey(curve, new Uint8Array(Buffer.from(jwk['d']!, 'base64url')));
      assert.strictEqual(derived.ok, true);
      if (derived.ok) {
        assert.strictEqual(b64u(derived.value), jwk['x']!);
      }
    }
  });

  test('supports fixed-width ECDSA signatures rather than only DER', () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const signature = sign('sha256', Buffer.from('m'), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    // Fixed-width R || S for P-256 is exactly 64 octets; a DER form would vary.
    assert.strictEqual(signature.length, 64);
  });

  test('supports an explicit PSS salt length and rejects a wrong one', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
    const options = {
      key: privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    };
    const signature = sign('sha256', Buffer.from('m'), options);

    assert.strictEqual(verify('sha256', Buffer.from('m'), options, signature), true);
    // An explicit length is required because the provider's automatic mode
    // would also accept salt lengths this profile does not permit.
    assert.strictEqual(verify('sha256', Buffer.from('m'), { ...options, saltLength: 48 }, signature), false);
  });
});

describe('runtime curve inventory', () => {
  test('provides every currently qualified required curve', () => {
    assert.ok(EC_CURVES.includes('P-256'));
  });
});

describe('randomness', () => {
  test('returns the requested length and varies between calls', () => {
    const first = systemRandom.randomBytes(32);
    const second = systemRandom.randomBytes(32);
    assert.strictEqual(first.ok && second.ok, true);
    if (first.ok && second.ok) {
      assert.strictEqual(first.value.length, 32);
      assert.strictEqual(Buffer.from(first.value).equals(Buffer.from(second.value)), false);
    }
  });

  test('accepts a zero-length request and rejects invalid lengths', () => {
    assert.strictEqual(systemRandom.randomBytes(0).ok, true);
    assert.strictEqual(systemRandom.randomBytes(-1).ok, false);
    assert.strictEqual(systemRandom.randomBytes(1.5).ok, false);
  });
});

describe('constant-time comparison', () => {
  test('compares equal and unequal values of the same length', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    assert.strictEqual(constantTime.equal(a, new Uint8Array([1, 2, 3, 4])), true);
    assert.strictEqual(constantTime.equal(a, new Uint8Array([1, 2, 3, 5])), false);
    // Differing in the first byte must behave the same as differing in the last.
    assert.strictEqual(constantTime.equal(a, new Uint8Array([9, 2, 3, 4])), false);
  });

  test('returns false for different lengths instead of throwing', () => {
    assert.strictEqual(constantTime.equal(new Uint8Array([1]), new Uint8Array([1, 2])), false);
    assert.strictEqual(constantTime.equal(new Uint8Array(), new Uint8Array([1])), false);
    assert.strictEqual(constantTime.equal(new Uint8Array(), new Uint8Array()), true);
  });
});

describe('WebCrypto backend selection', () => {
  test('rejects the mismatched EC private key the native module accepts', async () => {
    // This is the property that motivates preferring WebCrypto: the native
    // module imports this key and echoes the attacker-supplied coordinates back
    // on export, while WebCrypto refuses it outright.
    const a = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;
    const b = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;

    const mismatched = { kty: 'EC', crv: 'P-256', x: b['x']!, y: b['y']!, d: a['d']! };

    assert.doesNotThrow(() => createPrivateKey({ key: mismatched, format: 'jwk' }));

    await assert.rejects(
      crypto.subtle.importKey('jwk', mismatched, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']),
    );
  });

  test('produces ECDSA signatures in the fixed-width JOSE form', async () => {
    // No DER conversion step exists in this path, so the wire encoding cannot
    // be got wrong by a faulty converter.
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      new Uint8Array([1, 2, 3, 4]),
    );

    assert.strictEqual(signature.byteLength, 64);
  });

  test('accepts an undersized HMAC key, so the length bound is enforced here', async () => {
    // The provider imposes no minimum, which is why `computeHmac` checks the
    // key against the hash output size before signing.
    const key = await crypto.subtle.importKey('raw', new Uint8Array(8), { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
    ]);

    assert.notStrictEqual(key, undefined);
  });

  test('rejects a private key handed to a public-only operation', async () => {
    // Usages are bound to what the key contains, which is why public operations
    // build a JWK carrying only `n` and `e`.
    const jwk = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
      format: 'jwk',
    }) as Record<string, string>;

    await assert.rejects(
      crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']),
    );
  });
});
