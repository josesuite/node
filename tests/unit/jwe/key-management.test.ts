import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { contentEncryptionShape } from '../../../src/algorithms/content-encryption/index.ts';
import {
  aesKwKeySize,
  defaultIntegrityValue,
  KW_OVERHEAD_BYTES,
  unwrapAesKw,
  wrapAesKw,
} from '../../../src/algorithms/jwe/aes-kw.ts';
import { concatKdf } from '../../../src/algorithms/jwe/concat-kdf.ts';
import { directCek } from '../../../src/algorithms/jwe/direct.ts';
import {
  agree,
  agreementFieldBytes,
  generateEphemeralEc,
  generateEphemeralOkp,
  isAgreementCurve,
} from '../../../src/algorithms/jwe/ecdh-es.ts';
import { decryptRsaOaep, encryptRsaOaep, oaepHash } from '../../../src/algorithms/jwe/rsaes-oaep.ts';
import type { EcMaterial, OkpMaterial, RsaPrivateMaterial } from '../../../src/key/validation.ts';
import { flipBit, supportsCurve } from '../../helpers/runtime.ts';

const b64u = (value: unknown) => new Uint8Array(Buffer.from(String(value), 'base64url'));

describe('direct key agreement', () => {
  test('accepts a key of the exact size the content algorithm requires', () => {
    for (const algorithm of ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512']) {
      const size = contentEncryptionShape(algorithm)!.cekBytes;
      const configured = new Uint8Array(randomBytes(size));

      const result = directCek(algorithm, configured);
      assert.strictEqual(result.ok, true);
      if (result.ok) {
        assert.deepStrictEqual(result.cek, configured);
      }
    }
  });

  test('refuses a key that is not the exact size', () => {
    // Padding or truncating would let one configured key serve several `enc`
    // values, reusing material across constructions.
    const shape = contentEncryptionShape('A128GCM')!;

    for (const size of [shape.cekBytes - 1, shape.cekBytes + 1, 0, 32]) {
      const result = directCek('A128GCM', new Uint8Array(size));
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, 'key_size_mismatch');
      }
    }
  });

  test('refuses an unknown content algorithm', () => {
    const result = directCek('A128CBC', new Uint8Array(32));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'unsupported_enc');
    }
  });
});

describe('AES key wrapping', () => {
  const ALGORITHMS = ['A128KW', 'A192KW', 'A256KW'] as const;

  test('requires the exact KEK size per identifier', () => {
    assert.strictEqual(aesKwKeySize('A128KW'), 16);
    assert.strictEqual(aesKwKeySize('A192KW'), 24);
    assert.strictEqual(aesKwKeySize('A256KW'), 32);
    assert.strictEqual(aesKwKeySize('A128GCMKW'), undefined);
  });

  test('uses the specified default integrity value', () => {
    assert.deepStrictEqual([...defaultIntegrityValue()], [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);
  });

  test('matches the published RFC 3394 vectors', async () => {
    // A round trip only proves this agrees with itself. These published vectors
    // are what establish the wrapped bytes interoperate, and they would catch a
    // substituted padded variant or a different initial value.
    const vectors: readonly [string, string, string, string][] = [
      [
        'A128KW',
        '000102030405060708090A0B0C0D0E0F',
        '00112233445566778899AABBCCDDEEFF',
        '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5',
      ],
      [
        'A192KW',
        '000102030405060708090A0B0C0D0E0F1011121314151617',
        '00112233445566778899AABBCCDDEEFF',
        '96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D',
      ],
      [
        'A256KW',
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        '00112233445566778899AABBCCDDEEFF',
        '64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7',
      ],
      [
        'A256KW',
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
        '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21',
      ],
    ];

    for (const [algorithm, kekHex, cekHex, expectedHex] of vectors) {
      const kek = new Uint8Array(Buffer.from(kekHex, 'hex'));
      const cek = new Uint8Array(Buffer.from(cekHex, 'hex'));

      const wrapped = await wrapAesKw(algorithm, kek, cek);
      assert.strictEqual(wrapped.ok, true);
      if (wrapped.ok) {
        assert.strictEqual(Buffer.from(wrapped.value).toString('hex').toUpperCase(), expectedHex);
      }

      const unwrapped = await unwrapAesKw(algorithm, kek, new Uint8Array(Buffer.from(expectedHex, 'hex')));
      assert.strictEqual(unwrapped.ok, true);
      if (unwrapped.ok) {
        assert.deepStrictEqual(unwrapped.value, cek);
      }
    }
  });

  for (const algorithm of ALGORITHMS) {
    test(`${algorithm} round-trips a CEK`, async () => {
      const kek = new Uint8Array(randomBytes(aesKwKeySize(algorithm)!));
      const cek = new Uint8Array(randomBytes(32));

      const wrapped = await wrapAesKw(algorithm, kek, cek);
      assert.strictEqual(wrapped.ok, true);
      if (!wrapped.ok) {
        return;
      }
      assert.strictEqual(wrapped.value.length, cek.length + KW_OVERHEAD_BYTES);

      const unwrapped = await unwrapAesKw(algorithm, kek, wrapped.value);
      assert.strictEqual(unwrapped.ok, true);
      if (unwrapped.ok) {
        assert.deepStrictEqual(unwrapped.value, cek);
      }
    });

    test(`${algorithm} rejects a wrong KEK without releasing key material`, async () => {
      const kek = new Uint8Array(randomBytes(aesKwKeySize(algorithm)!));
      const other = new Uint8Array(randomBytes(aesKwKeySize(algorithm)!));
      const wrapped = await wrapAesKw(algorithm, kek, new Uint8Array(randomBytes(32)));
      if (!wrapped.ok) {
        throw new Error('wrap failed');
      }

      const unwrapped = await unwrapAesKw(algorithm, other, wrapped.value);
      // The integrity check is what catches this, and it is an authentication
      // outcome rather than a provider fault.
      assert.strictEqual(unwrapped.ok, true);
      if (unwrapped.ok) {
        assert.strictEqual(unwrapped.value, undefined);
      }
    });

    test(`${algorithm} rejects modified wrapped bytes`, async () => {
      const kek = new Uint8Array(randomBytes(aesKwKeySize(algorithm)!));
      const wrapped = await wrapAesKw(algorithm, kek, new Uint8Array(randomBytes(32)));
      if (!wrapped.ok) {
        throw new Error('wrap failed');
      }

      for (const index of [0, 8, wrapped.value.length - 1]) {
        const modified = flipBit(wrapped.value, index);

        const unwrapped = await unwrapAesKw(algorithm, kek, modified);
        assert.strictEqual(unwrapped.ok, true);
        if (unwrapped.ok) {
          assert.strictEqual(unwrapped.value, undefined);
        }
      }
    });

    test(`${algorithm} refuses a wrong-size KEK`, async () => {
      const size = aesKwKeySize(algorithm)!;
      const cek = new Uint8Array(32);

      for (const wrong of [size - 1, size + 1]) {
        const result = await wrapAesKw(algorithm, new Uint8Array(wrong), cek);
        assert.strictEqual(result.ok, false);
        if (!result.ok) {
          assert.strictEqual(result.failure, 'operation_failed');
        }
      }
    });
  }

  test('wraps every CEK size the content algorithms use', async () => {
    const kek = new Uint8Array(randomBytes(32));

    for (const enc of ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512']) {
      const size = contentEncryptionShape(enc)!.cekBytes;
      const wrapped = await wrapAesKw('A256KW', kek, new Uint8Array(randomBytes(size)));

      assert.strictEqual(wrapped.ok, true);
      if (wrapped.ok) {
        assert.strictEqual(wrapped.value.length, size + KW_OVERHEAD_BYTES);
      }
    }
  });

  test('refuses a CEK that is not whole 64-bit blocks', async () => {
    const kek = new Uint8Array(randomBytes(32));

    for (const size of [0, 8, 15, 17, 20]) {
      const result = await wrapAesKw('A256KW', kek, new Uint8Array(size));
      assert.strictEqual(result.ok, false);
    }
  });

  test('rejects a wrapped value that is too short to be genuine', async () => {
    const kek = new Uint8Array(randomBytes(32));

    for (const size of [0, 8, 16, 23, 25]) {
      const result = await unwrapAesKw('A256KW', kek, new Uint8Array(size));
      assert.strictEqual(result.ok, true);
      if (result.ok) {
        assert.strictEqual(result.value, undefined);
      }
    }
  });

  test('reports an unsupported identifier separately from a failed unwrap', async () => {
    const result = await unwrapAesKw('A128GCMKW', new Uint8Array(16), new Uint8Array(40));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'unsupported');
    }
  });
});

describe('RSAES-OAEP', () => {
  function rsaMaterial(): RsaPrivateMaterial {
    const generated = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = generated.privateKey.export({ format: 'jwk' });
    return {
      n: b64u(jwk.n),
      e: b64u(jwk.e),
      d: b64u(jwk.d),
      p: b64u(jwk.p),
      q: b64u(jwk.q),
      dp: b64u(jwk.dp),
      dq: b64u(jwk.dq),
      qi: b64u(jwk.qi),
      modulusBits: 2048,
    };
  }

  test('fixes the hash from the identifier', () => {
    assert.strictEqual(oaepHash('RSA-OAEP-256'), 'SHA-256');
    // The SHA-1 variant is receive-only, which the registry enforces; here only
    // the hash binding is asserted.
    assert.strictEqual(oaepHash('RSA-OAEP'), 'SHA-1');
    assert.strictEqual(oaepHash('RSA-OAEP-384'), undefined);
    assert.strictEqual(oaepHash('RSA1_5'), undefined);
  });

  test('round-trips a CEK under RSA-OAEP-256', async () => {
    const key = rsaMaterial();
    const cek = new Uint8Array(randomBytes(32));

    const encrypted = await encryptRsaOaep('RSA-OAEP-256', key, cek);
    assert.strictEqual(encrypted.ok, true);
    if (!encrypted.ok) {
      return;
    }
    // The ciphertext is exactly one modulus wide.
    assert.strictEqual(encrypted.value.length, key.n.length);

    const decrypted = await decryptRsaOaep('RSA-OAEP-256', key, encrypted.value);
    assert.strictEqual(decrypted.ok, true);
    if (decrypted.ok) {
      assert.deepStrictEqual(decrypted.value, cek);
    }
  });

  test('does not decrypt under a different key', async () => {
    const key = rsaMaterial();
    const other = rsaMaterial();
    const encrypted = await encryptRsaOaep('RSA-OAEP-256', key, new Uint8Array(randomBytes(32)));
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const decrypted = await decryptRsaOaep('RSA-OAEP-256', other, encrypted.value);
    assert.strictEqual(decrypted.ok, true);
    if (decrypted.ok) {
      assert.strictEqual(decrypted.value, undefined);
    }
  });

  test('does not decrypt under the other hash', async () => {
    // The hash is part of the construction, so an object encrypted under
    // SHA-256 must not open under the SHA-1 variant.
    const key = rsaMaterial();
    const encrypted = await encryptRsaOaep('RSA-OAEP-256', key, new Uint8Array(randomBytes(32)));
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const decrypted = await decryptRsaOaep('RSA-OAEP', key, encrypted.value);
    assert.strictEqual(decrypted.ok, true);
    if (decrypted.ok) {
      assert.strictEqual(decrypted.value, undefined);
    }
  });

  test('reports a modified ciphertext as a failed recovery, not an error', async () => {
    // OAEP decoding failures must be indistinguishable from a wrong key:
    // separating them is what enabled adaptive ciphertext attacks.
    const key = rsaMaterial();
    const encrypted = await encryptRsaOaep('RSA-OAEP-256', key, new Uint8Array(randomBytes(32)));
    if (!encrypted.ok) {
      throw new Error('encrypt failed');
    }

    const modified = flipBit(encrypted.value, encrypted.value.length - 1);

    const decrypted = await decryptRsaOaep('RSA-OAEP-256', key, modified);
    assert.strictEqual(decrypted.ok, true);
    if (decrypted.ok) {
      assert.strictEqual(decrypted.value, undefined);
    }
  });

  test('rejects a ciphertext that is not modulus-sized', async () => {
    const key = rsaMaterial();

    for (const length of [key.n.length - 1, key.n.length + 1, 0]) {
      const decrypted = await decryptRsaOaep('RSA-OAEP-256', key, new Uint8Array(length));
      assert.strictEqual(decrypted.ok, true);
      if (decrypted.ok) {
        assert.strictEqual(decrypted.value, undefined);
      }
    }
  });

  test('reports an unspecified identifier as unsupported', async () => {
    const key = rsaMaterial();
    const result = await encryptRsaOaep('RSA-OAEP-512', key, new Uint8Array(32));

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.failure, 'unsupported');
    }
  });
});

describe('ECDH-ES agreement', () => {
  const EC_CURVES = ['P-256', 'P-384', 'P-521'] as const;
  const XDH_CURVES = (['X25519', 'X448'] as const).filter(supportsCurve);

  function ecMaterial(curve: string): EcMaterial {
    const generated = generateKeyPairSync('ec', {
      namedCurve: { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' }[curve]!,
    });
    const jwk = generated.privateKey.export({ format: 'jwk' });
    return { curve: curve as EcMaterial['curve'], x: b64u(jwk.x), y: b64u(jwk.y), d: b64u(jwk.d) };
  }

  function okpMaterial(curve: string): OkpMaterial {
    const generated = generateKeyPairSync(curve.toLowerCase() as 'x25519');
    const jwk = generated.privateKey.export({ format: 'jwk' });
    return { curve: curve as OkpMaterial['curve'], x: b64u(jwk.x), d: b64u(jwk.d) };
  }

  test('recognises only agreement curves', () => {
    for (const curve of ['P-256', 'P-384', 'P-521', 'X25519', 'X448']) {
      assert.strictEqual(isAgreementCurve(curve), true);
    }
    // Signing curves are never silently reused for agreement.
    for (const curve of ['Ed25519', 'Ed448', 'secp256k1']) {
      assert.strictEqual(isAgreementCurve(curve), false);
    }
  });

  for (const curve of EC_CURVES) {
    test(`${curve} produces the same secret for both parties`, async () => {
      const recipient = ecMaterial(curve);
      const ephemeral = await generateEphemeralEc(curve);
      assert.strictEqual(ephemeral.ok, true);
      if (!ephemeral.ok) {
        return;
      }

      const senderSide = await agree(
        { curve, x: ephemeral.value.x, y: ephemeral.value.y, d: ephemeral.value.d } as EcMaterial,
        { curve, x: recipient.x, y: recipient.y },
      );
      const recipientSide = await agree(recipient, { curve, x: ephemeral.value.x, y: ephemeral.value.y });

      assert.strictEqual(senderSide.ok && recipientSide.ok, true);
      if (senderSide.ok && recipientSide.ok) {
        assert.deepStrictEqual(senderSide.value, recipientSide.value);
        assert.strictEqual(senderSide.value.length, agreementFieldBytes(curve)!);
      }
    });

    test(`${curve} generates a fresh ephemeral key each time`, async () => {
      // A reused ephemeral key would derive one CEK for every message, which is
      // the failure the ephemeral half exists to prevent.
      const first = await generateEphemeralEc(curve);
      const second = await generateEphemeralEc(curve);

      assert.strictEqual(first.ok && second.ok, true);
      if (first.ok && second.ok) {
        assert.notDeepStrictEqual(first.value.d, second.value.d);
        assert.notDeepStrictEqual(first.value.x, second.value.x);
      }
    });

    test(`${curve} rejects an off-curve peer point`, async () => {
      const recipient = ecMaterial(curve);
      const offCurve = flipBit(recipient.x, 0, 0xff);

      const result = await agree(recipient, { curve, x: offCurve, y: recipient.y });
      assert.strictEqual(result.ok, false);
    });

    test(`${curve} refuses to agree across curves`, async () => {
      const recipient = ecMaterial(curve);
      const other = curve === 'P-256' ? 'P-384' : 'P-256';
      const peer = ecMaterial(other);

      const result = await agree(recipient, { curve: other, x: peer.x, y: peer.y });
      assert.strictEqual(result.ok, false);
    });
  }

  for (const curve of XDH_CURVES) {
    test(`${curve} produces the same secret for both parties`, async () => {
      const recipient = okpMaterial(curve);
      const ephemeral = await generateEphemeralOkp(curve);
      assert.strictEqual(ephemeral.ok, true);
      if (!ephemeral.ok) {
        return;
      }

      const senderSide = await agree({ curve, x: ephemeral.value.x, d: ephemeral.value.d } as OkpMaterial, {
        curve,
        x: recipient.x,
      });
      const recipientSide = await agree(recipient, { curve, x: ephemeral.value.x });

      assert.strictEqual(senderSide.ok && recipientSide.ok, true);
      if (senderSide.ok && recipientSide.ok) {
        assert.deepStrictEqual(senderSide.value, recipientSide.value);
        assert.strictEqual(senderSide.value.length, agreementFieldBytes(curve)!);
      }
    });

    test(`${curve} rejects an all-zero agreement result`, async () => {
      // A low-order peer point forces the same secret regardless of the private
      // key, letting anyone derive the CEK.
      const recipient = okpMaterial(curve);
      const lowOrder = new Uint8Array(recipient.x.length);

      const result = await agree(recipient, { curve, x: lowOrder });
      assert.strictEqual(result.ok, false);
    });
  }

  test('refuses to agree with a public-only key', async () => {
    const recipient = ecMaterial('P-256');
    const publicOnly: EcMaterial = { ...recipient, d: undefined };

    const result = await agree(publicOnly, { curve: 'P-256', x: recipient.x, y: recipient.y });
    assert.strictEqual(result.ok, false);
  });

  test('refuses an EC peer point missing its Y coordinate', async () => {
    const recipient = ecMaterial('P-256');

    const result = await agree(recipient, { curve: 'P-256', x: recipient.x });
    assert.strictEqual(result.ok, false);
  });

  test('derives different CEKs for direct and wrapped agreement', async () => {
    // Direct mode feeds `enc` to the KDF and wrapped mode feeds `alg`, so the
    // same agreement must not produce the same key for both.
    const recipient = ecMaterial('P-256');
    const ephemeral = await generateEphemeralEc('P-256');
    if (!ephemeral.ok) {
      throw new Error('generate failed');
    }

    const secret = await agree(recipient, { curve: 'P-256', x: ephemeral.value.x, y: ephemeral.value.y });
    if (!secret.ok) {
      throw new Error('agree failed');
    }

    const encoder = new TextEncoder();
    const empty = new Uint8Array(0);
    const direct = concatKdf(secret.value, {
      algorithmId: encoder.encode('A128GCM'),
      partyUInfo: empty,
      partyVInfo: empty,
      keyBytes: 16,
    });
    const wrapped = concatKdf(secret.value, {
      algorithmId: encoder.encode('ECDH-ES+A128KW'),
      partyUInfo: empty,
      partyVInfo: empty,
      keyBytes: 16,
    });

    assert.notDeepStrictEqual(direct, wrapped);
  });
});
