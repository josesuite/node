import { describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';

import {
  GCMKW_IV_BYTES,
  GCMKW_TAG_BYTES,
  gcmKwKeySize,
  unwrapGcmKw,
  wrapGcmKw,
} from '../../../src/algorithms/jwe/aes-gcm-kw.ts';
import { keyManagementShape } from '../../../src/algorithms/jwe/index.ts';
import { flipBit } from '../../helpers/runtime.ts';

const ALGORITHMS = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'] as const;

function materials(algorithm: string) {
  return {
    kek: new Uint8Array(randomBytes(gcmKwKeySize(algorithm)!)),
    iv: new Uint8Array(randomBytes(GCMKW_IV_BYTES)),
    cek: new Uint8Array(randomBytes(32)),
  };
}

describe('parameters', () => {
  test('fixes the KEK size from the identifier', () => {
    expect(gcmKwKeySize('A128GCMKW')).toBe(16);
    expect(gcmKwKeySize('A192GCMKW')).toBe(24);
    expect(gcmKwKeySize('A256GCMKW')).toBe(32);
    expect(gcmKwKeySize('A128KW')).toBeUndefined();
  });

  test('uses a 12-octet wrapping IV and a 16-octet wrapping tag', () => {
    expect(GCMKW_IV_BYTES).toBe(12);
    expect(GCMKW_TAG_BYTES).toBe(16);
  });

  test('is registered as a wrapping mode carrying an encrypted key', () => {
    for (const algorithm of ALGORITHMS) {
      const shape = keyManagementShape(algorithm);
      expect(shape?.mode).toBe('gcm_wrapping');
      expect(shape?.carriesEncryptedKey).toBe(true);
      // Several recipients may each wrap the one common CEK.
      expect(shape?.singleRecipientOnly).toBe(false);
    }
  });
});

describe('round trips', () => {
  for (const algorithm of ALGORITHMS) {
    test(`${algorithm} recovers the CEK`, async () => {
      const { kek, iv, cek } = materials(algorithm);

      const wrapped = await wrapGcmKw(algorithm, kek, iv, cek);
      expect(wrapped.ok).toBe(true);
      if (!wrapped.ok) {
        return;
      }

      // The wrapped key is the same length as the CEK; the tag travels apart.
      expect(wrapped.value.encryptedKey.length).toBe(cek.length);
      expect(wrapped.value.tag.length).toBe(GCMKW_TAG_BYTES);
      expect(wrapped.value.iv).toEqual(iv);

      const unwrapped = await unwrapGcmKw(
        algorithm,
        kek,
        wrapped.value.iv,
        wrapped.value.encryptedKey,
        wrapped.value.tag,
      );
      expect(unwrapped.ok).toBe(true);
      if (unwrapped.ok) {
        expect(unwrapped.value).toEqual(cek);
      }
    });
  }

  test('wraps every CEK size the content algorithms use', async () => {
    const kek = new Uint8Array(randomBytes(32));

    for (const size of [16, 24, 32, 48, 64]) {
      const iv = new Uint8Array(randomBytes(GCMKW_IV_BYTES));
      const cek = new Uint8Array(randomBytes(size));

      const wrapped = await wrapGcmKw('A256GCMKW', kek, iv, cek);
      expect(wrapped.ok).toBe(true);
      if (!wrapped.ok) {
        continue;
      }

      const unwrapped = await unwrapGcmKw('A256GCMKW', kek, iv, wrapped.value.encryptedKey, wrapped.value.tag);
      expect(unwrapped.ok).toBe(true);
      if (unwrapped.ok) {
        expect(unwrapped.value).toEqual(cek);
      }
    }
  });
});

describe('authentication failures', () => {
  async function wrapped() {
    const { kek, iv, cek } = materials('A256GCMKW');
    const result = await wrapGcmKw('A256GCMKW', kek, iv, cek);
    if (!result.ok) {
      throw new Error('wrap failed');
    }
    return { kek, cek, ...result.value };
  }

  test('rejects a wrong KEK', async () => {
    const { iv, encryptedKey, tag } = await wrapped();
    const other = new Uint8Array(randomBytes(32));

    const result = await unwrapGcmKw('A256GCMKW', other, iv, encryptedKey, tag);
    // A failed tag is an authentication outcome, never a provider fault.
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBeUndefined();
    }
  });

  test('rejects a modified wrapped key', async () => {
    const { kek, iv, encryptedKey, tag } = await wrapped();
    const modified = flipBit(encryptedKey);

    const result = await unwrapGcmKw('A256GCMKW', kek, iv, modified, tag);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBeUndefined();
    }
  });

  test('rejects a modified wrapping tag', async () => {
    const { kek, iv, encryptedKey, tag } = await wrapped();
    const modified = flipBit(tag);

    const result = await unwrapGcmKw('A256GCMKW', kek, iv, encryptedKey, modified);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBeUndefined();
    }
  });

  test('rejects a wrong wrapping IV', async () => {
    const { kek, encryptedKey, tag } = await wrapped();
    const other = new Uint8Array(randomBytes(GCMKW_IV_BYTES));

    const result = await unwrapGcmKw('A256GCMKW', kek, other, encryptedKey, tag);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBeUndefined();
    }
  });

  test('rejects wrapping parameters of the wrong width', async () => {
    const { kek, iv, encryptedKey, tag } = await wrapped();

    const shortIv = await unwrapGcmKw('A256GCMKW', kek, iv.subarray(0, 8), encryptedKey, tag);
    expect(shortIv.ok && shortIv.value === undefined).toBe(true);

    const shortTag = await unwrapGcmKw('A256GCMKW', kek, iv, encryptedKey, tag.subarray(0, 8));
    expect(shortTag.ok && shortTag.value === undefined).toBe(true);
  });
});

describe('size enforcement', () => {
  test('refuses a wrong-size KEK', async () => {
    const iv = new Uint8Array(GCMKW_IV_BYTES);
    const cek = new Uint8Array(32);

    for (const size of [15, 17, 0]) {
      const result = await wrapGcmKw('A128GCMKW', new Uint8Array(size), iv, cek);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure).toBe('operation_failed');
      }
    }
  });

  test('refuses a wrapping IV that is not 12 octets', async () => {
    // A provider given an odd-length nonce applies its own derivation, which
    // would produce a value outside the uniqueness argument made for it.
    const kek = new Uint8Array(32);
    const cek = new Uint8Array(32);

    for (const size of [8, 11, 13, 16]) {
      const result = await wrapGcmKw('A256GCMKW', kek, new Uint8Array(size), cek);
      expect(result.ok).toBe(false);
    }
  });

  test('reports an unsupported identifier separately from a failed unwrap', async () => {
    const result = await unwrapGcmKw(
      'A128KW',
      new Uint8Array(16),
      new Uint8Array(12),
      new Uint8Array(32),
      new Uint8Array(16),
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('unsupported');
    }
  });
});

describe('nonce reuse consequence', () => {
  test('one wrapping nonce used twice leaks the CEK difference', async () => {
    // This is the failure the separate key-scoped allocation exists to prevent,
    // asserted so the consequence is recorded rather than assumed.
    const kek = new Uint8Array(randomBytes(32));
    const iv = new Uint8Array(randomBytes(GCMKW_IV_BYTES));
    const first = new Uint8Array(randomBytes(32));
    const second = new Uint8Array(randomBytes(32));

    const a = await wrapGcmKw('A256GCMKW', kek, iv, first);
    const b = await wrapGcmKw('A256GCMKW', kek, iv, second);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) {
      return;
    }

    for (let i = 0; i < first.length; i += 1) {
      expect(a.value.encryptedKey[i]! ^ b.value.encryptedKey[i]!).toBe(first[i]! ^ second[i]!);
    }
  });
});
