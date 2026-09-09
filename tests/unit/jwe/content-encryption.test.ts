import { describe, expect, test } from 'bun:test';
import { createHmac, randomBytes } from 'node:crypto';

import { CBC_IV_BYTES, cbcHmacParameters } from '../../../src/algorithms/content-encryption/aes-cbc-hmac.ts';
import { GCM_IV_BYTES, GCM_TAG_BYTES } from '../../../src/algorithms/content-encryption/aes-gcm.ts';
import { contentEncryptionShape, openContent, sealContent } from '../../../src/algorithms/content-encryption/index.ts';
import { flipBit } from '../../helpers/runtime.ts';

const GCM = ['A128GCM', 'A192GCM', 'A256GCM'] as const;
const CBC = ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const;
const ALL = [...GCM, ...CBC];

const AAD = new TextEncoder().encode('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0');
const PLAINTEXT = new TextEncoder().encode('the quick brown fox');

function materials(algorithm: string) {
  const shape = contentEncryptionShape(algorithm);
  if (shape === undefined) {
    throw new Error(`unknown enc ${algorithm}`);
  }
  return {
    shape,
    cek: new Uint8Array(randomBytes(shape.cekBytes)),
    iv: new Uint8Array(randomBytes(shape.ivBytes)),
  };
}

async function seal(algorithm: string, plaintext = PLAINTEXT, aad = AAD) {
  const { cek, iv } = materials(algorithm);
  const sealed = await sealContent(algorithm, cek, iv, plaintext, aad);
  if (!sealed.ok) {
    throw new Error(`seal failed: ${sealed.failure}`);
  }
  return { cek, iv, ...sealed.value };
}

describe('algorithm shapes', () => {
  test('fixes every size from the identifier alone', () => {
    const expected: Readonly<Record<string, [number, number, number]>> = {
      A128GCM: [16, 12, 16],
      A192GCM: [24, 12, 16],
      A256GCM: [32, 12, 16],
      'A128CBC-HS256': [32, 16, 16],
      'A192CBC-HS384': [48, 16, 24],
      'A256CBC-HS512': [64, 16, 32],
    };

    for (const [algorithm, [cek, iv, tag]] of Object.entries(expected)) {
      const shape = contentEncryptionShape(algorithm);
      expect(shape).toBeDefined();
      expect(shape!.cekBytes).toBe(cek);
      expect(shape!.ivBytes).toBe(iv);
      expect(shape!.tagBytes).toBe(tag);
    }
  });

  test('marks only GCM as needing a never-repeating nonce', () => {
    // The distinction decides whether creation must hold durable allocation
    // state, so it is asserted rather than left implicit.
    for (const algorithm of GCM) {
      expect(contentEncryptionShape(algorithm)!.requiresUniqueNonce).toBe(true);
    }
    for (const algorithm of CBC) {
      expect(contentEncryptionShape(algorithm)!.requiresUniqueNonce).toBe(false);
    }
  });

  test('reports nothing for an unknown or signature identifier', () => {
    for (const algorithm of ['A128CBC', 'ES256', 'dir', 'A128GCMKW', '']) {
      expect(contentEncryptionShape(algorithm)).toBeUndefined();
    }
  });
});

describe('round trips', () => {
  for (const algorithm of ALL) {
    test(`${algorithm} recovers the exact plaintext`, async () => {
      const { cek, iv, ciphertext, tag } = await seal(algorithm);

      const opened = await openContent(algorithm, cek, iv, ciphertext, tag, AAD);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toEqual(PLAINTEXT);
      }
    });

    test(`${algorithm} handles an empty plaintext`, async () => {
      const { cek, iv, ciphertext, tag } = await seal(algorithm, new Uint8Array(0));

      // GCM produces no ciphertext bytes for an empty plaintext; CBC still
      // emits one full padding block.
      if (algorithm.includes('GCM')) {
        expect(ciphertext.length).toBe(0);
      } else {
        expect(ciphertext.length).toBe(16);
      }

      const opened = await openContent(algorithm, cek, iv, ciphertext, tag, AAD);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toEqual(new Uint8Array(0));
      }
    });

    test(`${algorithm} handles empty additional data`, async () => {
      const empty = new Uint8Array(0);
      const { cek, iv, ciphertext, tag } = await seal(algorithm, PLAINTEXT, empty);

      const opened = await openContent(algorithm, cek, iv, ciphertext, tag, empty);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toEqual(PLAINTEXT);
      }
    });

    test(`${algorithm} produces the exact tag width`, async () => {
      const { tag } = await seal(algorithm);
      expect(tag.length).toBe(contentEncryptionShape(algorithm)!.tagBytes);
    });
  }
});

describe('authentication failures', () => {
  for (const algorithm of ALL) {
    test(`${algorithm} rejects a modified ciphertext`, async () => {
      const { cek, iv, ciphertext, tag } = await seal(algorithm);
      const modified = flipBit(ciphertext);

      const opened = await openContent(algorithm, cek, iv, modified, tag, AAD);
      // Authentication failure is a successful outcome carrying no plaintext,
      // never a backend fault: the two must stay distinguishable.
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toBeUndefined();
      }
    });

    test(`${algorithm} rejects a modified tag`, async () => {
      const { cek, iv, ciphertext, tag } = await seal(algorithm);
      const modified = flipBit(tag);

      const opened = await openContent(algorithm, cek, iv, ciphertext, modified, AAD);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toBeUndefined();
      }
    });

    test(`${algorithm} rejects modified additional data`, async () => {
      // The header is authenticated but not encrypted, so a change there must
      // be caught by the tag rather than silently accepted.
      const { cek, iv, ciphertext, tag } = await seal(algorithm);
      const modified = new TextEncoder().encode('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn1');

      const opened = await openContent(algorithm, cek, iv, ciphertext, tag, modified);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toBeUndefined();
      }
    });

    test(`${algorithm} rejects a wrong key`, async () => {
      const { iv, ciphertext, tag } = await seal(algorithm);
      const other = new Uint8Array(randomBytes(contentEncryptionShape(algorithm)!.cekBytes));

      const opened = await openContent(algorithm, other, iv, ciphertext, tag, AAD);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toBeUndefined();
      }
    });

    test(`${algorithm} rejects a wrong IV`, async () => {
      const { cek, ciphertext, tag } = await seal(algorithm);
      const other = new Uint8Array(randomBytes(contentEncryptionShape(algorithm)!.ivBytes));

      const opened = await openContent(algorithm, cek, other, ciphertext, tag, AAD);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toBeUndefined();
      }
    });

    test(`${algorithm} rejects a truncated tag rather than checking a prefix`, async () => {
      const { cek, iv, ciphertext, tag } = await seal(algorithm);

      const opened = await openContent(algorithm, cek, iv, ciphertext, tag.subarray(0, 8), AAD);
      expect(opened.ok).toBe(true);
      if (opened.ok) {
        expect(opened.value).toBeUndefined();
      }
    });
  }
});

describe('size enforcement', () => {
  for (const algorithm of ALL) {
    test(`${algorithm} refuses a wrong-size key on encryption`, async () => {
      const shape = contentEncryptionShape(algorithm)!;
      const iv = new Uint8Array(shape.ivBytes);

      for (const size of [shape.cekBytes - 1, shape.cekBytes + 1, 0]) {
        const result = await sealContent(algorithm, new Uint8Array(size), iv, PLAINTEXT, AAD);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.failure).toBe('operation_failed');
        }
      }
    });

    test(`${algorithm} refuses a wrong-size IV on encryption`, async () => {
      const shape = contentEncryptionShape(algorithm)!;
      const cek = new Uint8Array(shape.cekBytes);

      for (const size of [shape.ivBytes - 1, shape.ivBytes + 1]) {
        const result = await sealContent(algorithm, cek, new Uint8Array(size), PLAINTEXT, AAD);
        expect(result.ok).toBe(false);
      }
    });

    test(`${algorithm} refuses a wrong-size key on decryption`, async () => {
      // A wrong key size is a configuration defect rather than a failed
      // authentication, so it is reported separately.
      const { iv, ciphertext, tag } = await seal(algorithm);
      const shape = contentEncryptionShape(algorithm)!;

      const result = await openContent(algorithm, new Uint8Array(shape.cekBytes - 1), iv, ciphertext, tag, AAD);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure).toBe('operation_failed');
      }
    });
  }

  test('reports an unsupported identifier rather than failing to authenticate', async () => {
    const key = new Uint8Array(32);
    const sealed = await sealContent('A128CBC', key, new Uint8Array(16), PLAINTEXT, AAD);
    expect(sealed.ok).toBe(false);
    if (!sealed.ok) {
      expect(sealed.failure).toBe('unsupported');
    }

    const opened = await openContent('A128CBC', key, new Uint8Array(16), new Uint8Array(16), new Uint8Array(16), AAD);
    expect(opened.ok).toBe(false);
    if (!opened.ok) {
      expect(opened.failure).toBe('unsupported');
    }
  });
});

describe('CBC-HMAC construction detail', () => {
  test('computes the tag over AAD, IV, ciphertext and the bit length', async () => {
    // Pinning the exact MAC input catches a reordering or a byte-count length
    // that would still round-trip against itself while failing every other
    // implementation.
    const algorithm = 'A128CBC-HS256';
    const parameters = cbcHmacParameters(algorithm)!;
    const { cek, iv, ciphertext, tag } = await seal(algorithm);

    const macKey = cek.subarray(0, parameters.keyBytes / 2);
    const lengthBlock = new Uint8Array(8);
    new DataView(lengthBlock.buffer).setBigUint64(0, BigInt(AAD.length) * 8n);

    const mac = createHmac(parameters.hash, macKey);
    mac.update(AAD);
    mac.update(iv);
    mac.update(ciphertext);
    mac.update(lengthBlock);

    expect(tag).toEqual(new Uint8Array(mac.digest().subarray(0, parameters.tagBytes)));
  });

  test('uses the MAC half first and the AES half second', async () => {
    // Swapping the halves round-trips against itself, so the split is checked
    // against an independently computed tag using the leading half.
    const algorithm = 'A128CBC-HS256';
    const { cek, iv, ciphertext, tag } = await seal(algorithm);

    const swapped = new Uint8Array([...cek.subarray(16), ...cek.subarray(0, 16)]);
    const mac = createHmac('sha256', swapped.subarray(0, 16));
    mac.update(AAD);
    mac.update(iv);
    mac.update(ciphertext);
    const lengthBlock = new Uint8Array(8);
    new DataView(lengthBlock.buffer).setBigUint64(0, BigInt(AAD.length) * 8n);
    mac.update(lengthBlock);

    expect(tag).not.toEqual(new Uint8Array(mac.digest().subarray(0, 16)));
  });

  test('rejects a ciphertext that is not whole blocks', async () => {
    const algorithm = 'A128CBC-HS256';
    const { cek, iv, ciphertext, tag } = await seal(algorithm);

    const opened = await openContent(algorithm, cek, iv, ciphertext.subarray(0, 15), tag, AAD);
    expect(opened.ok).toBe(true);
    if (opened.ok) {
      expect(opened.value).toBeUndefined();
    }
  });

  test('rejects an empty ciphertext', async () => {
    // The construction always emits at least one padding block, so an empty
    // ciphertext cannot have come from it.
    const algorithm = 'A128CBC-HS256';
    const { cek, iv, tag } = await seal(algorithm);

    const opened = await openContent(algorithm, cek, iv, new Uint8Array(0), tag, AAD);
    expect(opened.ok).toBe(true);
    if (opened.ok) {
      expect(opened.value).toBeUndefined();
    }
  });

  test('pads a block-aligned plaintext with a full block', async () => {
    const algorithm = 'A128CBC-HS256';
    const aligned = new Uint8Array(32);
    const { cek, iv, ciphertext, tag } = await seal(algorithm, aligned);

    expect(ciphertext.length).toBe(48);

    const opened = await openContent(algorithm, cek, iv, ciphertext, tag, AAD);
    expect(opened.ok).toBe(true);
    if (opened.ok) {
      expect(opened.value).toEqual(aligned);
    }
  });

  test('does not leak padding validity separately from authentication', async () => {
    // With the tag recomputed over the corrupted ciphertext the MAC passes, so
    // decryption reaches genuinely invalid padding. That must still surface as
    // the same authentication outcome as a bad tag.
    const algorithm = 'A128CBC-HS256';
    const parameters = cbcHmacParameters(algorithm)!;
    const { cek, iv, ciphertext } = await seal(algorithm);

    const corrupted = flipBit(ciphertext, ciphertext.length - 1, 0xff);

    const lengthBlock = new Uint8Array(8);
    new DataView(lengthBlock.buffer).setBigUint64(0, BigInt(AAD.length) * 8n);
    const mac = createHmac(parameters.hash, cek.subarray(0, 16));
    mac.update(AAD);
    mac.update(iv);
    mac.update(corrupted);
    mac.update(lengthBlock);
    const forgedTag = new Uint8Array(mac.digest().subarray(0, parameters.tagBytes));

    const opened = await openContent(algorithm, cek, iv, corrupted, forgedTag, AAD);
    expect(opened.ok).toBe(true);
    if (opened.ok) {
      expect(opened.value).toBeUndefined();
    }
  });
});

describe('GCM construction detail', () => {
  test('uses a 12-byte nonce and a full 16-byte tag', () => {
    expect(GCM_IV_BYTES).toBe(12);
    expect(GCM_TAG_BYTES).toBe(16);
    expect(CBC_IV_BYTES).toBe(16);
  });

  test('produces ciphertext the same length as the plaintext', async () => {
    // GCM is a stream construction, so any length change would mean padding
    // was applied where none belongs.
    for (const algorithm of GCM) {
      const { ciphertext } = await seal(algorithm);
      expect(ciphertext.length).toBe(PLAINTEXT.length);
    }
  });

  test('reuses of one nonce produce a recoverable plaintext difference', async () => {
    // This is the failure the durable allocator exists to prevent, asserted so
    // the consequence is recorded rather than assumed.
    const algorithm = 'A128GCM';
    const cek = new Uint8Array(randomBytes(16));
    const iv = new Uint8Array(randomBytes(12));

    const first = new TextEncoder().encode('attack at dawn');
    const second = new TextEncoder().encode('attack at dusk');

    const a = await sealContent(algorithm, cek, iv, first, AAD);
    const b = await sealContent(algorithm, cek, iv, second, AAD);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) {
      return;
    }

    for (let i = 0; i < first.length; i += 1) {
      expect(a.value.ciphertext[i]! ^ b.value.ciphertext[i]!).toBe(first[i]! ^ second[i]!);
    }
  });
});
