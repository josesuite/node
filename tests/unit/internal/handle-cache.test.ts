import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { signWithKey, verifyWithKey } from '../../../src/algorithms/index.ts';
import { importCached } from '../../../src/internal/crypto/webcrypto.ts';
import { importKeyBytes, type UsableKey } from '../../../src/key/import.ts';

const INPUT = new TextEncoder().encode('signing input');

function imported(jwk: unknown, algorithm: string, operation: 'sign' | 'verify'): UsableKey {
  const result = importKeyBytes(new TextEncoder().encode(JSON.stringify(jwk)), { algorithm, operation });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

/** A distinguishable stand-in for a provider handle; the cache never inspects it. */
function handle(): CryptoKey {
  return {} as CryptoKey;
}

describe('provider handle cache', () => {
  test('imports once per token and reuses the result', async () => {
    const token = {};
    let imports = 0;
    const load = async (): Promise<CryptoKey> => {
      imports += 1;
      return handle();
    };

    const first = await importCached(token, load);
    const second = await importCached(token, load);

    assert.equal(imports, 1);
    assert.equal(second, first);
  });

  test('keeps tokens independent, so one key never serves another', async () => {
    const load = async (): Promise<CryptoKey> => handle();

    const first = await importCached({}, load);
    const second = await importCached({}, load);

    assert.notEqual(second, first);
  });

  test('imports every time when no token is supplied', async () => {
    // An absent token means the caller holds no record to key on, so reuse would
    // have to be keyed on key material, which this cache deliberately never does.
    let imports = 0;
    const load = async (): Promise<CryptoKey> => {
      imports += 1;
      return handle();
    };

    await importCached(undefined, load);
    await importCached(undefined, load);

    assert.equal(imports, 2);
  });

  test('shares one in-flight import between concurrent callers', async () => {
    const token = {};
    let imports = 0;
    const load = async (): Promise<CryptoKey> => {
      imports += 1;
      await Promise.resolve();
      return handle();
    };

    const [first, second] = await Promise.all([importCached(token, load), importCached(token, load)]);

    assert.equal(imports, 1);
    assert.equal(second, first);
  });

  test('does not cache a rejected import, so a transient fault is retried', async () => {
    // Caching the rejection would turn one provider outage into a key that can
    // never be used again for the lifetime of the record.
    const token = {};
    let attempts = 0;
    const load = async (): Promise<CryptoKey> => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error('provider unavailable');
      }
      return handle();
    };

    await assert.rejects(importCached(token, load));
    const recovered = await importCached(token, load);

    assert.equal(attempts, 2);
    assert.ok(recovered);
  });

  test('reports a rejection to its caller rather than only to the evicting handler', async () => {
    const token = {};
    await assert.rejects(
      importCached(token, async () => {
        throw new Error('provider unavailable');
      }),
      /provider unavailable/,
    );
  });
});

/** One freshly generated key pair, as the JWK members each side is imported from. */
interface Material {
  readonly signing: unknown;
  readonly verifying: unknown;
}

const MATERIAL: Readonly<Record<string, () => Material>> = {
  HS256: () => {
    const jwk = { kty: 'oct', k: randomBytes(32).toString('base64url') };
    return { signing: jwk, verifying: jwk };
  },
  ES256: () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
      signing: pair.privateKey.export({ format: 'jwk' }),
      verifying: pair.publicKey.export({ format: 'jwk' }),
    };
  },
  RS256: () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 3072 });
    return {
      signing: pair.privateKey.export({ format: 'jwk' }),
      verifying: pair.publicKey.export({ format: 'jwk' }),
    };
  },
};

describe('signatures under a reused key record', () => {
  for (const [algorithm, generate] of Object.entries(MATERIAL)) {
    test(`${algorithm} produces and accepts the same signatures across repeated operations`, async () => {
      const material = generate();
      const signingKey = imported(material.signing, algorithm, 'sign');
      const verifyingKey = imported(material.verifying, algorithm, 'verify');

      // The second pass runs against a cached handle. A stale or cross-bound
      // handle would show up here as a signature that no longer verifies.
      for (let pass = 0; pass < 2; pass += 1) {
        const signature = await signWithKey(signingKey, INPUT);
        assert.ok(signature.ok, `sign pass ${pass}`);

        const verified = await verifyWithKey(verifyingKey, INPUT, signature.value);
        assert.deepStrictEqual(verified, { ok: true, value: true }, `verify pass ${pass}`);
      }
    });

    test(`${algorithm} still rejects a foreign signature after its handle is cached`, async () => {
      const signingKey = imported(generate().signing, algorithm, 'sign');
      const verifyingKey = imported(generate().verifying, algorithm, 'verify');

      const foreign = await signWithKey(signingKey, INPUT);
      assert.ok(foreign.ok);

      // The first pass populates the verification handle; the second decides the
      // same rejection from the cached one.
      for (let pass = 0; pass < 2; pass += 1) {
        assert.deepStrictEqual(
          await verifyWithKey(verifyingKey, INPUT, foreign.value),
          { ok: true, value: false },
          `pass ${pass}`,
        );
      }
    });
  }
});
