import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { randomBytes } from 'node:crypto';

import { contentEncryptionShape } from '../../../src/algorithms/content-encryption/index.ts';
import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { OperationBudget } from '../../../src/internal/validation/limits.ts';
import { decryptJson, type TrustedRecipient } from '../../../src/jwe/decrypt.ts';
import { encryptJson } from '../../../src/jwe/encrypt.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';

const PLAINTEXT = new TextEncoder().encode('{"sub":"alice"}');

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function allocator(): NonceAllocator {
  let counter = 0n;
  return {
    reserve(): Promise<NonceResult> {
      counter += 1n;
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(1, counter)! } });
    },
  };
}

function symmetric(algorithm: string, bytes: number, contentAlgorithm: string) {
  const jwk = { kty: 'oct', k: randomBytes(bytes).toString('base64url') };
  const wrapping = algorithm === 'dir' ? (['encrypt', 'decrypt'] as const) : (['wrapKey', 'unwrapKey'] as const);
  const load = (operation: (typeof wrapping)[number]): UsableKey => {
    const result = importKey(object(jwk), { algorithm, operation, contentAlgorithms: [contentAlgorithm] });
    if (!result.ok) {
      throw new Error(`import failed: ${result.reason}`);
    }
    return result.key;
  };
  return { encryption: load(wrapping[0]), decryption: load(wrapping[1]) };
}

async function encrypted(
  pair: ReturnType<typeof symmetric>,
  keyAlgorithm: string,
  contentAlgorithm: string,
): Promise<Record<string, unknown>> {
  const result = await encryptJson(PLAINTEXT, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', [keyAlgorithm], 'create'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', [contentAlgorithm], 'create'),
    contentAlgorithm,
    // The direct modes derive their nonce from the key's own space, so the
    // identity naming that space is required rather than optional.
    recipients: [{ key: pair.encryption, keyIdentity: 'fixture' }],
    limits: LIMITS_V1,
    random: systemRandom,
    nonceAllocator: allocator(),
  });
  if (!result.ok) {
    throw new Error(`encrypt failed: ${result.reason}`);
  }
  return JSON.parse(result.value) as Record<string, unknown>;
}

async function decrypt(
  source: string | Record<string, unknown>,
  trusted: readonly TrustedRecipient[],
  overrides: {
    keyAlgorithms?: readonly string[];
    contentAlgorithms?: readonly string[];
    principalId?: string;
    limits?: typeof LIMITS_V1;
    operationBudget?: OperationBudget;
  } = {},
) {
  const serialized = typeof source === 'string' ? source : JSON.stringify(source);
  return decryptJson(new TextEncoder().encode(serialized), {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', overrides.keyAlgorithms ?? ['A256KW'], 'receive'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', overrides.contentAlgorithms ?? ['A128GCM'], 'receive'),
    recipients: trusted,
    principalId: overrides.principalId ?? trusted[0]?.principalId ?? 'alice',
    limits: overrides.limits ?? LIMITS_V1,
    operationBudget: overrides.operationBudget,
  });
}

/** Rewrites the sole recipient entry's wrapped key, or removes it when undefined. */
function withEncryptedKey(
  serialized: Record<string, unknown>,
  encryptedKey: string | undefined,
): Record<string, unknown> {
  const recipients = serialized['recipients'] as Record<string, unknown>[];
  const entry = { ...recipients[0]! };
  if (encryptedKey === undefined) {
    delete entry['encrypted_key'];
  } else {
    entry['encrypted_key'] = encryptedKey;
  }
  return { ...serialized, recipients: [entry] };
}

/** Rewrites the protected header of an already-encrypted object. */
function withProtectedHeader(
  serialized: Record<string, unknown>,
  members: Record<string, unknown>,
): Record<string, unknown> {
  const header = JSON.parse(Buffer.from(serialized['protected'] as string, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  const merged: Record<string, unknown> = { ...header, ...members };
  for (const [name, value] of Object.entries(members)) {
    if (value === undefined) {
      delete merged[name];
    }
  }
  return {
    ...serialized,
    protected: Buffer.from(JSON.stringify(merged)).toString('base64url'),
  };
}

function assertFailure(
  result: Awaited<ReturnType<typeof decryptJson>>,
  expected: { category?: string; stage?: string; reason: string },
): void {
  assert.strictEqual(result.ok, false);
  if (result.ok) {
    return;
  }
  assert.strictEqual(result.reason, expected.reason);
  if (expected.category !== undefined) {
    assert.strictEqual(result.category, expected.category);
  }
  if (expected.stage !== undefined) {
    assert.strictEqual(result.stage, expected.stage);
  }
}

function assertEncryptFailure(result: Awaited<ReturnType<typeof encryptJson>>, reason: string): void {
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.reason, reason);
  }
}

function recipientsFor(pair: ReturnType<typeof symmetric>): readonly TrustedRecipient[] {
  return [{ principalId: 'alice', key: pair.decryption }];
}

describe('JSON JWE decryption entry point', () => {
  test('honors shared layer, JSON-node, and cryptographic-attempt budgets', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const layers = new OperationBudget(LIMITS_V1);
    assert.strictEqual(layers.consumeLayer(), true);
    assert.strictEqual(layers.consumeLayer(), true);
    assertFailure(await decrypt(serialized, recipientsFor(pair), { operationBudget: layers }), {
      reason: 'too_many_cryptographic_layers',
    });

    const nodes = new OperationBudget(LIMITS_V1);
    assert.strictEqual(nodes.consumeJsonNodes(LIMITS_V1.jsonNodes), true);
    assertFailure(await decrypt(serialized, recipientsFor(pair), { operationBudget: nodes }), {
      reason: 'json_node_budget_exceeded',
    });

    for (const cryptographicAttempts of [0, 1]) {
      const result = await decrypt(serialized, recipientsFor(pair), {
        limits: lowerLimits({ cryptographicAttempts }),
      });
      assertFailure(result, { reason: 'cryptographic_attempt_budget_exceeded' });
    }
  });

  test('rejects limits that were never lowered from the baseline', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const result = await decrypt(serialized, recipientsFor(pair), {
      limits: { ...LIMITS_V1, ciphertext: LIMITS_V1.ciphertext + 1 },
    });
    assertFailure(result, {
      stage: 'configuration',
      category: 'policy_violation',
      reason: 'limit_ciphertext_exceeds_baseline',
    });
  });

  test('rejects an object larger than the configured input limit', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const result = await decrypt(serialized, recipientsFor(pair), { limits: lowerLimits({ joseInput: 32 }) });
    assertFailure(result, { stage: 'syntax', category: 'resource_limit', reason: 'jwe_too_large' });
  });

  test('distinguishes the JSON failure modes that reject the document', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');
    const valid = JSON.stringify(serialized);

    const truncated = await decrypt(valid.slice(0, valid.length - 1), recipientsFor(pair));
    assertFailure(truncated, { category: 'invalid_encoding', reason: 'jwe_invalid_json' });

    // A repeated member makes the document ambiguous rather than merely
    // malformed, so it is reported as such.
    const duplicated = `{"protected":"a",${valid.slice(1)}`;
    const duplicate = await decrypt(duplicated, recipientsFor(pair));
    assertFailure(duplicate, { category: 'malformed_input', reason: 'jwe_invalid_json' });

    const deep = await decrypt(valid, recipientsFor(pair), { limits: lowerLimits({ jsonDepth: 1 }) });
    assertFailure(deep, { category: 'resource_limit', reason: 'jwe_invalid_json' });
  });

  test('rejects a principal that names no trusted key before the object is examined', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const empty = await decrypt(serialized, recipientsFor(pair), { principalId: '' });
    assertFailure(empty, { stage: 'configuration', reason: 'principal_id_empty' });

    // Reported as a configuration defect rather than a key-resolution outcome,
    // so the failure does not reveal which recipients the object contains.
    const unknown = await decrypt(serialized, recipientsFor(pair), { principalId: 'stranger' });
    assertFailure(unknown, { stage: 'configuration', reason: 'selected_principal_has_no_trusted_key' });
  });
});

describe('JSON JWE protected header validation', () => {
  test('rejects a protected component that is not valid base64url or JSON', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const badEncoding = await decrypt({ ...serialized, protected: 'not base64url!' }, recipientsFor(pair));
    assertFailure(badEncoding, { category: 'invalid_encoding', reason: 'protected_header_invalid_base64url' });

    const badJson = await decrypt(
      { ...serialized, protected: Buffer.from('{not json').toString('base64url') },
      recipientsFor(pair),
    );
    assertFailure(badJson, { reason: 'protected_header_invalid_json' });

    // The parse stage bounds the component before the header is decoded, so the
    // size is refused there rather than at the header stage behind it.
    const oversized = await decrypt(serialized, recipientsFor(pair), { limits: lowerLimits({ headerSource: 8 }) });
    assertFailure(oversized, { category: 'resource_limit', reason: 'protected_too_large' });
  });

  test('requires the content algorithm to be present, permitted, and supported', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    for (const enc of [undefined, 1, null, true]) {
      const result = await decrypt(withProtectedHeader(serialized, { enc }), recipientsFor(pair));
      assertFailure(result, { stage: 'header', reason: 'enc_missing_or_not_a_string' });
    }

    const prohibited = await decrypt(serialized, recipientsFor(pair), { contentAlgorithms: ['A256GCM'] });
    assert.strictEqual(prohibited.ok, false);
    if (!prohibited.ok) {
      assert.strictEqual(prohibited.stage, 'header');
    }
  });

  test('refuses compression rather than returning compressed octets as plaintext', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const result = await decrypt(withProtectedHeader(serialized, { zip: 'DEF' }), recipientsFor(pair));
    assertFailure(result, { stage: 'header', category: 'policy_violation', reason: 'compression_not_enabled' });
  });

  test('requires a key-management algorithm that is a string', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const missing = await decrypt(withProtectedHeader(serialized, { alg: undefined }), recipientsFor(pair));
    assertFailure(missing, { stage: 'header', reason: 'alg_missing_or_not_a_string' });

    // A present `alg` of the wrong JSON type is caught by the registered
    // parameter type check that precedes the presence test.
    for (const alg of [1, null, true]) {
      const result = await decrypt(withProtectedHeader(serialized, { alg }), recipientsFor(pair));
      assertFailure(result, { stage: 'header', reason: 'parameter_not_a_string' });
    }
  });
});

describe('JSON JWE component shape', () => {
  test('requires the encrypted key to be present exactly when the mode wraps', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const missing = await decrypt(withEncryptedKey(serialized, undefined), recipientsFor(pair));
    assertFailure(missing, { stage: 'header', reason: 'encrypted_key_presence_mismatch' });

    // `dir` carries no wrapped key, so supplying one contradicts the algorithm
    // the object names.
    const direct = symmetric('dir', contentEncryptionShape('A128GCM')!.cekBytes, 'A128GCM');
    const directObject = await encrypted(direct, 'dir', 'A128GCM');
    const present = await decrypt(
      withEncryptedKey(directObject, Buffer.from(randomBytes(32)).toString('base64url')),
      [{ principalId: 'alice', key: direct.decryption }],
      { keyAlgorithms: ['dir'] },
    );
    assertFailure(present, { stage: 'header', reason: 'encrypted_key_presence_mismatch' });
  });

  test('requires the iv and tag to decode to the width the content algorithm fixes', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const shortIv = await decrypt(
      { ...serialized, iv: Buffer.from(randomBytes(8)).toString('base64url') },
      recipientsFor(pair),
    );
    assertFailure(shortIv, { stage: 'syntax', category: 'malformed_input', reason: 'iv_wrong_length' });

    const shortTag = await decrypt(
      { ...serialized, tag: Buffer.from(randomBytes(8)).toString('base64url') },
      recipientsFor(pair),
    );
    assertFailure(shortTag, { stage: 'syntax', category: 'malformed_input', reason: 'tag_wrong_length' });
  });

  test('rejects ciphertext and encrypted key that are not valid base64url', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const badCiphertext = await decrypt({ ...serialized, ciphertext: 'not base64url!' }, recipientsFor(pair));
    assertFailure(badCiphertext, { category: 'invalid_encoding', reason: 'ciphertext_invalid_base64url' });

    const oversized = await decrypt(serialized, recipientsFor(pair), { limits: lowerLimits({ ciphertext: 1 }) });
    assertFailure(oversized, { category: 'resource_limit', reason: 'ciphertext_too_large' });

    const badKey = await decrypt(withEncryptedKey(serialized, 'not base64url!'), recipientsFor(pair));
    assertFailure(badKey, { category: 'invalid_encoding', reason: 'encrypted_key_invalid_base64url' });
  });

  test('reports a wrapped key that does not unwrap as an authentication failure', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    // Indistinguishable from a failed content tag: reporting the key step
    // separately would tell an attacker whether their guess reached the content.
    const result = await decrypt(
      withEncryptedKey(serialized, Buffer.from(randomBytes(40)).toString('base64url')),
      recipientsFor(pair),
    );
    assertFailure(result, {
      stage: 'cryptographic',
      category: 'authentication_failure',
      reason: 'decryption_failed',
    });
  });

  test('reports a tampered ciphertext as an authentication failure', async () => {
    const pair = symmetric('A256KW', 32, 'A128GCM');
    const serialized = await encrypted(pair, 'A256KW', 'A128GCM');

    const bytes = Buffer.from(serialized['ciphertext'] as string, 'base64url');
    const tampered = Buffer.from(bytes.map((byte, index) => (index === 0 ? byte ^ 0xff : byte)));
    const result = await decrypt({ ...serialized, ciphertext: tampered.toString('base64url') }, recipientsFor(pair));
    assertFailure(result, {
      stage: 'cryptographic',
      category: 'authentication_failure',
      reason: 'decryption_failed',
    });
  });
});

describe('JSON JWE encryption configuration', () => {
  const CONTENT = 'A128GCM';

  async function encryptWith(overrides: Record<string, unknown>) {
    const pair = symmetric('A256KW', 32, CONTENT);
    return encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', [CONTENT], 'create'),
      contentAlgorithm: CONTENT,
      recipients: [{ key: pair.encryption }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
      ...overrides,
    });
  }

  test('rejects limits that were never lowered from the baseline', async () => {
    const result = await encryptWith({ limits: { ...LIMITS_V1, payload: LIMITS_V1.payload + 1 } });
    assertEncryptFailure(result, 'limit_payload_exceeds_baseline');
  });

  test('rejects a policy that was built for acceptance rather than creation', async () => {
    // A receive policy permits identifiers this direction refuses, so passing
    // one is a configuration defect rather than a per-identifier outcome.
    assertEncryptFailure(
      await encryptWith({ keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive') }),
      'policy_not_built_for_creation',
    );
    assertEncryptFailure(
      await encryptWith({ contentPolicy: AlgorithmPolicy.create('jwe_enc', [CONTENT], 'receive') }),
      'policy_not_built_for_creation',
    );
  });

  test('bounds the recipient list at both ends', async () => {
    assertEncryptFailure(await encryptWith({ recipients: [] }), 'no_recipients');

    const many = Array.from({ length: 3 }, () => ({ key: symmetric('A256KW', 32, CONTENT).encryption }));
    assertEncryptFailure(
      await encryptWith({ recipients: many, limits: lowerLimits({ recipients: 2 }) }),
      'too_many_recipients',
    );
  });

  test('requires the flattened form to carry exactly one recipient', async () => {
    const two = Array.from({ length: 2 }, () => ({ key: symmetric('A256KW', 32, CONTENT).encryption }));
    assertEncryptFailure(
      await encryptWith({ flattened: true, recipients: two }),
      'flattened_requires_single_recipient',
    );
  });

  test('rejects a plaintext larger than the payload limit', async () => {
    assertEncryptFailure(await encryptWith({ limits: lowerLimits({ payload: 4 }) }), 'plaintext_too_large');
  });

  test('requires every recipient key to be bound to the content algorithm and the right operation', async () => {
    const unwrapping = symmetric('A256KW', 32, CONTENT);
    assertEncryptFailure(await encryptWith({ recipients: [{ key: unwrapping.decryption }] }), 'key_operation_mismatch');

    const otherContent = symmetric('A256KW', 32, 'A256GCM');
    assertEncryptFailure(
      await encryptWith({ recipients: [{ key: otherContent.encryption }] }),
      'content_algorithm_not_bound',
    );
  });

  test('rejects recipients whose key algorithms disagree', async () => {
    // A single shared `alg` goes in the protected header; differing values would
    // need a policy constraining each recipient's key independently.
    const wrapping = symmetric('A256KW', 32, CONTENT);
    const other = symmetric('A128KW', 16, CONTENT);
    const result = await encryptWith({
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW', 'A128KW'], 'create'),
      recipients: [{ key: wrapping.encryption }, { key: other.encryption }],
    });
    assertEncryptFailure(result, 'recipients_disagree_on_algorithm');
  });

  test('fails closed when the randomness source is unavailable', async () => {
    assertEncryptFailure(
      await encryptWith({
        random: {
          randomBytes: () => {
            throw new Error('entropy unavailable');
          },
        },
      }),
      'randomness_unavailable',
    );

    assertEncryptFailure(
      await encryptWith({ random: { randomBytes: () => ({ ok: true, value: new Uint8Array(1) }) } }),
      'randomness_unavailable',
    );
  });
});

describe('JSON JWE direct-mode nonce allocation', () => {
  const CONTENT = 'A128GCM';

  async function encryptDirect(overrides: Record<string, unknown>) {
    const pair = symmetric('dir', contentEncryptionShape(CONTENT)!.cekBytes, CONTENT);
    return encryptJson(PLAINTEXT, {
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'create'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', [CONTENT], 'create'),
      contentAlgorithm: CONTENT,
      recipients: [{ key: pair.encryption, keyIdentity: 'fixture' }],
      limits: LIMITS_V1,
      random: systemRandom,
      nonceAllocator: allocator(),
      ...overrides,
    });
  }

  test('requires a durable allocator and a key identity naming its space', async () => {
    const pair = symmetric('dir', contentEncryptionShape(CONTENT)!.cekBytes, CONTENT);

    // Generating a nonce locally would satisfy the type while losing the
    // uniqueness guarantee the allocator exists to provide.
    assertEncryptFailure(await encryptDirect({ nonceAllocator: undefined }), 'nonce_allocator_required');

    assertEncryptFailure(await encryptDirect({ recipients: [{ key: pair.encryption }] }), 'key_identity_required');
  });

  test('reports each terminal allocator outcome distinctly', async () => {
    assertEncryptFailure(
      await encryptDirect({
        nonceAllocator: {
          reserve: () => {
            throw new Error('store offline');
          },
        },
      }),
      'nonce_allocator_unavailable',
    );

    for (const failure of ['unavailable', 'exhausted', 'state_uncertain'] as const) {
      const result = await encryptDirect({
        nonceAllocator: { reserve: () => Promise.resolve({ ok: false, failure }) },
      });
      assertEncryptFailure(result, `nonce_${failure}`);
    }
  });

  test('rejects a reserved nonce of the wrong width for the content algorithm', async () => {
    const result = await encryptDirect({
      nonceAllocator: {
        reserve: () => Promise.resolve({ ok: true, reservation: { nonce: new Uint8Array(8) } }),
      },
    });
    assertEncryptFailure(result, 'nonce_wrong_length');
  });
});
