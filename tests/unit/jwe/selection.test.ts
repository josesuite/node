import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { randomBytes } from 'node:crypto';

import { systemRandom } from '../../../src/internal/crypto/random.ts';
import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { decryptParsed, type TrustedRecipient } from '../../../src/jwe/decrypt.ts';
import { encryptJson } from '../../../src/jwe/encrypt.ts';
import { composeNonce, type NonceAllocator, type NonceResult } from '../../../src/jwe/nonce.ts';
import { parseJsonJwe } from '../../../src/jwe/parse.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1 } from '../../../src/policy/limits.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function key(
  jwk: Record<string, unknown>,
  algorithm: string,
  operation: 'encrypt' | 'wrapKey' | 'unwrapKey',
): UsableKey {
  const result = importKey(object(jwk), {
    algorithm,
    operation,
    contentAlgorithms: algorithm === 'dir' ? ['A128GCM'] : ['A128GCM', 'A128CBC-HS256'],
  });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

function allocator(): NonceAllocator {
  const counters = new Map<string, bigint>();
  return {
    reserve(id: string): Promise<NonceResult> {
      const next = (counters.get(id) ?? 0n) + 1n;
      counters.set(id, next);
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(1, next)! } });
    },
  };
}

function signer(kid: string) {
  const jwk = { kty: 'oct', k: randomBytes(32).toString('base64url'), kid };
  return { kid, encryption: key(jwk, 'A256KW', 'wrapKey'), decryption: key(jwk, 'A256KW', 'unwrapKey') };
}

const PLAINTEXT = new TextEncoder().encode('secret');

async function encryptTo(recipients: readonly { encryption: UsableKey; kid: string }[], publishKid = true) {
  const result = await encryptJson(PLAINTEXT, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
    contentAlgorithm: 'A128GCM',
    recipients: recipients.map((r) => ({
      key: r.encryption,
      ...(publishKid ? { unprotectedHeader: { kid: r.kid } } : {}),
    })),
    limits: LIMITS_V1,
    random: systemRandom,
    nonceAllocator: allocator(),
  });
  if (!result.ok) {
    throw new Error(`encrypt failed: ${result.reason}`);
  }
  return result.value;
}

async function decrypt(serialized: string, trusted: readonly TrustedRecipient[], principalId?: string) {
  const parsedJson = parseJson(new TextEncoder().encode(serialized), LIMITS_V1);
  if (!parsedJson.ok) {
    throw new Error('bad serialization');
  }
  const parsed = parseJsonJwe(parsedJson.value, LIMITS_V1);
  if (!parsed.ok) {
    throw new Error(`parse failed: ${parsed.reason}`);
  }

  return decryptParsed(parsed.value, {
    keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
    contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
    recipients: trusted,
    principalId: principalId ?? trusted[0]!.principalId,
    limits: LIMITS_V1,
  });
}

describe('recipient selection', () => {
  test('refuses when no trusted key matches', async () => {
    const alice = signer('alice');
    const stranger = signer('stranger');
    const serialized = await encryptTo([alice]);

    const result = await decrypt(serialized, [{ principalId: 'stranger', key: stranger.decryption }]);

    // The only entry names another principal's kid, so nothing addressed to the
    // selected principal remains and no unwrap is ever attempted.
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'key_resolution_failure');
      assert.strictEqual(result.reason, 'no_eligible_recipient');
    }
  });

  test('an unhinted entry that the selected principal cannot open fails at authentication', async () => {
    // Without a kid the entry stays structurally eligible, so the wrong key
    // reaches the unwrap and fails there rather than during resolution.
    const alice = signer('alice');
    const stranger = signer('stranger');
    const serialized = await encryptTo([alice], false);

    const result = await decrypt(serialized, [{ principalId: 'stranger', key: stranger.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'authentication_failure');
    }
  });

  test('refuses when several entries are equally eligible', async () => {
    // Two entries share an algorithm and publish no distinguishing hint, so no
    // rule picks one. Trying each in turn would let the object decide which
    // key gets used, which is exactly what must not happen.
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([alice, bob], false);

    const result = await decrypt(serialized, [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'key_resolution_failure');
      assert.strictEqual(result.reason, 'ambiguous_recipient');
    }
  });

  test('a kid narrows several entries to one', async () => {
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([alice, bob]);

    const result = await decrypt(serialized, [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.principalId, 'alice');
      assert.deepStrictEqual(result.plaintext, PLAINTEXT);
    }
  });

  test('a kid never introduces a key the caller does not trust', async () => {
    // The hint may narrow the trusted set but cannot add to it, so naming an
    // untrusted principal resolves nothing.
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([alice, bob]);

    const result = await decrypt(serialized, [{ principalId: 'carol', key: signer('carol').decryption }]);

    assert.strictEqual(result.ok, false);
  });

  test('reports no eligible recipient when the algorithm is not permitted', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);

    const parsedJson = parseJson(new TextEncoder().encode(serialized), LIMITS_V1);
    if (!parsedJson.ok) {
      throw new Error('bad');
    }
    const parsed = parseJsonJwe(parsedJson.value, LIMITS_V1);
    if (!parsed.ok) {
      throw new Error('bad');
    }

    const result = await decryptParsed(parsed.value, {
      // The object names A256KW, which this caller did not permit.
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A128KW'], 'receive'),
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
      recipients: [{ principalId: 'alice', key: alice.decryption }],
      principalId: 'alice',
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'key_resolution_failure');
      assert.strictEqual(result.reason, 'no_eligible_recipient');
    }
  });
});

describe('the selected principal comes from the caller', () => {
  test('a token addressed to another locally trusted principal does not switch principals', async () => {
    // Both keys are configured, so trying every principal would succeed as bob.
    // The caller selected alice, and only alice's eligibility may be consulted.
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([bob]);

    const trusted = [
      { principalId: 'alice', key: alice.decryption },
      { principalId: 'bob', key: bob.decryption },
    ];

    const asAlice = await decrypt(serialized, trusted, 'alice');
    assert.strictEqual(asAlice.ok, false);
    if (!asAlice.ok) {
      assert.strictEqual(asAlice.category, 'key_resolution_failure');
      assert.strictEqual(asAlice.reason, 'no_eligible_recipient');
    }

    const asBob = await decrypt(serialized, trusted, 'bob');
    assert.strictEqual(asBob.ok, true);
    if (asBob.ok) {
      assert.strictEqual(asBob.principalId, 'bob');
    }
  });

  test('refuses a selected principal with no trusted key before reading the object', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);

    const result = await decrypt(serialized, [{ principalId: 'alice', key: alice.decryption }], 'carol');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'configuration');
      assert.strictEqual(result.reason, 'selected_principal_has_no_trusted_key');
    }
  });

  test('refuses an empty selected principal', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);

    const result = await decrypt(serialized, [{ principalId: 'alice', key: alice.decryption }], '');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'principal_id_empty');
    }
  });

  test('several entries eligible for the selected principal are refused without trying any', async () => {
    const alice = signer('alice');
    const other = signer('alice-second');
    const serialized = await encryptTo([alice, other], false);

    const result = await decrypt(
      serialized,
      [
        { principalId: 'alice', key: alice.decryption },
        { principalId: 'alice', key: other.decryption },
      ],
      'alice',
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'ambiguous_recipient');
      // Nothing was tried, so no entry carries a status.
      assert.strictEqual(result.recipients, undefined);
    }
  });
});

describe('per-entry recipient outcomes', () => {
  test('the selected entry succeeds and every other is not_selected', async () => {
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([bob, alice]);

    const result = await decrypt(serialized, [{ principalId: 'alice', key: alice.decryption }], 'alice');

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual(result.recipients, [
        { index: 0, status: 'not_selected' },
        { index: 1, status: 'success' },
      ]);
    }
  });

  test('a failing selected entry is reported as failed with its category', async () => {
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([bob, alice]);
    const parsed = JSON.parse(serialized);
    // Corrupt only the entry addressed to alice, so selection still resolves it.
    parsed.recipients[1].encrypted_key = Buffer.from(randomBytes(40)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }], 'alice');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.deepStrictEqual(result.recipients, [
        { index: 0, status: 'not_selected' },
        { index: 1, status: 'failed', category: 'authentication_failure' },
      ]);
    }
  });
});

function moveAlgToRecipients(serialized: string, algorithms: readonly string[]): string {
  const parsed = JSON.parse(serialized);
  const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
  delete header.alg;
  parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');
  for (const [index, entry] of parsed.recipients.entries()) {
    entry.header = { ...entry.header, alg: algorithms[index] ?? algorithms[0] };
  }
  return JSON.stringify(parsed);
}

describe('algorithm header placement', () => {
  test('refuses an unprotected alg when the object uses one algorithm', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);

    const result = await decrypt(
      moveAlgToRecipients(serialized, ['A256KW']),
      [{ principalId: 'alice', key: alice.decryption }],
      'alice',
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'alg_must_be_protected');
    }
  });

  test('refuses differing per-recipient algorithms unless the profile is enabled', async () => {
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([alice, bob]);

    const result = await decrypt(
      moveAlgToRecipients(serialized, ['A256KW', 'A128KW']),
      [{ principalId: 'alice', key: alice.decryption }],
      'alice',
    );

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'differing_recipient_algorithms_not_enabled');
    }
  });
});

describe('whole-object rejection precedes selection', () => {
  test('an unselected direct entry rejects the object before key resolution', async () => {
    // The caller could open the wrapping entry, but a multi-recipient object
    // carrying a direct mode is malformed no matter which entry is selected.
    const alice = signer('alice');
    const bob = signer('bob');
    const serialized = await encryptTo([alice, bob]);
    const parsed = JSON.parse(serialized);

    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    delete header.alg;
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');
    parsed.recipients[0].header = { ...parsed.recipients[0].header, alg: 'A256KW' };
    parsed.recipients[1].header = { ...parsed.recipients[1].header, alg: 'dir' };
    delete parsed.recipients[1].encrypted_key;

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }], 'alice');

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'algorithm_requires_single_recipient');
    }
  });

  test('a prohibited algorithm rejects before any recipient is chosen', async () => {
    // The rejection must not depend on whether that recipient would have been
    // selected, so it is asserted with a trusted key present for another entry.
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);
    const parsed = JSON.parse(serialized);

    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    header.alg = 'RSA1_5';
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'prohibited_algorithm');
    }
  });

  test('an unsupported content algorithm rejects before selection', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);
    const parsed = JSON.parse(serialized);

    const header = JSON.parse(Buffer.from(parsed.protected, 'base64url').toString('utf8'));
    header.enc = 'A128CBC';
    parsed.protected = Buffer.from(JSON.stringify(header)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'header');
    }
  });
});

describe('structural consistency with the named algorithm', () => {
  test('rejects a wrapping algorithm with no encrypted key', async () => {
    // Presence is structural: a wrapping mode always carries bytes, so an
    // object naming one without them does not describe what it claims.
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);
    const parsed = JSON.parse(serialized);
    delete parsed.recipients[0].encrypted_key;

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'encrypted_key_presence_mismatch');
    }
  });

  test('rejects an IV of the wrong length', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);
    const parsed = JSON.parse(serialized);
    parsed.iv = Buffer.from(randomBytes(8)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'iv_wrong_length');
    }
  });

  test('rejects a tag of the wrong length', async () => {
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);
    const parsed = JSON.parse(serialized);
    parsed.tag = Buffer.from(randomBytes(8)).toString('base64url');

    const result = await decrypt(JSON.stringify(parsed), [{ principalId: 'alice', key: alice.decryption }]);

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'tag_wrong_length');
    }
  });

  test('rejects octets shifted across the ciphertext and tag boundary', async () => {
    // Each case preserves `ciphertext || tag`, so an implementation that
    // concatenated the members before authenticating would accept them all.
    const alice = signer('alice');
    const serialized = await encryptTo([alice]);
    const parsed = JSON.parse(serialized);
    const ciphertext = Buffer.from(parsed.ciphertext, 'base64url');
    const tag = Buffer.from(parsed.tag, 'base64url');
    const joined = Buffer.concat([ciphertext, tag]);

    const shifted = [
      // One octet moved from the ciphertext into the tag, and the reverse.
      { ciphertext: joined.subarray(0, ciphertext.length - 1), tag: joined.subarray(ciphertext.length - 1) },
      { ciphertext: joined.subarray(0, ciphertext.length + 1), tag: joined.subarray(ciphertext.length + 1) },
      // Every octet on one side of the boundary.
      { ciphertext: joined, tag: Buffer.alloc(0) },
      { ciphertext: Buffer.alloc(0), tag: joined },
    ];

    for (const members of shifted) {
      const candidate = JSON.stringify({
        ...parsed,
        ciphertext: members.ciphertext.toString('base64url'),
        tag: members.tag.toString('base64url'),
      });

      // An emptied member is refused as malformed structure before decryption,
      // a wrongly sized one during it; either layer rejecting is correct.
      const parsedJson = parseJson(new TextEncoder().encode(candidate), LIMITS_V1);
      if (!parsedJson.ok) {
        throw new Error('bad serialization');
      }
      const structure = parseJsonJwe(parsedJson.value, LIMITS_V1);
      if (!structure.ok) {
        continue;
      }

      const result = await decrypt(candidate, [{ principalId: 'alice', key: alice.decryption }]);
      assert.strictEqual(result.ok, false);
    }
  });
});

describe('creation refuses unusable configurations', () => {
  const base = {
    contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
    contentAlgorithm: 'A128GCM',
    limits: LIMITS_V1,
    random: systemRandom,
  };

  /** A `dir` key, whose CEK is the configured long-lived key itself. */
  function directKey() {
    const jwk = { kty: 'oct', k: randomBytes(16).toString('base64url') };
    return key(jwk, 'dir', 'encrypt');
  }

  test('refuses a GCM object under dir with no nonce allocator', async () => {
    // Under `dir` the CEK is the caller's long-lived key, so its GCM nonce must
    // never repeat across messages. Generating one locally would satisfy the
    // type while losing the uniqueness guarantee the allocator provides.
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'create'),
      recipients: [{ key: directKey(), keyIdentity: 'content-key' }],
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'nonce_allocator_required');
    }
  });

  test('refuses a GCM object under dir with no provisioned key identity', async () => {
    // The allocator cannot scope a counter to a key it cannot name.
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['dir'], 'create'),
      recipients: [{ key: directKey() }],
      nonceAllocator: allocator(),
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'key_identity_required');
    }
  });

  test('needs no allocator when the CEK is generated per message', async () => {
    // A wrapping mode draws a fresh CEK from the CSPRNG for this message alone.
    // A nonce cannot repeat under a key that encrypts exactly once, so no
    // durable reservation applies and none is demanded.
    const alice = signer('alice');
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      recipients: [{ key: alice.encryption }],
    });

    assert.strictEqual(result.ok, true);
  });

  test('needs no allocator for a CBC construction', async () => {
    // CBC needs an unpredictable IV rather than a unique one, so the CSPRNG
    // suffices and no durable state is required.
    const alice = signer('alice');
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      contentPolicy: AlgorithmPolicy.create('jwe_enc', ['A128CBC-HS256'], 'create'),
      contentAlgorithm: 'A128CBC-HS256',
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      recipients: [{ key: alice.encryption }],
    });

    assert.strictEqual(result.ok, true);
  });

  test('refuses zero recipients', async () => {
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      recipients: [],
      nonceAllocator: allocator(),
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'no_recipients');
    }
  });

  test('refuses the flattened form with several recipients', async () => {
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      recipients: [{ key: signer('a').encryption }, { key: signer('b').encryption }],
      nonceAllocator: allocator(),
      flattened: true,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'flattened_requires_single_recipient');
    }
  });

  test('refuses a caller-supplied algorithm header', async () => {
    // The algorithms come from the keys and the content choice, so a caller
    // cannot steer them through the header.
    for (const name of ['alg', 'enc', 'epk', 'zip']) {
      const result = await encryptJson(PLAINTEXT, {
        ...base,
        keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
        recipients: [{ key: signer('a').encryption }],
        nonceAllocator: allocator(),
        protectedHeader: { [name]: 'injected' },
      });

      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.reason, `reserved_header_${name}`);
      }
    }
  });

  test('refuses a name appearing in both header sources', async () => {
    const result = await encryptJson(PLAINTEXT, {
      ...base,
      keyPolicy: AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
      recipients: [{ key: signer('a').encryption, unprotectedHeader: { cty: 'text/plain' } }],
      nonceAllocator: allocator(),
      protectedHeader: { cty: 'application/json' },
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'header_name_collision');
    }
  });
});
