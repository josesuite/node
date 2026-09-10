import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { parseJson } from '../../../src/internal/json/parse.ts';
import type { JsonObject } from '../../../src/internal/json/types.ts';
import { importKey, type UsableKey } from '../../../src/key/import.ts';
import { allRequiredSigners, namedSigner, thresholdOfSigners } from '../../../src/jws/aggregate.ts';
import { signJson } from '../../../src/jws/sign-json.ts';
import { type TrustedSigner, verifyJson } from '../../../src/jws/verify-json.ts';
import { AlgorithmPolicy } from '../../../src/policy/algorithms.ts';
import { LIMITS_V1, lowerLimits } from '../../../src/policy/limits.ts';
import { flipBit } from '../../helpers/runtime.ts';

function object(value: Record<string, unknown>): JsonObject {
  const result = parseJson(new TextEncoder().encode(JSON.stringify(value)), LIMITS_V1);
  if (!result.ok || result.value.kind !== 'object') {
    throw new Error('bad fixture');
  }
  return result.value;
}

function key(jwk: Record<string, unknown>, algorithm: string, operation: 'sign' | 'verify'): UsableKey {
  const result = importKey(object(jwk), { algorithm, operation });
  if (!result.ok) {
    throw new Error(`import failed: ${result.reason}`);
  }
  return result.key;
}

/**
 * A signer whose signing and verification keys are the same EC key pair.
 *
 * Each key carries a `kid` because exactly one key must be eligible per
 * signature entry: with several trusted keys sharing an algorithm, the hint is
 * what narrows the set to one rather than leaving the entry ambiguous.
 */
function ecSigner(principalId: string, algorithm = 'ES256', curve = 'P-256') {
  const generated = generateKeyPairSync('ec', { namedCurve: curve });
  const priv = generated.privateKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
  const pub = generated.publicKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
  return {
    principalId,
    kid: principalId,
    signing: key({ ...priv, kid: principalId }, algorithm, 'sign'),
    verification: key({ ...pub, kid: principalId }, algorithm, 'verify'),
  };
}

function macSigner(principalId: string) {
  const jwk = { kty: 'oct', k: randomBytes(32).toString('base64url'), kid: principalId };
  return {
    principalId,
    kid: principalId,
    signing: key(jwk, 'HS256', 'sign'),
    verification: key(jwk, 'HS256', 'verify'),
  };
}

const PAYLOAD = new TextEncoder().encode('{"sub":"alice"}');

async function sign(
  signers: readonly { signing: UsableKey; kid: string }[],
  algorithms: readonly string[],
  extra = {},
) {
  const result = await signJson(PAYLOAD, {
    policy: AlgorithmPolicy.create('jws', algorithms, 'create'),
    // The `kid` is published so a verifier holding several trusted keys can
    // narrow each entry to exactly one.
    signers: signers.map((s) => ({ key: s.signing, protectedHeader: { kid: s.kid } })),
    limits: LIMITS_V1,
    ...extra,
  });
  if (!result.ok) {
    throw new Error(`sign failed: ${result.reason}`);
  }
  return result.value;
}

async function verify(
  serialized: string,
  trusted: readonly TrustedSigner[],
  aggregate: ReturnType<typeof namedSigner>,
  algorithms: readonly string[] = ['ES256'],
  extra = {},
) {
  if (!aggregate.ok) {
    throw new Error('bad aggregate fixture');
  }
  return await verifyJson(new TextEncoder().encode(serialized), {
    policy: AlgorithmPolicy.create('jws', algorithms, 'receive'),
    aggregate: aggregate.policy,
    signers: trusted,
    limits: LIMITS_V1,
    ...extra,
  });
}

function trust(...signers: readonly { principalId: string; verification: UsableKey }[]): TrustedSigner[] {
  return signers.map((s) => ({ principalId: s.principalId, key: s.verification }));
}

describe('round trips', () => {
  test('verifies a general JWS with one signature', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    assert.strictEqual(JSON.parse(serialized).signatures.length, 1);

    const result = await verify(serialized, trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), '{"sub":"alice"}');
      assert.deepStrictEqual([...result.principals], ['alice']);
      assert.strictEqual(result.entries.length, 1);
    }
  });

  test('verifies a flattened JWS', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256'], { flattened: true });

    const parsed = JSON.parse(serialized);
    assert.strictEqual(parsed.signatures, undefined);
    assert.strictEqual(typeof parsed.signature, 'string');

    assert.strictEqual((await verify(serialized, trust(alice), namedSigner('alice'))).ok, true);
  });

  test('verifies several signatures from different signers', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);

    const result = await verify(serialized, trust(alice, bob), allRequiredSigners(['alice', 'bob']));
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual([...result.principals].toSorted(), ['alice', 'bob']);
    }
  });

  test('carries an unprotected header without authenticating it', async () => {
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      // The hint names the signing key, since a present `kid` is applied as an
      // exact resolution filter wherever it appears. Placement decides what the
      // signature covers, not whether the filter runs.
      signers: [{ key: alice.signing, unprotectedHeader: { kid: alice.kid } }],
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    const verified = await verify(result.value, trust(alice), namedSigner('alice'));
    assert.strictEqual(verified.ok, true);
    if (verified.ok) {
      // The hint is visible but marked as not covered by the signature.
      const kid = verified.entries[0]!.header?.parameters.get('kid');
      assert.strictEqual(kid?.origin, 'per_entry_unprotected');
    }
  });
});

describe('aggregate policy decides acceptance', () => {
  test('rejects when the named signer did not sign', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice], ['ES256']);

    const result = await verify(serialized, trust(alice, bob), namedSigner('bob'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'aggregate_policy_unsatisfied');
      // The valid signature is still reported, it just is not the one required.
      assert.strictEqual(result.entries[0]!.ok, true);
      assert.strictEqual(result.entries[0]!.principalId, 'alice');
    }
  });

  test('rejects when a threshold is not met', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const carol = ecSigner('carol');
    const serialized = await sign([alice], ['ES256']);

    const result = await verify(serialized, trust(alice, bob, carol), thresholdOfSigners(['alice', 'bob', 'carol'], 2));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
    }
  });

  test('accepts once a threshold is met', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const carol = ecSigner('carol');
    const serialized = await sign([alice, bob], ['ES256']);

    const result = await verify(serialized, trust(alice, bob, carol), thresholdOfSigners(['alice', 'bob', 'carol'], 2));
    assert.strictEqual(result.ok, true);
  });

  test('a signer outside the eligible set does not fill a threshold', async () => {
    const alice = ecSigner('alice');
    const mallory = ecSigner('mallory');
    const serialized = await sign([alice, mallory], ['ES256']);

    // Two valid signatures, but only one belongs to an eligible principal.
    const result = await verify(serialized, trust(alice, mallory), thresholdOfSigners(['alice', 'bob'], 2));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.entries.filter((e) => e.ok).length, 2);
    }
  });
});

describe('failed entries do not erase successes', () => {
  test('one valid and one invalid signature from the same signer still satisfies a named policy', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const parsed = JSON.parse(serialized);

    // Append a second entry for the same signer whose signature is corrupt.
    const broken = { ...parsed.signatures[0] };
    const bytes = Buffer.from(flipBit(Buffer.from(broken.signature, 'base64url'), 0, 0xff));
    broken.signature = bytes.toString('base64url');
    parsed.signatures.push(broken);

    const result = await verify(JSON.stringify(parsed), trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual([...result.principals], ['alice']);
      // Both entries keep their own outcome.
      assert.strictEqual(result.entries.length, 2);
      assert.strictEqual(result.entries.filter((e) => e.ok).length, 1);
      assert.strictEqual(result.entries.filter((e) => !e.ok).length, 1);
    }
  });

  test('every entry is evaluated rather than stopping at the first failure', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);
    const parsed = JSON.parse(serialized);

    // Corrupt the first entry; the second must still be evaluated.
    const bytes = Buffer.from(flipBit(Buffer.from(parsed.signatures[0].signature, 'base64url'), 0, 0xff));
    parsed.signatures[0].signature = bytes.toString('base64url');

    const result = await verify(JSON.stringify(parsed), trust(alice, bob), namedSigner('bob'));
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.entries[0]!.ok, false);
      assert.strictEqual(result.entries[1]!.ok, true);
      assert.deepStrictEqual([...result.principals], ['bob']);
    }
  });

  test('duplicate successful entries for one signer count once', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const parsed = JSON.parse(serialized);
    parsed.signatures.push({ ...parsed.signatures[0] });

    // Two valid entries, but one principal, so a two-signer threshold fails.
    const result = await verify(JSON.stringify(parsed), trust(alice), thresholdOfSigners(['alice', 'bob'], 2));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.entries.filter((e) => e.ok).length, 2);
      assert.strictEqual(result.category, 'policy_violation');
    }
  });
});

describe('whole-object rejection', () => {
  test('a prohibited algorithm in any entry rejects the object', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const parsed = JSON.parse(serialized);

    // A second entry naming `none`, which would never have been selected.
    parsed.signatures.push({
      protected: Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
      signature: 'AAAA',
    });

    const result = await verify(JSON.stringify(parsed), trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      // Rejected before any entry is evaluated, so the valid one does not save it.
      assert.strictEqual(result.category, 'prohibited_algorithm');
      assert.strictEqual(result.entries.length, 0);
    }
  });

  test('a prohibited algorithm outranks a later undecodable header', async () => {
    // The prohibited entry comes first. Returning on the later syntax defect
    // instead would report a lesser category for an object that is unreachable.
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const parsed = JSON.parse(serialized);

    parsed.signatures.push({
      protected: Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
      signature: 'AAAA',
    });
    parsed.signatures.push({ protected: 'not!base64url', signature: 'AAAA' });

    const result = await verify(JSON.stringify(parsed), trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'prohibited_algorithm');
    }
  });

  test('a malformed signature encoding rejects the object beside a valid entry', async () => {
    // The valid entry alone satisfies the policy, so treating the bad encoding
    // as one entry's failure would accept a structurally broken object.
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);
    const parsed = JSON.parse(serialized);

    parsed.signatures[1].signature = 'not!base64url';

    const result = await verify(JSON.stringify(parsed), trust(alice, bob), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_encoding');
      assert.strictEqual(result.reason, 'signature_invalid');
      assert.deepStrictEqual(result.entries, []);
    }
  });

  test('an entry declaring b64 alongside an unknown critical extension still counts toward agreement', async () => {
    // The unimplemented extension fails this entry, but it declared `b64:false`
    // while the other entry is encoded. Skipping its declared value would let a
    // contradictory object through on the strength of the entry that verified.
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);
    const parsed = JSON.parse(serialized);

    parsed.signatures[1].protected = Buffer.from(
      JSON.stringify({ alg: 'ES256', b64: false, unknown: 1, crit: ['b64', 'unknown'] }),
    ).toString('base64url');

    const result = await verify(JSON.stringify(parsed), trust(alice, bob), namedSigner('alice'), ['ES256'], {
      unencodedPayload: true,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'inconsistent_b64_across_signatures');
    }
  });

  test('entries disagreeing about payload encoding reject the object', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);
    const parsed = JSON.parse(serialized);

    // Rewrite one entry to claim an unencoded payload.
    parsed.signatures[1].protected = Buffer.from(JSON.stringify({ alg: 'ES256', b64: false, crit: ['b64'] })).toString(
      'base64url',
    );

    // Unencoded mode is enabled, so only the disagreement itself rejects this.
    const result = await verify(JSON.stringify(parsed), trust(alice, bob), namedSigner('alice'), ['ES256'], {
      unencodedPayload: true,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'inconsistent_b64_across_signatures');
      assert.strictEqual(result.category, 'invalid_header');
    }
  });

  test('rejects an unencoded payload the caller never enabled', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const parsed = JSON.parse(serialized);

    parsed.signatures[0].protected = Buffer.from(JSON.stringify({ alg: 'ES256', b64: false, crit: ['b64'] })).toString(
      'base64url',
    );

    const result = await verify(JSON.stringify(parsed), trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'unencoded_payload_not_accepted');
    }
  });
});

describe('key resolution', () => {
  test('reports an entry with no eligible key without failing the object', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);

    // Only alice's key is trusted; bob's entry names a `kid` absent from the
    // snapshot, so it resolves to no key rather than being tried against alice's.
    const result = await verify(serialized, trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual([...result.principals], ['alice']);
      const failed = result.entries.find((e) => !e.ok);
      assert.strictEqual(failed?.category, 'key_resolution_failure');
    }
  });

  test('a token cannot introduce a key or a principal', async () => {
    const alice = ecSigner('alice');
    const mallory = ecSigner('mallory');
    // Signed with no published `kid`, so alice's name can be planted in the
    // unprotected header without colliding with a protected one.
    const serialized = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: mallory.signing }],
      limits: LIMITS_V1,
    });
    if (!serialized.ok) {
      throw new Error('sign failed');
    }
    const parsed = JSON.parse(serialized.value);

    parsed.signatures[0].header = { kid: 'alice' };

    const result = await verify(JSON.stringify(parsed), trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'policy_violation');
      assert.strictEqual(result.reason, 'aggregate_policy_unsatisfied');
    }
  });

  test('a header collision rejects the object rather than one entry', async () => {
    // The valid entry would otherwise satisfy the policy, letting a malformed
    // object be accepted because the defect landed on an entry nobody counted.
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);
    const parsed = JSON.parse(serialized);

    parsed.signatures[1].header = { kid: 'bob' };

    const result = await verify(JSON.stringify(parsed), trust(alice, bob), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
      // No entry ran, so none carries a status to report.
      assert.deepStrictEqual(result.entries, []);
    }
  });
});

describe('detached payloads', () => {
  test('round trips a detached payload', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256'], { detached: true });
    assert.strictEqual(JSON.parse(serialized).payload, undefined);

    const result = await verify(serialized, trust(alice), namedSigner('alice'), ['ES256'], {
      detachedPayload: PAYLOAD,
    });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(new TextDecoder().decode(result.payload), '{"sub":"alice"}');
    }
  });

  test('rejects an absent payload when none was supplied', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256'], { detached: true });

    // Detachment is never inferred from the missing member.
    const result = await verify(serialized, trust(alice), namedSigner('alice'));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'payload_missing');
    }
  });

  test('rejects supplying both an embedded and an external payload', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    const result = await verify(serialized, trust(alice), namedSigner('alice'), ['ES256'], {
      detachedPayload: PAYLOAD,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'ambiguous_payload_source');
    }
  });
});

describe('MAC entries', () => {
  test('a MAC signature establishes its shared-secret principal', async () => {
    const alice = macSigner('alice-hmac');
    const serialized = await sign([alice], ['HS256']);

    // Counting a MAC-backed principal requires a profile that treats it as a
    // shared-secret domain rather than an independently attributable signer.
    const result = await verify(serialized, trust(alice), namedSigner('alice-hmac'), ['HS256'], {
      sharedSecretDomains: true,
    });
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.deepStrictEqual([...result.principals], ['alice-hmac']);
    }
  });

  test('a MAC principal is not counted without the shared-secret profile', async () => {
    const alice = macSigner('alice-hmac');
    const serialized = await sign([alice], ['HS256']);

    // A MAC proves only that some holder of the secret produced the entry, so
    // without the explicit profile it cannot satisfy a signer policy.
    const result = await verify(serialized, trust(alice), namedSigner('alice-hmac'), ['HS256']);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'configuration');
      assert.strictEqual(result.reason, 'mac_principal_requires_shared_secret_profile');
    }
  });
});

describe('trusted signer configuration', () => {
  test('refuses one key bound to two principals', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    // The same material under two principals makes a signature's signer
    // indeterminate, so a threshold over them would be meaningless.
    const aliased: TrustedSigner[] = [
      { principalId: 'alice', key: alice.verification },
      { principalId: 'alice-alias', key: alice.verification },
    ];
    const result = await verify(serialized, aliased, thresholdOfSigners(['alice', 'alice-alias'], 2));
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'configuration');
      assert.strictEqual(result.reason, 'shared_key_material_across_principals');
    }
  });

  test('refuses equivalent HMAC domains across principals', async () => {
    const alice = macSigner('alice-hmac');
    const serialized = await sign([alice], ['HS256']);

    // Distinct secret bytes are not evidence of distinct MAC capabilities; the
    // same secret under two principals is one authentication domain.
    const aliased: TrustedSigner[] = [
      { principalId: 'alice-hmac', key: alice.verification },
      { principalId: 'other-hmac', key: alice.verification },
    ];
    const result = await verify(serialized, aliased, thresholdOfSigners(['alice-hmac', 'other-hmac'], 2), ['HS256'], {
      sharedSecretDomains: true,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'configuration');
      assert.strictEqual(result.reason, 'shared_key_material_across_principals');
    }
  });

  test('refuses an aggregate policy that references no principal', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    // Hand-built rather than produced by a constructor: an empty required set
    // would otherwise be satisfied without any valid signature.
    const result = await verify(serialized, trust(alice), {
      ok: true,
      policy: { kind: 'all', required: new Set<string>() },
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'configuration');
      assert.strictEqual(result.reason, 'aggregate_policy_references_no_principal');
    }
  });
});

describe('creation guards', () => {
  test('bounds signer count, payload bytes, and protected header bytes', async () => {
    const alice = ecSigner('alice');
    const policy = AlgorithmPolicy.create('jws', ['ES256'], 'create');
    const cases = [
      signJson(PAYLOAD, { policy, signers: [{ key: alice.signing }], limits: lowerLimits({ signatures: 0 }) }),
      signJson(PAYLOAD, { policy, signers: [{ key: alice.signing }], limits: lowerLimits({ payload: 0 }) }),
      signJson(PAYLOAD, { policy, signers: [{ key: alice.signing }], limits: lowerLimits({ headerSource: 1 }) }),
    ];

    for (const result of await Promise.all(cases)) {
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'resource_limit');
      }
    }
  });

  test('refuses a public signing key', async () => {
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: alice.verification }],
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'signing_requires_private_key');
    }
  });

  test('refuses a private key bound to verification', async () => {
    const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateJwk = generated.privateKey.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: key(privateJwk, 'ES256', 'verify') }],
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'key_operation_mismatch');
    }
  });

  test('refuses the flattened form with several signers', async () => {
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: alice.signing }, { key: bob.signing }],
      limits: LIMITS_V1,
      flattened: true,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'flattened_requires_single_signature');
    }
  });

  test('refuses a header name appearing in both sources', async () => {
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [
        {
          key: alice.signing,
          protectedHeader: { kid: 'a' },
          unprotectedHeader: { kid: 'b' },
        },
      ],
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'header_name_collision');
    }
  });

  test('compares only supplied header names', async () => {
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [
        {
          key: alice.signing,
          protectedHeader: { ['__proto__']: 'protected' },
          unprotectedHeader: { constructor: 'unprotected' },
        },
      ],
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, true);
    if (result.ok) {
      const value = JSON.parse(result.value);
      assert.strictEqual(value.signatures[0].header.constructor, 'unprotected');
      assert.deepStrictEqual(JSON.parse(Buffer.from(value.signatures[0].protected, 'base64url').toString()), {
        ['__proto__']: 'protected',
        alg: 'ES256',
      });
    }
  });

  test('refuses a wrong-type recognized header', async () => {
    // A recognized parameter's JSON type is fixed, and a producer emitting the
    // wrong one builds an object its corresponding consumer rejects.
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: alice.signing, protectedHeader: { kid: ['not', 'a', 'string'] } }],
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'invalid_header');
      assert.strictEqual(result.reason, 'header_kid_wrong_type');
    }
  });

  test('refuses an empty unprotected header', async () => {
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: alice.signing, unprotectedHeader: {} }],
      limits: LIMITS_V1,
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'unprotected_header_empty');
    }
  });

  test('refuses a caller header overriding the algorithm', async () => {
    const alice = ecSigner('alice');
    for (const name of ['alg', 'b64', 'crit']) {
      const result = await signJson(PAYLOAD, {
        policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
        signers: [{ key: alice.signing, protectedHeader: { [name]: 'x' } }],
        limits: LIMITS_V1,
      });
      assert.strictEqual(result.ok, false);
    }
  });

  test('refuses signing with no signers', async () => {
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [],
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'no_signers');
    }
  });
});

describe('key resolution requires exactly one eligible key', () => {
  test('rejects an entry as ambiguous when several keys are eligible', async () => {
    // Two trusted keys share an algorithm and neither is narrowed by a hint,
    // so which principal a valid signature belongs to is undetermined.
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: alice.signing }],
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    const verified = await verify(result.value, trust(alice, bob), namedSigner('alice'));
    assert.strictEqual(verified.ok, false);
    if (!verified.ok) {
      assert.strictEqual(verified.entries[0]!.category, 'key_resolution_failure');
      assert.strictEqual(verified.entries[0]!.reason, 'ambiguous_key');
    }
  });

  test('a kid naming another principal cannot reattribute a signature', async () => {
    const alice = ecSigner('alice');
    const mallory = ecSigner('mallory');

    // Mallory signs but publishes alice's kid.
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: mallory.signing, protectedHeader: { kid: 'alice' } }],
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    // The hint selects alice's key, under which the signature does not verify.
    const verified = await verify(result.value, trust(alice, mallory), namedSigner('alice'));
    assert.strictEqual(verified.ok, false);
    if (!verified.ok) {
      assert.strictEqual(verified.entries[0]!.category, 'signature_verification_failure');
      assert.strictEqual(verified.entries[0]!.principalId, undefined);
    }
  });

  test('an unmatched kid resolves to no key rather than falling back', async () => {
    const alice = ecSigner('alice');
    const result = await signJson(PAYLOAD, {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'create'),
      signers: [{ key: alice.signing, protectedHeader: { kid: 'no-such-key' } }],
      limits: LIMITS_V1,
    });
    assert.strictEqual(result.ok, true);
    if (!result.ok) {
      return;
    }

    // A present `kid` is an exact filter. Naming a key absent from the snapshot
    // must not fall back to a differently-named trusted key, even when that key
    // is the only candidate and the signature would verify under it.
    const verified = await verify(result.value, trust(alice), namedSigner('alice'));
    assert.strictEqual(verified.ok, false);
    if (!verified.ok) {
      assert.strictEqual(verified.entries[0]!.category, 'key_resolution_failure');
      assert.strictEqual(verified.entries[0]!.reason, 'no_eligible_key');
    }
  });
});

describe('resource limits reach the whole operation', () => {
  test('accounts cryptographic attempts without a caller-supplied budget', async () => {
    // A standalone operation owns its budget. Accounting only when an enclosing
    // caller passes one in would leave every direct call unbounded.
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    const result = await verify(serialized, trust(alice), namedSigner('alice'), ['ES256'], {
      limits: lowerLimits({ cryptographicAttempts: 0 }),
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      const entry = result.entries[0]!;
      assert.strictEqual(entry.category, 'resource_limit');
      assert.strictEqual(entry.reason, 'cryptographic_attempt_budget_exceeded');
    }
  });

  test('charges one attempt per entry', async () => {
    // The object's entry count decides how many verifications are performed, so
    // a budget of one admits the first entry and stops at the second.
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);

    const result = await verify(serialized, trust(alice, bob), namedSigner('alice'), ['ES256'], {
      limits: lowerLimits({ cryptographicAttempts: 1 }),
    });

    assert.strictEqual(result.entries.length, 2);
    assert.strictEqual(result.entries[0]!.ok, true);
    assert.strictEqual(result.entries[1]!.reason, 'cryptographic_attempt_budget_exceeded');
  });

  test('exhausting the budget rejects the object even when the policy is already satisfied', async () => {
    // The entry that exhausts the budget leaves the remaining entries
    // unevaluated. An earlier success must not carry the aggregate decision on
    // an evaluation that never completed, so exhaustion is object-scoped.
    const alice = ecSigner('alice');
    const bob = ecSigner('bob');
    const serialized = await sign([alice, bob], ['ES256']);

    const result = await verify(serialized, trust(alice, bob), namedSigner('alice'), ['ES256'], {
      limits: lowerLimits({ cryptographicAttempts: 1 }),
    });

    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'cryptographic_attempt_budget_exceeded');
      // The entry that succeeded before exhaustion is still reported.
      assert.strictEqual(result.entries[0]!.ok, true);
    }
  });
});

describe('the operation decides on the configuration it validated', () => {
  test('mutating the aggregate policy after the call does not change the decision', async () => {
    // The policy stays caller-owned and is applied after the provider awaits.
    // Repointing it mid-flight would let the decision rest on a predicate the
    // configuration checks never saw.
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    const aggregate = { kind: 'named' as const, principalId: 'alice' };
    const pending = verifyJson(new TextEncoder().encode(serialized), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      aggregate,
      signers: trust(alice),
      limits: LIMITS_V1,
    });

    aggregate.principalId = 'mallory';

    assert.strictEqual((await pending).ok, true);
  });

  test('mutating the signer list after the call does not change the candidates', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    const signers = trust(alice);
    const pending = verifyJson(new TextEncoder().encode(serialized), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      aggregate: { kind: 'named', principalId: 'alice' },
      signers,
      limits: LIMITS_V1,
    });

    signers.length = 0;

    assert.strictEqual((await pending).ok, true);
  });
});

function assertConfigurationFailure(result: Awaited<ReturnType<typeof verifyJson>>, reason: string): void {
  assert.strictEqual(result.ok, false);
  if (!result.ok) {
    assert.strictEqual(result.stage, 'configuration');
    assert.strictEqual(result.reason, reason);
  }
}

describe('trusted signer configuration', () => {
  async function verifyWith(trusted: readonly TrustedSigner[], extra: Record<string, unknown> = {}) {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const aggregate = namedSigner('alice');
    if (!aggregate.ok) {
      throw new Error('bad aggregate fixture');
    }
    return verifyJson(new TextEncoder().encode(serialized), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      aggregate: aggregate.policy,
      signers: trusted,
      limits: LIMITS_V1,
      ...extra,
    });
  }

  test('rejects an empty signer list', async () => {
    assertConfigurationFailure(await verifyWith([]), 'no_trusted_signers');
  });

  test('rejects more signers than the key limit allows', async () => {
    const many = Array.from({ length: 4 }, (_, index) => ecSigner(`signer-${index}`));
    const result = await verifyWith(trust(...many), { limits: lowerLimits({ jwksKeys: 3 }) });
    assertConfigurationFailure(result, 'too_many_trusted_signers');
  });

  test('rejects a signer whose principal identifier is empty', async () => {
    const alice = ecSigner('alice');
    assertConfigurationFailure(await verifyWith([{ principalId: '', key: alice.verification }]), 'principal_id_empty');
  });

  test('rejects an aggregate policy that no signature could satisfy', async () => {
    const alice = ecSigner('alice');
    // A hand-built policy can reach here without passing its constructor; one
    // referencing no principal would be satisfied by no signatures at all.
    const result = await verifyWith(trust(alice), {
      aggregate: { kind: 'threshold', required: 0, eligible: new Set<string>() },
    });
    assertConfigurationFailure(result, 'aggregate_policy_references_no_principal');
  });

  test('rejects one key bound to two principals', async () => {
    // A signature under shared material would have no determinate signer, so
    // the pair is refused rather than either binding being preferred.
    const alice = ecSigner('alice');
    const result = await verifyWith([
      { principalId: 'alice', key: alice.verification },
      { principalId: 'mallory', key: alice.verification },
    ]);
    assertConfigurationFailure(result, 'shared_key_material_across_principals');
  });

  test('rejects a MAC-backed principal the aggregate counts without a shared-secret profile', async () => {
    // A MAC establishes only that some holder of the secret produced the entry,
    // so counting it toward a distinct-signer policy needs an explicit profile.
    const mac = macSigner('alice');
    assertConfigurationFailure(
      await verifyWith(trust(mac), { policy: AlgorithmPolicy.create('jws', ['HS256'], 'receive') }),
      'mac_principal_requires_shared_secret_profile',
    );
  });

  test('rejects limits that were never lowered from the baseline', async () => {
    const alice = ecSigner('alice');
    const result = await verifyWith(trust(alice), {
      limits: { ...LIMITS_V1, joseInput: LIMITS_V1.joseInput + 1 },
    });
    assertConfigurationFailure(result, 'limit_joseInput_exceeds_baseline');
  });
});

describe('JSON verification entry paths', () => {
  async function verifyRaw(serialized: string, extra: Record<string, unknown> = {}) {
    const alice = ecSigner('alice');
    const aggregate = namedSigner('alice');
    if (!aggregate.ok) {
      throw new Error('bad aggregate fixture');
    }
    return verifyJson(new TextEncoder().encode(serialized), {
      policy: AlgorithmPolicy.create('jws', ['ES256'], 'receive'),
      aggregate: aggregate.policy,
      signers: trust(alice),
      limits: LIMITS_V1,
      ...extra,
    });
  }

  test('rejects an object larger than the configured input limit', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    const result = await verify(serialized, trust(alice), namedSigner('alice'), ['ES256'], {
      limits: lowerLimits({ joseInput: 32 }),
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'input_too_large');
    }
  });

  test('distinguishes the JSON failure modes that reject the document', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    // Truncation and a repeated member are both structural defects in the
    // document rather than defects in how its octets were encoded.
    for (const source of [serialized.slice(0, serialized.length - 1), `{"payload":"a",${serialized.slice(1)}`]) {
      const result = await verifyRaw(source);
      assert.strictEqual(result.ok, false);
      if (!result.ok) {
        assert.strictEqual(result.category, 'malformed_input');
      }
    }

    // Octets that are not UTF-8 at all fail as an encoding defect instead.
    const invalidUtf8 = await verifyRaw(Buffer.from([0xff, 0xfe, 0xfd]).toString('latin1'));
    assert.strictEqual(invalidUtf8.ok, false);
    if (!invalidUtf8.ok) {
      assert.strictEqual(invalidUtf8.category, 'malformed_input');
    }

    const deep = await verifyRaw(serialized, { limits: lowerLimits({ jsonDepth: 1 }) });
    assert.strictEqual(deep.ok, false);
    if (!deep.ok) {
      assert.strictEqual(deep.category, 'resource_limit');
    }
  });

  test('bounds the cryptographic layers a single call may consume', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);

    const result = await verify(serialized, trust(alice), namedSigner('alice'), ['ES256'], {
      limits: lowerLimits({ cryptographicLayers: 0 }),
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.reason, 'too_many_cryptographic_layers');
    }
  });

  test('rejects a rewritten payload at the signature rather than at decoding', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256']);
    const parsed = JSON.parse(serialized) as Record<string, unknown>;

    // The signature covers the payload component, so any rewrite fails
    // verification before the deferred decode is ever reached.
    const tampered = JSON.stringify({ ...parsed, payload: 'not base64url!' });
    const result = await verifyRaw(tampered);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.stage, 'cryptographic');
    }
  });

  test('rejects a detached payload larger than its own bound', async () => {
    const alice = ecSigner('alice');
    const serialized = await sign([alice], ['ES256'], { detached: true });

    const result = await verify(serialized, trust(alice), namedSigner('alice'), ['ES256'], {
      detachedPayload: PAYLOAD,
      limits: lowerLimits({ detachedPayload: 4 }),
    });
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.category, 'resource_limit');
      assert.strictEqual(result.reason, 'detached_payload_too_large');
    }
  });
});
