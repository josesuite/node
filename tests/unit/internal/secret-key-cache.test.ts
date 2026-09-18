import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { randomBytes } from 'node:crypto';

import { secretKeyCached } from '../../../src/internal/crypto/node.ts';

describe('native secret-key handle cache', () => {
  test('creates one handle per token and reuses it', () => {
    const token = {};
    const material = randomBytes(32);

    const first = secretKeyCached(token, material);
    const second = secretKeyCached(token, material);

    assert.strictEqual(second, first);
    assert.strictEqual(first.type, 'secret');
    assert.strictEqual(first.symmetricKeySize, 32);
  });

  test('keeps tokens independent, so one key never serves another', () => {
    const first = secretKeyCached({}, randomBytes(32));
    const second = secretKeyCached({}, randomBytes(32));

    assert.notStrictEqual(second, first);
  });

  test('creates a fresh handle every time when no token is supplied', () => {
    // An absent token means the caller holds no record to key on, so reuse
    // would have to be keyed on key material, which this cache never does.
    const material = randomBytes(32);
    assert.notStrictEqual(secretKeyCached(undefined, material), secretKeyCached(undefined, material));
  });

  test('the handle holds a copy, so later mutation of the source is not observed', () => {
    const material = randomBytes(32);
    const handle = secretKeyCached({}, material);
    material.fill(0);

    assert.notDeepStrictEqual(new Uint8Array(handle.export()), new Uint8Array(32));
  });
});
