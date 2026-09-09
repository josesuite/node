import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import * as jose from '../../src/index.ts';

describe('public API', () => {
  test('exports the core operations and policy constructors', () => {
    for (const name of [
      'AlgorithmPolicy',
      'buildSnapshot',
      'buildSnapshotBytes',
      'computeThumbprint',
      'createJwt',
      'createJwtProfile',
      'decryptCompact',
      'decryptJson',
      'decryptKeyContainer',
      'encryptCompact',
      'encryptJson',
      'exportEcPublicJwk',
      'getCapabilityReport',
      'importKeyBytes',
      'signCompact',
      'signJson',
      'validateJwt',
      'verifyCompact',
      'verifyJson',
    ]) {
      assert.strictEqual(typeof jose[name as keyof typeof jose], 'function');
    }
  });

  test('does not export internal protocol helpers', () => {
    assert.strictEqual('parseJson' in jose, false);
    assert.strictEqual('recoverCek' in jose, false);
    assert.strictEqual('signWithKey' in jose, false);
    assert.strictEqual('importKey' in jose, false);
    assert.strictEqual('decryptParsed' in jose, false);
  });
});
