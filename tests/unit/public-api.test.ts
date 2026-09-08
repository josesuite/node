import { describe, expect, test } from 'bun:test';

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
      expect(jose[name as keyof typeof jose]).toBeFunction();
    }
  });

  test('does not export internal protocol helpers', () => {
    expect('parseJson' in jose).toBe(false);
    expect('recoverCek' in jose).toBe(false);
    expect('signWithKey' in jose).toBe(false);
    expect('importKey' in jose).toBe(false);
    expect('decryptParsed' in jose).toBe(false);
  });
});
