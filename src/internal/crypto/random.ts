/**
 * Operating-system-backed randomness.
 *
 * `randomBytes` draws from the platform CSPRNG. It is used rather than
 * `Math.random` or any seeded generator because CEKs, IVs, salts, and ephemeral
 * keys must be unpredictable to an attacker who can observe other outputs.
 * There is deliberately no deterministic mode on this path. A production caller
 * must not be able to select a predictable source. Callers needing deterministic
 * input must substitute the whole `RandomSource` instead.
 */

import { randomBytes as nodeRandomBytes } from 'node:crypto';

import { backendError, backendOk, type BackendResult, type RandomSource } from './backend.ts';

export const systemRandom: RandomSource = {
  randomBytes(length: number): BackendResult<Uint8Array> {
    if (!Number.isSafeInteger(length) || length < 0) {
      return backendError('operation_failed');
    }

    let bytes: Buffer;
    try {
      bytes = nodeRandomBytes(length);
    } catch {
      // Generator failure fails closed; there is no weaker fallback source.
      return backendError('unavailable');
    }

    // A short read would silently weaken every key derived from it, so the
    // length is confirmed rather than assumed.
    if (bytes.length !== length) {
      return backendError('unavailable');
    }

    return backendOk(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  },
};
