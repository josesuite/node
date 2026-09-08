/**
 * Constant-time comparison.
 *
 * MAC and authentication-tag comparisons must not leak how many leading bytes
 * matched. A byte-by-byte `===` loop returns early on the first difference,
 * which lets an attacker recover a valid tag one byte at a time by measuring
 * response times, so `timingSafeEqual` is used instead.
 *
 * Timing equivalence here is not a whole-system guarantee: surrounding work,
 * allocation, and provider internals need separate review, and a passing timing
 * measurement cannot prove constant-time behaviour.
 */

import { timingSafeEqual } from 'node:crypto';

import type { ConstantTime } from './backend.ts';

export const constantTime: ConstantTime = {
  equal(a: Uint8Array, b: Uint8Array): boolean {
    // Length is public and `timingSafeEqual` throws on a mismatch, so it is
    // checked first. Returning early here leaks only the length, which an
    // attacker already knows from the encoded object.
    if (a.length !== b.length) {
      return false;
    }
    return timingSafeEqual(a, b);
  },
};
