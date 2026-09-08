import { describe, expect, test } from 'bun:test';

import {
  composeNonce,
  GCM_NONCE_BYTES,
  MAX_CREATIONS_PER_KEY,
  type NonceAllocator,
  nonceFailureCategory,
  type NonceResult,
} from '../../../src/jwe/nonce.ts';

describe('nonce composition', () => {
  test('produces 96 bits from a writer identifier and a counter', () => {
    const nonce = composeNonce(1, 2n);

    expect(nonce).toBeDefined();
    expect(nonce!.length).toBe(GCM_NONCE_BYTES);
    expect([...nonce!]).toEqual([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
  });

  test('never repeats across distinct writers at the same counter', () => {
    // Uniqueness across writers is the whole reason the space is split, so it
    // is asserted rather than assumed from the layout.
    const seen = new Set<string>();
    for (let writer = 0; writer < 64; writer += 1) {
      const nonce = composeNonce(writer, 7n);
      seen.add(Buffer.from(nonce!).toString('hex'));
    }
    expect(seen.size).toBe(64);
  });

  test('never repeats across successive counters for one writer', () => {
    const seen = new Set<string>();
    for (let counter = 0n; counter < 64n; counter += 1n) {
      const nonce = composeNonce(9, counter);
      seen.add(Buffer.from(nonce!).toString('hex'));
    }
    expect(seen.size).toBe(64);
  });

  test('accepts the full range of both fields', () => {
    expect(composeNonce(0, 0n)).toBeDefined();
    expect(composeNonce(0xffff_ffff, 0xffff_ffff_ffff_ffffn)).toBeDefined();
  });

  test('refuses values that would not fit their field', () => {
    // A silently truncated writer identifier would alias two writers onto one
    // nonce space, which is exactly the collision the split prevents.
    expect(composeNonce(-1, 0n)).toBeUndefined();
    expect(composeNonce(0x1_0000_0000, 0n)).toBeUndefined();
    expect(composeNonce(1.5, 0n)).toBeUndefined();
    expect(composeNonce(0, -1n)).toBeUndefined();
    expect(composeNonce(0, 0x1_0000_0000_0000_0000n)).toBeUndefined();
  });
});

describe('creation cap', () => {
  test('stops far below the construction ceiling', () => {
    // The cap leaves several orders of magnitude of headroom under the 2^32
    // invocation limit so an accounting error is not immediately fatal.
    expect(MAX_CREATIONS_PER_KEY).toBe(2 ** 24);
    expect(MAX_CREATIONS_PER_KEY).toBeLessThan(2 ** 32);
  });
});

describe('failure mapping', () => {
  test('separates a store outage from a state problem', () => {
    expect(nonceFailureCategory('unavailable')).toBe('backend_failure');
    expect(nonceFailureCategory('exhausted')).toBe('policy_violation');
    expect(nonceFailureCategory('state_uncertain')).toBe('policy_violation');
  });
});

/** A test double standing in for the durable store a deployment supplies. */
function countingAllocator(writerId: number): NonceAllocator {
  const counters = new Map<string, bigint>();

  return {
    reserve(keyIdentity: string): Promise<NonceResult> {
      const next = (counters.get(keyIdentity) ?? 0n) + 1n;
      if (next > BigInt(MAX_CREATIONS_PER_KEY)) {
        return Promise.resolve({ ok: false, failure: 'exhausted' });
      }
      // The reservation is recorded before the value is handed out, so a
      // caller that never uses it burns the nonce rather than reissuing it.
      counters.set(keyIdentity, next);
      return Promise.resolve({ ok: true, reservation: { nonce: composeNonce(writerId, next)! } });
    },
  };
}

describe('allocator contract', () => {
  test('issues a distinct nonce for every reservation under one key', async () => {
    const allocator = countingAllocator(1);
    const seen = new Set<string>();

    for (let i = 0; i < 100; i += 1) {
      const result = await allocator.reserve('key-a');
      expect(result.ok).toBe(true);
      if (result.ok) {
        seen.add(Buffer.from(result.reservation.nonce).toString('hex'));
      }
    }

    expect(seen.size).toBe(100);
  });

  test('keeps separate keys in separate nonce spaces', async () => {
    // Two keys may legitimately use the same nonce value; the requirement is
    // uniqueness per key, not globally.
    const allocator = countingAllocator(1);

    const a = await allocator.reserve('key-a');
    const b = await allocator.reserve('key-b');
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(a.reservation.nonce).toEqual(b.reservation.nonce);
    }
  });

  test('burns a reservation that is never used', async () => {
    // A crash between reservation and encryption must not let the value come
    // back, so the counter advances regardless of what the caller does.
    const allocator = countingAllocator(1);

    const first = await allocator.reserve('key-a');
    const second = await allocator.reserve('key-a');

    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.reservation.nonce).not.toEqual(second.reservation.nonce);
    }
  });

  test('reports exhaustion rather than wrapping the counter', async () => {
    const exhausted: NonceAllocator = {
      reserve: () => Promise.resolve({ ok: false, failure: 'exhausted' }),
    };

    const result = await exhausted.reserve('key-a');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe('exhausted');
      expect(nonceFailureCategory(result.failure)).toBe('policy_violation');
    }
  });

  test('has no default in-memory implementation exported', async () => {
    // An in-memory allocator would satisfy the interface while losing its
    // counter on every restart, so the module must not ship one.
    const module = (await import('../../../src/jwe/nonce.ts')) as Record<string, unknown>;
    const exported = Object.keys(module);

    expect(exported).not.toContain('memoryNonceAllocator');
    expect(exported.filter((name) => name.toLowerCase().includes('default'))).toHaveLength(0);
    for (const name of exported) {
      const value = module[name];
      // Only pure helpers and constants are exported; anything holding state
      // would be an allocator in disguise.
      expect(typeof value === 'function' || typeof value === 'number').toBe(true);
    }
  });
});
