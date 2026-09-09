import { generateKeyPairSync } from 'node:crypto';

/**
 * Whether the current runtime's cryptographic provider supports a curve.
 *
 * Optional curves depend on the Node/OpenSSL provider available on the host.
 * Tests must distinguish "this runtime cannot generate the key" from "the
 * library rejected a valid key" rather than failing indistinguishably.
 */
export function supportsCurve(curve: string): boolean {
  try {
    if (curve === 'Ed25519' || curve === 'Ed448' || curve === 'X25519' || curve === 'X448') {
      generateKeyPairSync(curve.toLowerCase() as 'ed25519');
    } else {
      generateKeyPairSync('ec', { namedCurve: curve });
    }
    return true;
  } catch {
    return false;
  }
}

/** Curves from `candidates` that this runtime's provider can actually generate. */
export function availableCurves(candidates: readonly string[]): readonly string[] {
  return candidates.filter(supportsCurve);
}

/** Flips a bit in a copy of `bytes`, for corrupting signatures, tags, and ciphertext. */
export function flipBit(bytes: Uint8Array, index = 0, mask = 0x01): Uint8Array {
  const copy = new Uint8Array(bytes);
  const current = copy[index];
  if (current === undefined) {
    throw new RangeError('flipBit index out of range');
  }
  copy[index] = current ^ mask;
  return copy;
}
