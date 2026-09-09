/**
 * Byte ownership helpers.
 *
 * Trust boundaries copy caller-owned buffers so that a caller cannot mutate
 * authenticated input after it has been validated, and copy outbound buffers so
 * that a caller cannot reach back into retained internal state. Without those
 * copies a caller could change bytes between the moment they are checked and
 * the moment they are used.
 */

/**
 * Copies into a buffer WebCrypto will accept.
 *
 * `BufferSource` excludes views backed by a `SharedArrayBuffer`, which a caller
 * could otherwise mutate concurrently while the provider reads it. Copying into
 * a buffer this library allocated satisfies the type and removes that race in
 * one step.
 */
export function toBufferSource(input: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(input.length));
  copy.set(input);
  return copy;
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
