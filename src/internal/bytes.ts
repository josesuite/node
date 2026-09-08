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
 * Copies into a buffer this library owns exclusively.
 *
 * A `Uint8Array` can be a view onto a larger `ArrayBuffer`; slicing by the
 * view's own offsets is required so a view never exposes neighbouring bytes.
 */
export function copyBytes(input: Uint8Array): Uint8Array {
  const copy = new Uint8Array(input.length);
  copy.set(input);
  return copy;
}

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
