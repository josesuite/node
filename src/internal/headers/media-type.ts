/**
 * Normalizes a `typ` or `cty` media type to a single canonical spelling, so that
 * type checks compare meaning rather than formatting.
 *
 * Both members are attacker-controlled and are compared to decide whether a
 * token is the kind the caller expected, so every input that denotes one type
 * must reduce to one string. Anything unrecognized returns `undefined` and is
 * rejected by the caller rather than being passed through as-is.
 */

/** RFC 9110 token characters; excludes the separators a parameter would need. */
const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
const MEDIA_TYPE = new RegExp(`^(${TOKEN})/(${TOKEN})$`);

export function normalizeMediaType(value: string): string | undefined {
  // Parameters are refused outright rather than stripped: two types differing
  // only in a parameter would otherwise compare as equal.
  if (value.includes(';')) {
    return undefined;
  }

  // JOSE permits omitting the `application/` prefix, so `JWT` and
  // `application/JWT` name one type and must not compare as different.
  const full = value.includes('/') ? value : `application/${value}`;
  const match = MEDIA_TYPE.exec(full);

  // Type and subtype are case-insensitive, so they fold to lowercase; a
  // parameter value would not be foldable, which is why none is accepted.
  return match === null ? undefined : `${match[1]!.toLowerCase()}/${match[2]!.toLowerCase()}`;
}
