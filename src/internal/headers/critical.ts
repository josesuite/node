/**
 * Recognized-parameter type validation, critical-extension processing, and
 * `b64` resolution.
 */

import type { ErrorCategory } from '../../errors/codes.ts';

export interface HeaderRejection {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly reason: string;
}

export type HeaderCheck = { readonly ok: true } | HeaderRejection;

/**
 * Recognized parameters whose JSON type is fixed regardless of whether policy
 * acts on their meaning. A recognized parameter's type is validated even when
 * its meaning is ignored here, so that a malformed value is rejected rather
 * than passed along to a consumer that does interpret it.
 */
const STRING_PARAMETERS = [
  'alg',
  'enc',
  'kid',
  'typ',
  'cty',
  'zip',
  'jku',
  'x5u',
  'x5t',
  'x5t#S256',
  'apu',
  'apv',
  'iv',
  'tag',
  'p2s',
  'iss',
  'sub',
] as const;

const OBJECT_PARAMETERS = ['jwk', 'epk'] as const;

/**
 * Base parameter names and implemented extension semantics are per-context: a
 * parameter registered for one context is an ordinary unrecognized name in the
 * other, and must be classified accordingly rather than by one global set.
 */
export type JoseContext = 'jws' | 'jwe';

/**
 * Parameter names defined by the base JOSE and algorithm specifications, minus
 * those registered for only one context.
 *
 * The critical list must not redeclare any of these. They already have fixed
 * meaning that every implementation processes, so naming one as a critical
 * extension is a construction error rather than a request for extension
 * semantics, and treating it as one would let a producer demand behaviour the
 * name does not define.
 */
const SHARED_BASE_PARAMETER_NAMES: readonly string[] = [
  ...STRING_PARAMETERS.filter((name) => name !== 'enc' && name !== 'zip'),
  ...OBJECT_PARAMETERS,
  'crit',
  'x5c',
  'aud',
];

/**
 * `enc`, `zip`, and the PBES2 parameters are registered for JWE only. In a JWS
 * header such a name selects nothing, so listing it as critical is an
 * unsupported extension request rather than a malformed list naming a base
 * parameter — the specification requires those two cases to be distinguished.
 */
const BASE_PARAMETER_NAMES: Readonly<Record<JoseContext, ReadonlySet<string>>> = Object.freeze({
  jws: new Set(SHARED_BASE_PARAMETER_NAMES),
  jwe: new Set([...SHARED_BASE_PARAMETER_NAMES, 'enc', 'zip', 'p2c']),
});

/**
 * "Understood" means implemented semantics, not name recognition, so an
 * identifier belongs here only once its processing exists. Listing a name here
 * without implementing it would silently downgrade a critical extension into an
 * ignored hint. `b64` is RFC 7797's unencoded-payload option, which is defined
 * for JWS only; JWE implements no critical extension.
 */
const IMPLEMENTED_CRITICAL_EXTENSIONS: Readonly<Record<JoseContext, ReadonlySet<string>>> = Object.freeze({
  jws: new Set(['b64']),
  jwe: new Set<string>(),
});

/**
 * Whether a name is defined by the base JOSE or algorithm specifications for a
 * context, and therefore may not be declared as a critical extension.
 *
 * Shared with creation so a producer applies the same construction rules its
 * corresponding consumer enforces.
 */
export function isBaseParameter(name: string, context: JoseContext): boolean {
  return BASE_PARAMETER_NAMES[context].has(name);
}
