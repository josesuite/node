/**
 * Recognized-parameter type validation, critical-extension processing, and
 * `b64` resolution.
 */

import type { ErrorCategory } from '../../errors/codes.ts';
import { LIMITS_V1, type Limits } from '../../policy/limits.ts';
import { utf8Length } from '../encoding/utf8.ts';
import type { JsonValue } from '../json/types.ts';
import type { MergedHeader } from './types.ts';

export interface HeaderRejection {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly reason: string;
}

export type HeaderCheck = { readonly ok: true } | HeaderRejection;

const OK: HeaderCheck = { ok: true };

function reject(category: ErrorCategory, reason: string): HeaderRejection {
  return { ok: false, category, reason };
}

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

/** A header member value a caller may supply at creation. */
export type SuppliedHeaderValue = string | boolean | string[] | undefined;

/**
 * Checks a caller-supplied header member against the fixed JSON type of the
 * parameter it names.
 *
 * A producer must not emit what its corresponding consumer refuses, so the same
 * recognized-parameter types apply in both directions. Unrecognized names carry
 * no fixed type and pass through.
 */
export function checkSuppliedParameterType(name: string, value: SuppliedHeaderValue): boolean {
  if (name === 'crit') {
    return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
  }
  if (name === 'x5c') {
    return Array.isArray(value) && value.length > 0 && value.every((entry) => validCertificateEncoding(entry));
  }
  if (name === 'b64') {
    return typeof value === 'boolean';
  }
  return !STRING_PARAMETER_NAMES.has(name) || typeof value === 'string';
}

const STRING_PARAMETER_NAMES: ReadonlySet<string> = new Set<string>(STRING_PARAMETERS);

export function validateParameterTypes(header: MergedHeader, limits: Limits = LIMITS_V1): HeaderCheck {
  for (const name of STRING_PARAMETERS) {
    const parameter = header.parameters.get(name);
    if (parameter === undefined) {
      continue;
    }
    if (parameter.value.kind !== 'string') {
      return reject('invalid_header', 'parameter_not_a_string');
    }
  }

  for (const name of OBJECT_PARAMETERS) {
    const parameter = header.parameters.get(name);
    if (parameter === undefined) {
      continue;
    }
    if (parameter.value.kind !== 'object') {
      return reject('invalid_header', 'parameter_not_an_object');
    }
  }

  const x5c = header.parameters.get('x5c');
  if (x5c !== undefined) {
    if (x5c.value.kind !== 'array' || x5c.value.elements.length === 0) {
      return reject('invalid_header', 'x5c_not_a_nonempty_array');
    }
    for (const certificate of x5c.value.elements) {
      if (certificate.kind !== 'string' || !validCertificateEncoding(certificate.value, limits)) {
        return reject('invalid_header', 'x5c_entry_invalid');
      }
    }
  }

  const p2c = header.parameters.get('p2c');
  if (p2c !== undefined && p2c.value.kind !== 'number') {
    return reject('invalid_header', 'p2c_not_a_number');
  }

  const kid = header.parameters.get('kid');
  if (kid !== undefined && kid.value.kind === 'string') {
    // A key identifier is opaque bounded data, never a path or query. Its size
    // is checked before it is ever used to narrow a key namespace, so an
    // oversized attacker-supplied value cannot reach a lookup.
    if (utf8Length(kid.value.value) > limits.kid) {
      return reject('resource_limit', 'kid_too_long');
    }
  }

  return OK;
}

function validCertificateEncoding(value: string, limits: Limits = LIMITS_V1): boolean {
  if (value.length === 0 || value.length > Math.ceil((limits.derCertificate * 4) / 3) + 2) {
    return false;
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return false;
  }
  const bytes = Buffer.from(value, 'base64');
  return bytes.length > 0 && bytes.length <= limits.derCertificate && bytes.toString('base64') === value;
}

export interface CriticalResult {
  readonly ok: true;
  /** Names listed in `crit`, in source order. Empty when `crit` is absent. */
  readonly names: readonly string[];
}

/**
 * A list that is structurally sound but names an extension without implemented
 * semantics. The names are still reported: the parameters they refer to were
 * validly declared, and a whole-object check may need the declared value even
 * though this entry cannot itself be accepted.
 */
export interface CriticalUnimplemented {
  readonly ok: false;
  readonly category: 'unsupported_critical_parameter';
  readonly reason: 'critical_extension_not_implemented';
  readonly names: readonly string[];
}

export type CriticalCheck = CriticalResult | CriticalUnimplemented | HeaderRejection;

/**
 * Validates `crit` construction and confirms every listed extension has
 * implemented semantics.
 *
 * `crit` must be protected, nonempty, an array of distinct strings, and every
 * listed name must be present in the header. A listed name whose semantics are
 * not implemented is rejected outright, which is what keeps a critical
 * extension from degrading into an ignored hint: the producer marked it as
 * something the recipient must act on, so proceeding without acting on it would
 * accept an object under weaker terms than the producer intended.
 */
export function validateCritical(header: MergedHeader, context: JoseContext): CriticalCheck {
  const parameter = header.parameters.get('crit');
  if (parameter === undefined) {
    return { ok: true, names: [] };
  }

  // The critical list itself must be protected. An unprotected list
  // could be stripped or rewritten in transit without invalidating the
  // signature.
  if (parameter.origin !== 'protected') {
    return reject('invalid_header', 'crit_not_protected');
  }

  const value: JsonValue = parameter.value;
  if (value.kind !== 'array') {
    return reject('invalid_header', 'crit_not_an_array');
  }
  if (value.elements.length === 0) {
    return reject('invalid_header', 'crit_empty');
  }

  const names: string[] = [];
  const seen = new Set<string>();
  let unimplemented = false;

  for (const element of value.elements) {
    if (element.kind !== 'string') {
      return reject('invalid_header', 'crit_entry_not_a_string');
    }
    const name = element.value;

    if (seen.has(name)) {
      return reject('invalid_header', 'crit_duplicate_name');
    }
    seen.add(name);

    // A base-specification parameter is not an extension; listing one is a
    // malformed critical list rather than an unsupported extension request.
    if (BASE_PARAMETER_NAMES[context].has(name)) {
      return reject('invalid_header', 'crit_names_base_parameter');
    }

    // Every listed name must actually be present in the header.
    if (!header.parameters.has(name)) {
      return reject('invalid_header', 'crit_names_absent_parameter');
    }

    names.push(name);

    // Recorded rather than returned immediately, so the remaining names are
    // still checked for the malformed-list defects above, which take precedence.
    if (!IMPLEMENTED_CRITICAL_EXTENSIONS[context].has(name)) {
      unimplemented = true;
    }
  }

  if (unimplemented) {
    return {
      ok: false,
      category: 'unsupported_critical_parameter',
      reason: 'critical_extension_not_implemented',
      names,
    };
  }

  return { ok: true, names };
}
