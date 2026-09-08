/**
 * Compact JWS creation.
 *
 * Creation takes an explicit algorithm and a compatible key. It never inspects
 * a caller-supplied header to decide what to do, because header-directed
 * dispatch is how a producer ends up signing under an algorithm it did not
 * intend.
 *
 * Generic signing covers exactly the bytes it is given. It makes no claim about
 * what those bytes mean and performs no application-level validation of them.
 */

import { signWithKey } from '../algorithms/index.ts';
import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { encodeBase64url } from '../internal/encoding/base64url.ts';
import { encodeUtf8 } from '../internal/encoding/utf8.ts';
import { checkSuppliedParameterType } from '../internal/headers/critical.ts';
import type { UsableKey } from '../key/import.ts';
import { type AlgorithmPolicy, decideAlgorithm } from '../policy/algorithms.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import { serializeCompact } from './compact.ts';
import { buildSigningInput, validateInlineUnencodedPayload } from './types.ts';

export type SignResult =
  | { readonly ok: true; readonly token: string }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly stage: TrustStage;
      readonly reason: string;
    };

export interface SignOptions {
  readonly policy: AlgorithmPolicy;
  readonly key: UsableKey;
  readonly limits: Limits;
  /** Additional protected header members. `alg` is supplied by the key binding. */
  readonly protectedHeader?: Readonly<Record<string, string | boolean | string[]>> | undefined;
  /** Omit the payload from the output, for detached mode. */
  readonly detached?: boolean | undefined;
  /** Authenticate the payload octets directly rather than Base64url of them. */
  readonly unencoded?: boolean | undefined;
}

function fail(stage: TrustStage, category: ErrorCategory, reason: string): SignResult {
  return { ok: false, category, stage, reason };
}

/**
 * Signs `payload` and returns a Compact JWS.
 *
 * The algorithm comes from the key's trusted binding rather than from the
 * caller's header, so the two cannot disagree about what was signed.
 */
export async function signCompact(payload: Uint8Array, options: SignOptions): Promise<SignResult> {
  // Limits arrive as a structural value, so a caller can present one that was
  // never lowered from the baseline.
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('configuration', 'policy_violation', limitDefect);
  }

  const algorithm = options.key.algorithm;

  const decision = decideAlgorithm(options.policy, algorithm);
  if (!decision.ok) {
    return fail('configuration', decision.category, decision.reason);
  }

  if (!options.key.isPrivate) {
    return fail('configuration', 'incompatible_key', 'signing_requires_private_key');
  }
  if (options.key.operation !== 'sign') {
    return fail('configuration', 'incompatible_key', 'key_operation_mismatch');
  }
  if (payload.length > options.limits.payload) {
    return fail('configuration', 'resource_limit', 'payload_too_large');
  }

  const unencoded = options.unencoded ?? false;

  if (unencoded) {
    // Compact form reads a period as a component separator, so an inline
    // unencoded payload must not contain one. Binary content uses detached mode.
    const permitted = validateInlineUnencodedPayload(payload, false);
    if (!permitted.ok) {
      return fail('configuration', 'policy_violation', permitted.failure);
    }
  }

  const headerResult = buildProtectedHeader(algorithm, unencoded, options);
  if (!headerResult.ok) {
    return headerResult;
  }
  const protectedComponent = headerResult.component;

  const payloadComponent = unencoded ? new TextDecoder().decode(payload) : encodeBase64url(payload);

  const signingInput = unencoded
    ? buildSigningInput(protectedComponent, { octets: payload })
    : buildSigningInput(protectedComponent, { component: payloadComponent });
  if (!signingInput.ok) {
    return fail('configuration', 'invalid_header', signingInput.failure);
  }

  const signature = await signWithKey(options.key, signingInput.bytes);
  if (!signature.ok) {
    // Nothing is published on a backend failure: an empty or partial signature
    // must never be mistaken for a real one.
    return signature.failure === 'unsupported'
      ? fail('cryptographic', 'unsupported_algorithm', 'algorithm_unavailable')
      : fail('cryptographic', 'backend_failure', 'signing_failed');
  }

  return {
    ok: true,
    token: serializeCompact({
      protectedComponent,
      // Detached form omits the payload, leaving the middle component empty.
      payloadComponent: options.detached === true ? '' : payloadComponent,
      signatureComponent: encodeBase64url(signature.value),
    }),
  };
}

type HeaderResult = { readonly ok: true; readonly component: string } | Extract<SignResult, { ok: false }>;

/**
 * Builds and encodes the protected header exactly once.
 *
 * The encoded string is what the signature covers, so it is produced here and
 * reused rather than regenerated later from the same members.
 */
function buildProtectedHeader(algorithm: string, unencoded: boolean, options: SignOptions): HeaderResult {
  const members: Record<string, string | boolean | string[]> = {};

  for (const [name, value] of Object.entries(options.protectedHeader ?? {})) {
    // The algorithm and the payload-encoding extension are decided by the key
    // binding and the caller's mode, so a supplied value cannot override them.
    if (name === 'alg' || name === 'b64' || name === 'crit') {
      return fail('configuration', 'invalid_header', `reserved_header_${name}`) as HeaderResult;
    }
    // A recognized parameter's JSON type is fixed, and a producer must not emit
    // what its corresponding consumer rejects.
    if (!checkSuppliedParameterType(name, value, options.limits)) {
      return fail('configuration', 'invalid_header', `header_${name}_wrong_type`) as HeaderResult;
    }
    members[name] = value;
  }

  members['alg'] = algorithm;

  if (unencoded) {
    // The unencoded choice must be marked critical, including when explicit,
    // so a consumer cannot ignore it and build a different signing input.
    members['b64'] = false;
    members['crit'] = ['b64'];
  }

  const serialized = encodeUtf8(JSON.stringify(members));
  if (serialized.length > options.limits.headerSource) {
    return fail('configuration', 'resource_limit', 'header_too_large') as HeaderResult;
  }

  return { ok: true, component: encodeBase64url(serialized) };
}
