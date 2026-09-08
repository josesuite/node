/**
 * JSON JWS creation.
 *
 * Each signature carries its own protected header and therefore its own signing
 * input, even though the payload is shared. Algorithms come from each key's
 * trusted binding, never from a caller-supplied header, so a producer cannot be
 * steered into signing under an algorithm it did not intend.
 */

import { signWithKey } from '../algorithms/index.ts';
import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import { encodeBase64url } from '../internal/encoding/base64url.ts';
import { encodeUtf8 } from '../internal/encoding/utf8.ts';
import { checkSuppliedParameterType } from '../internal/headers/critical.ts';
import type { UsableKey } from '../key/import.ts';
import { type AlgorithmPolicy, decideAlgorithm } from '../policy/algorithms.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import { buildSigningInputForOctets } from './types.ts';

export interface JsonSignerInput {
  readonly key: UsableKey;
  /** Extra protected members; `alg` comes from the key binding. */
  readonly protectedHeader?: Readonly<Record<string, string | boolean | string[]>> | undefined;
  /**
   * Unprotected members, carried verbatim and excluded from the signing input.
   * These stay unauthenticated hints and must not hold security-relevant data.
   */
  readonly unprotectedHeader?: Readonly<Record<string, string>> | undefined;
}

export interface JsonSignOptions {
  readonly policy: AlgorithmPolicy;
  readonly signers: readonly JsonSignerInput[];
  readonly limits: Limits;
  /** Omit the payload member, for detached mode. */
  readonly detached?: boolean | undefined;
  /** Emit the single-signature Flattened form instead of `signatures`. */
  readonly flattened?: boolean | undefined;
}

export type JsonSignResult =
  | { readonly ok: true; readonly value: string }
  | {
      readonly ok: false;
      readonly category: ErrorCategory;
      readonly stage: TrustStage;
      readonly reason: string;
    };

function fail(category: ErrorCategory, reason: string): JsonSignResult {
  return { ok: false, category, stage: 'configuration', reason };
}

export async function signJson(payload: Uint8Array, options: JsonSignOptions): Promise<JsonSignResult> {
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('policy_violation', limitDefect);
  }
  if (options.signers.length === 0) {
    return fail('policy_violation', 'no_signers');
  }
  if (options.signers.length > options.limits.signatures) {
    return fail('resource_limit', 'too_many_signers');
  }
  if (options.flattened === true && options.signers.length !== 1) {
    // The Flattened form has exactly one signature by definition.
    return fail('policy_violation', 'flattened_requires_single_signature');
  }
  if (payload.length > options.limits.payload) {
    return fail('resource_limit', 'payload_too_large');
  }

  const payloadComponent = encodeBase64url(payload);
  const entries: Record<string, string | Record<string, string>>[] = [];

  for (const signer of options.signers) {
    const algorithm = signer.key.algorithm;

    const decision = decideAlgorithm(options.policy, algorithm);
    if (!decision.ok) {
      return fail(decision.category, decision.reason);
    }
    if (!signer.key.isPrivate) {
      return fail('incompatible_key', 'signing_requires_private_key');
    }
    if (signer.key.operation !== 'sign') {
      return fail('incompatible_key', 'key_operation_mismatch');
    }

    const header = buildProtectedHeader(algorithm, signer, options.limits);
    if (!header.ok) {
      return header.failure;
    }

    const signingInput = buildSigningInputForOctets(header.component, payload, {
      encoded: true,
      location: options.detached === true ? 'detached' : 'attached',
    });
    if (!signingInput.ok) {
      return fail('invalid_header', signingInput.failure);
    }

    // Sequential so that a failure stops before any later signer's key is used;
    // nothing is emitted unless every signature succeeded.
    // oxlint-disable-next-line no-await-in-loop
    const signature = await signWithKey(signer.key, signingInput.bytes);
    if (!signature.ok) {
      // Nothing is emitted on a backend failure: a partial or empty signature
      // must never be mistaken for a real one.
      return signature.failure === 'unsupported'
        ? fail('unsupported_algorithm', 'algorithm_unavailable')
        : fail('backend_failure', 'signing_failed');
    }

    const entry: Record<string, string | Record<string, string>> = {
      protected: header.component,
      signature: encodeBase64url(signature.value),
    };

    if (signer.unprotectedHeader !== undefined) {
      // An empty optional value is omitted rather than emitted as `{}`.
      if (Object.keys(signer.unprotectedHeader).length === 0) {
        return fail('invalid_header', 'unprotected_header_empty');
      }
      entry['header'] = { ...signer.unprotectedHeader };
    }

    entries.push(entry);
  }

  const object: Record<string, unknown> = {};
  // Detached form omits the member entirely; an embedded empty payload is the
  // empty string, which is a different state.
  if (options.detached !== true) {
    object['payload'] = payloadComponent;
  }

  if (options.flattened === true) {
    Object.assign(object, entries[0]);
  } else {
    object['signatures'] = entries;
  }

  return { ok: true, value: JSON.stringify(object) };
}

type HeaderResult =
  | { readonly ok: true; readonly component: string }
  | { readonly ok: false; readonly failure: JsonSignResult };

function buildProtectedHeader(algorithm: string, signer: JsonSignerInput, limits: Limits): HeaderResult {
  const members: Record<string, string | boolean | string[]> = {};

  for (const [name, value] of Object.entries(signer.protectedHeader ?? {})) {
    // The algorithm is fixed by the key binding, and this entry point does not
    // offer unencoded payloads, so neither may be supplied by the caller.
    if (name === 'alg' || name === 'b64' || name === 'crit') {
      return { ok: false, failure: fail('invalid_header', `reserved_header_${name}`) };
    }
    // A recognized parameter's JSON type is fixed, and a producer must not emit
    // what its corresponding consumer rejects.
    if (!checkSuppliedParameterType(name, value, limits)) {
      return { ok: false, failure: fail('invalid_header', `header_${name}_wrong_type`) };
    }
    members[name] = value;
  }

  members['alg'] = algorithm;

  // A name appearing in both header sources has ambiguous provenance, so the
  // collision is refused at creation rather than emitted for a consumer to
  // reject.
  for (const name of Object.keys(signer.unprotectedHeader ?? {})) {
    if (name in members) {
      return { ok: false, failure: fail('invalid_header', 'header_name_collision') };
    }
  }

  const serialized = encodeUtf8(JSON.stringify(members));
  if (serialized.length > limits.headerSource) {
    return { ok: false, failure: fail('resource_limit', 'header_too_large') };
  }

  return { ok: true, component: encodeBase64url(serialized) };
}
