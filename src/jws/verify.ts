/**
 * Compact JWS verification.
 *
 * Stages run in a fixed order: structure, then headers and critical
 * extensions, then algorithm policy, then key eligibility, and only then
 * cryptography. Each stage's failure is reported with its own category, so a
 * token rejected on policy never reaches key resolution and a rejection at the
 * wrong stage is visible as such rather than hidden behind a matching category.
 *
 * A successful backend result is necessary but not sufficient: the algorithm,
 * key binding, and signature representation are all checked around it.
 */

import { verifyWithKey } from '../algorithms/index.ts';
import { type ErrorCategory, type TrustStage } from '../errors/codes.ts';
import { decodeBase64url, encodeBase64url } from '../internal/encoding/base64url.ts';
import { encodeUtf8 } from '../internal/encoding/utf8.ts';
import { resolveB64, validateCritical, validateParameterTypes } from '../internal/headers/critical.ts';
import { mergeHeaders, requireHeaderObject } from '../internal/headers/merge.ts';
import type { MergedHeader } from '../internal/headers/types.ts';
import { parseJson } from '../internal/json/parse.ts';
import { OperationBudget } from '../internal/validation/limits.ts';
import type { UsableKey } from '../key/import.ts';
import { type AlgorithmPolicy, decideAlgorithm } from '../policy/algorithms.ts';
import { checkLimits, type Limits } from '../policy/limits.ts';
import { parseCompact } from './compact.ts';
import { buildSigningInput, type PayloadMode, validateInlineUnencodedPayload } from './types.ts';

export interface VerifyFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
}

export interface VerifySuccess {
  readonly ok: true;
  /** Authenticated payload octets. */
  readonly payload: Uint8Array;
  /** Header provenance, so callers can tell protected values from hints. */
  readonly header: MergedHeader;
  /**
   * The principal this key was bound to by trusted configuration.
   *
   * For an asymmetric signature this identifies the configured signer. For a
   * MAC it identifies the shared-secret domain and does **not** establish which
   * holder of that secret produced the object, since every holder can produce
   * an identical MAC.
   */
  readonly principalId: string;
  /** True when the binding was a MAC, where the above distinction applies. */
  readonly isSharedSecret: boolean;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

export interface VerifyOptions {
  readonly policy: AlgorithmPolicy;
  readonly key: UsableKey;
  readonly principalId: string;
  readonly limits: Limits;
  /**
   * External payload for detached mode. Its presence is an explicit caller
   * choice; detachment is never inferred from an empty component, and the
   * content is never fetched from an address inside the token.
   */
  readonly detachedPayload?: Uint8Array | undefined;
  /**
   * Accepts RFC 7797 unencoded payloads. Off by default: the parameter decides
   * what the signing input is built from, so a token must not be able to select
   * a payload mode the caller never enabled.
   */
  readonly unencodedPayload?: boolean | undefined;
  readonly legacyEddsaCurve?: string | undefined;
  readonly operationBudget?: OperationBudget | undefined;
}

function fail(stage: TrustStage, category: ErrorCategory, reason: string): VerifyFailure {
  return { ok: false, category, stage, reason };
}

/**
 * Verifies a Compact JWS against one trusted key.
 *
 * The key and its principal come from trusted configuration. Nothing in the
 * token selects them: a `kid` may narrow candidates elsewhere, but it can never
 * introduce a key the caller did not already trust.
 */
export async function verifyCompact(token: string, options: VerifyOptions): Promise<VerifyResult> {
  const limitDefect = checkLimits(options.limits);
  if (limitDefect !== undefined) {
    return fail('configuration', 'policy_violation', limitDefect);
  }
  // A standalone call owns its budget. Accounting only when an enclosing
  // operation supplies one would leave every direct call unbounded.
  const budget = options.operationBudget ?? new OperationBudget(options.limits);
  if (!budget.consumeLayer()) {
    return fail('syntax', 'resource_limit', 'too_many_cryptographic_layers');
  }
  const parsed = parseCompact(token, options.limits.joseInput);
  if (!parsed.ok) {
    return fail('syntax', parsed.category, parsed.reason);
  }
  const parts = parsed.parts;

  const headerBytes = decodeBase64url(parts.protectedComponent, options.limits.headerSource);
  if (!headerBytes.ok) {
    return headerBytes.failure === 'too_large'
      ? fail('syntax', 'resource_limit', 'protected_header_too_large')
      : fail('syntax', 'invalid_encoding', 'protected_header_invalid_base64url');
  }

  const headerJson = parseJson(headerBytes.bytes, options.limits);
  if (!headerJson.ok) {
    const category: ErrorCategory =
      headerJson.failure === 'resource_limit'
        ? 'resource_limit'
        : headerJson.failure === 'invalid_encoding'
          ? 'invalid_encoding'
          : 'malformed_input';
    return fail('syntax', category, `protected_header_${headerJson.failure}`);
  }
  if (!budget.consumeJsonNodes(headerJson.nodes)) {
    return fail('syntax', 'resource_limit', 'json_node_budget_exceeded');
  }

  const headerObject = requireHeaderObject(headerJson.value);
  if (!headerObject.ok) {
    return fail('header', headerObject.category, headerObject.reason);
  }

  const merged = mergeHeaders(
    [
      {
        origin: 'protected',
        object: headerObject.object,
        sourceBytes: headerBytes.bytes.length,
      },
    ],
    options.limits,
  );
  if (!merged.ok) {
    return fail('header', merged.category, merged.reason);
  }
  const header = merged.header;

  const types = validateParameterTypes(header, options.limits);
  if (!types.ok) {
    return fail('header', types.category, types.reason);
  }

  const critical = validateCritical(header, 'jws');
  if (!critical.ok) {
    return fail('header', critical.category, critical.reason);
  }

  const b64 = resolveB64(header, critical.names, options.unencodedPayload === true);
  if (!b64.ok) {
    return fail('header', b64.category, b64.reason);
  }

  const algMember = header.parameters.get('alg');
  if (algMember === undefined) {
    return fail('header', 'invalid_header', 'alg_missing');
  }
  if (algMember.value.kind !== 'string') {
    return fail('header', 'invalid_header', 'alg_not_a_string');
  }
  // The algorithm must be protected: an unprotected one is not covered by the
  // signature and could be rewritten in transit.
  if (algMember.origin !== 'protected') {
    return fail('header', 'invalid_header', 'alg_not_protected');
  }

  const decision = decideAlgorithm(options.policy, algMember.value.value);
  if (!decision.ok) {
    return fail('header', decision.category, decision.reason);
  }

  // The key's own binding must be the algorithm in use. This is what stops a
  // public key from being accepted as an HMAC secret when the header asks for
  // a MAC, since the bound algorithm would not match.
  if (options.key.algorithm !== algMember.value.value) {
    return fail('key_resolution', 'incompatible_key', 'key_algorithm_mismatch');
  }
  if (options.key.operation !== 'verify') {
    return fail('key_resolution', 'incompatible_key', 'key_operation_mismatch');
  }

  // A present `kid` is an exact filter, applied even though only one key is
  // configured. Ignoring it here would verify a token naming a key absent from
  // the trusted configuration against whichever key the caller happened to
  // supply, which is the fallback exact filtering exists to prevent.
  const kid = header.parameters.get('kid');
  if (kid !== undefined && kid.value.kind === 'string' && options.key.metadata.kid !== kid.value.value) {
    return fail('key_resolution', 'key_resolution_failure', 'kid_does_not_match_configured_key');
  }

  const payload = resolvePayload(parts.payloadComponent, b64.encoded, options);
  if (!payload.ok) {
    return payload.failure;
  }

  // Attached encoded mode authenticates the received component verbatim, so
  // the original string is used rather than a re-encoding of the decoded bytes.
  // Every other mode appends octets directly after the period.
  const signingInput =
    payload.mode.encoded && payload.mode.location === 'attached'
      ? buildSigningInput(parts.protectedComponent, { component: parts.payloadComponent })
      : buildSigningInput(parts.protectedComponent, { octets: payload.signedOctets });
  if (!signingInput.ok) {
    return fail('cryptographic', 'invalid_header', signingInput.failure);
  }

  const signature = decodeBase64url(parts.signatureComponent, options.limits.signatureOctets);
  if (!signature.ok) {
    return signature.failure === 'too_large'
      ? fail('syntax', 'resource_limit', 'signature_too_large')
      : fail('syntax', 'invalid_encoding', 'signature_invalid_base64url');
  }

  if (!budget.consumeAttempt()) {
    return fail('cryptographic', 'resource_limit', 'cryptographic_attempt_budget_exceeded');
  }
  const verified = await verifyWithKey(options.key, signingInput.bytes, signature.bytes, {
    legacyEddsaCurve: options.legacyEddsaCurve,
  });

  if (!verified.ok) {
    // A provider fault is reported as such. Collapsing it into a verification
    // failure would make an outage indistinguishable from a forgery.
    return verified.failure === 'unsupported'
      ? fail('cryptographic', 'unsupported_algorithm', 'algorithm_unavailable')
      : fail('cryptographic', 'backend_failure', 'provider_failure');
  }

  if (!verified.value) {
    return fail('cryptographic', 'signature_verification_failure', 'signature_did_not_verify');
  }

  return {
    ok: true,
    payload: payload.plaintext,
    header,
    principalId: options.principalId,
    isSharedSecret: options.key.keyType === 'oct',
  };
}

interface ResolvedPayload {
  readonly ok: true;
  readonly plaintext: Uint8Array;
  /** Octets appended to the signing input in unencoded or detached mode. */
  readonly signedOctets: Uint8Array;
  readonly mode: PayloadMode;
}

function resolvePayload(
  component: string,
  encoded: boolean,
  options: VerifyOptions,
): ResolvedPayload | { readonly ok: false; readonly failure: VerifyFailure } {
  const detached = options.detachedPayload;

  if (detached !== undefined) {
    // Supplying both an embedded payload and external content is ambiguous
    // about which one the signature covers, so it is refused.
    if (component.length > 0) {
      return {
        ok: false,
        failure: fail('syntax', 'invalid_header', 'ambiguous_payload_source'),
      };
    }
    if (detached.length > options.limits.detachedPayload) {
      return { ok: false, failure: fail('syntax', 'resource_limit', 'detached_payload_too_large') };
    }

    // The caller keeps ownership of the supplied array and can change it while
    // verification awaits the provider. Everything authenticated and returned
    // comes from this snapshot, so the bytes reported on success are exactly
    // the bytes the signature covered.
    const owned = new Uint8Array(detached);

    // Detached encoded mode authenticates the Base64url of the external bytes;
    // unencoded mode authenticates those bytes directly.
    return {
      ok: true,
      plaintext: owned,
      signedOctets: encoded ? encodeForSigning(owned) : owned,
      mode: { encoded, location: 'detached' },
    };
  }

  if (!encoded) {
    // An inline unencoded payload is the raw component bytes. Compact form
    // excludes the period, which the component split has already guaranteed.
    const octets = new TextEncoder().encode(component);
    if (octets.length > options.limits.payload) {
      return { ok: false, failure: fail('syntax', 'resource_limit', 'payload_too_large') };
    }
    // The accepted inline profile is the same on both sides. Without this a
    // correctly signed token could carry a payload the creator would refuse to
    // produce, so acceptance would depend on which side built the object.
    const permitted = validateInlineUnencodedPayload(octets, false);
    if (!permitted.ok) {
      return { ok: false, failure: fail('syntax', 'policy_violation', permitted.failure) };
    }
    return {
      ok: true,
      plaintext: octets,
      signedOctets: octets,
      mode: { encoded: false, location: 'attached' },
    };
  }

  const decoded = decodeBase64url(component, options.limits.payload);
  if (!decoded.ok) {
    return {
      ok: false,
      failure:
        decoded.failure === 'too_large'
          ? fail('syntax', 'resource_limit', 'payload_too_large')
          : fail('syntax', 'invalid_encoding', 'payload_invalid_base64url'),
    };
  }

  return {
    ok: true,
    plaintext: decoded.bytes,
    signedOctets: decoded.bytes,
    mode: { encoded: true, location: 'attached' },
  };
}

function encodeForSigning(bytes: Uint8Array): Uint8Array {
  return encodeUtf8(encodeBase64url(bytes));
}
