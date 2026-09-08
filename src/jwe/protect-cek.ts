/**
 * CEK generation and per-recipient protection.
 *
 * One CEK protects the content, and each recipient gets its own path to that
 * same key. The exception is the direct modes, where the key is not chosen here
 * at all: it arrives from configuration or from an agreement, and generating
 * one would produce a key the recipient cannot reproduce.
 *
 * Every ephemeral agreement key is generated fresh. Reusing one across messages
 * would derive the same CEK each time, collapsing distinct messages onto one
 * key.
 */

import { aesKwKeySize, wrapAesKw } from '../algorithms/jwe/aes-kw.ts';
import { GCMKW_IV_BYTES, gcmKwKeySize, wrapGcmKw } from '../algorithms/jwe/aes-gcm-kw.ts';
import { concatKdf, partyInfo } from '../algorithms/jwe/concat-kdf.ts';
import { directCek } from '../algorithms/jwe/direct.ts';
import { agree, generateEphemeralEc, generateEphemeralOkp, isAgreementCurve } from '../algorithms/jwe/ecdh-es.ts';
import { agreementWrappingAlgorithm, keyManagementShape } from '../algorithms/jwe/index.ts';
import { encryptRsaOaep } from '../algorithms/jwe/rsaes-oaep.ts';
import type { ErrorCategory } from '../errors/codes.ts';
import type { RandomSource } from '../internal/crypto/backend.ts';
import { encodeAscii } from '../internal/encoding/ascii.ts';
import { isImportedKey, type UsableKey } from '../key/import.ts';
import type { EcMaterial, OkpMaterial, RsaPublicMaterial } from '../key/validation.ts';

export interface ProtectedRecipient {
  /** Absent for the direct modes, which carry no encrypted key. */
  readonly encryptedKey: Uint8Array | undefined;
  /**
   * Ephemeral public key for the agreement modes, absent otherwise.
   *
   * The recipient cannot reproduce the agreement without it, so it must reach
   * the emitted header; it is public by construction and carries no private
   * member.
   */
  readonly ephemeralPublicKey: EphemeralPublicKey | undefined;
  /**
   * Wrapping IV and tag for the GCM key-wrap mode, absent otherwise.
   *
   * These travel as header parameters and are distinct from the content IV and
   * tag; a recipient cannot unwrap without them.
   */
  readonly gcmKw: { readonly iv: Uint8Array; readonly tag: Uint8Array } | undefined;
}

/**
 * Decoded `apu`/`apv` octets bound into the Concat KDF.
 *
 * These are the same octets the header publishes; deriving with one value and
 * emitting another produces a key the recipient cannot reproduce.
 */
export interface PartyInfo {
  readonly partyU?: Uint8Array | undefined;
  readonly partyV?: Uint8Array | undefined;
}

/** Public half of a sender's ephemeral agreement key, as header members. */
export interface EphemeralPublicKey {
  readonly kty: 'EC' | 'OKP';
  readonly crv: string;
  readonly x: Uint8Array;
  /** Present for the NIST curves and absent for the Montgomery ones. */
  readonly y: Uint8Array | undefined;
}

export type ProtectCekResult =
  | {
      readonly ok: true;
      readonly cek: Uint8Array;
      readonly ownsCek: boolean;
      readonly recipients: readonly ProtectedRecipient[];
    }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function fail(category: ErrorCategory, reason: string): ProtectCekResult {
  return { ok: false, category, reason };
}

interface RecipientKey {
  readonly key: UsableKey;
}

/**
 * Produces the CEK and each recipient's encrypted key.
 *
 * The direct modes are resolved first because they determine the CEK rather
 * than consuming one; mixing them with other recipients is refused earlier,
 * where the recipient set is validated.
 */
export async function protectCek(
  contentAlgorithm: string,
  cekBytes: number,
  recipients: readonly RecipientKey[],
  random: RandomSource,
  wrappingNonces: readonly Uint8Array[] = [],
  party: PartyInfo = {},
): Promise<ProtectCekResult> {
  const first = recipients[0];
  if (first === undefined) {
    return fail('policy_violation', 'no_recipients');
  }
  // A record not produced by key import carries no validated material, so it is
  // refused here rather than dispatched on whatever it happens to hold.
  if (recipients.some((recipient) => !isImportedKey(recipient.key))) {
    return fail('incompatible_key', 'key_not_imported');
  }

  const shape = keyManagementShape(first.key.algorithm);
  if (shape === undefined) {
    return fail('unsupported_algorithm', 'unsupported_key_algorithm');
  }

  if (shape.mode === 'direct') {
    if (first.key.keyType !== 'oct') {
      return fail('incompatible_key', 'direct_requires_symmetric_key');
    }
    const result = directCek(contentAlgorithm, first.key.material);
    if (!result.ok) {
      return result.reason === 'unsupported_enc'
        ? fail('unsupported_algorithm', 'unsupported_content_algorithm')
        : fail('incompatible_key', 'direct_key_size_mismatch');
    }
    return {
      ok: true,
      cek: result.cek,
      ownsCek: false,
      recipients: [{ encryptedKey: undefined, ephemeralPublicKey: undefined, gcmKw: undefined }],
    };
  }

  if (shape.mode === 'direct_agreement') {
    // The agreement output is the CEK, so the KDF is bound to `enc` and sized
    // by the content algorithm.
    const derived = await deriveAgreedKey(first.key, contentAlgorithm, cekBytes, party);
    if (!derived.ok) {
      return derived.failure;
    }
    return {
      ok: true,
      cek: derived.value.derived,
      ownsCek: true,
      recipients: [{ encryptedKey: undefined, ephemeralPublicKey: derived.value.ephemeralPublicKey, gcmKw: undefined }],
    };
  }

  // Every remaining mode wraps or transports an independently generated CEK, so
  // it comes from the CSPRNG rather than from any key the caller supplied.
  let generated;
  try {
    generated = random.randomBytes(cekBytes);
  } catch {
    return fail('backend_failure', 'randomness_unavailable');
  }
  if (!generated.ok || generated.value.length !== cekBytes) {
    return fail('backend_failure', 'randomness_unavailable');
  }
  const cek = generated.value;

  const protectedRecipients: ProtectedRecipient[] = [];
  for (const recipient of recipients) {
    // Sequential so a failure stops before any later recipient's key is used;
    // nothing is emitted unless every recipient succeeded.
    // oxlint-disable-next-line no-await-in-loop
    const encrypted = await protectFor(recipient.key, cek, wrappingNonces[protectedRecipients.length], party);
    if (!encrypted.ok) {
      cek.fill(0);
      return encrypted.failure;
    }
    protectedRecipients.push(encrypted.value);
  }

  return { ok: true, cek, ownsCek: true, recipients: protectedRecipients };
}

type Produced<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly failure: ProtectCekResult };

async function protectFor(
  key: UsableKey,
  cek: Uint8Array,
  wrappingNonce: Uint8Array | undefined,
  party: PartyInfo,
): Promise<Produced<ProtectedRecipient>> {
  const shape = keyManagementShape(key.algorithm);
  if (shape === undefined) {
    return { ok: false, failure: fail('unsupported_algorithm', 'unsupported_key_algorithm') };
  }

  switch (shape.mode) {
    case 'key_wrapping': {
      if (key.keyType !== 'oct') {
        return { ok: false, failure: fail('incompatible_key', 'wrapping_requires_symmetric_key') };
      }
      const wrapped = await wrapAesKw(key.algorithm, key.material, cek);
      return wrapped.ok
        ? { ok: true, value: { encryptedKey: wrapped.value, ephemeralPublicKey: undefined, gcmKw: undefined } }
        : { ok: false, failure: fail('backend_failure', 'key_wrapping_failed') };
    }

    case 'key_transport': {
      if (key.keyType !== 'RSA') {
        return { ok: false, failure: fail('incompatible_key', 'transport_requires_rsa_key') };
      }
      const encrypted = await encryptRsaOaep(key.algorithm, key.material as RsaPublicMaterial, cek);
      return encrypted.ok
        ? { ok: true, value: { encryptedKey: encrypted.value, ephemeralPublicKey: undefined, gcmKw: undefined } }
        : { ok: false, failure: fail('backend_failure', 'key_transport_failed') };
    }

    case 'agreement_with_wrapping': {
      // Wrapped agreement derives a key-encryption key, so the KDF is bound to
      // `alg` and sized by the wrapping algorithm rather than by `enc`.
      const wrapping = agreementWrappingAlgorithm(key.algorithm);
      const kekBytes = wrapping === undefined ? undefined : aesKwKeySize(wrapping);
      if (wrapping === undefined || kekBytes === undefined) {
        return { ok: false, failure: fail('unsupported_algorithm', 'unsupported_key_algorithm') };
      }

      const kek = await deriveAgreedKey(key, key.algorithm, kekBytes, party);
      if (!kek.ok) {
        return kek;
      }

      const wrapped = await wrapAesKw(wrapping, kek.value.derived, cek);
      kek.value.derived.fill(0);
      return wrapped.ok
        ? {
            ok: true,
            value: {
              encryptedKey: wrapped.value,
              ephemeralPublicKey: kek.value.ephemeralPublicKey,
              gcmKw: undefined,
            },
          }
        : { ok: false, failure: fail('backend_failure', 'key_wrapping_failed') };
    }

    case 'gcm_wrapping': {
      if (key.keyType !== 'oct') {
        return { ok: false, failure: fail('incompatible_key', 'wrapping_requires_symmetric_key') };
      }
      const kekBytes = gcmKwKeySize(key.algorithm);
      if (kekBytes === undefined) {
        return { ok: false, failure: fail('unsupported_algorithm', 'unsupported_key_algorithm') };
      }
      // The wrapping nonce is allocated by the caller from durable state, in
      // its own key-scoped space: the wrapping key and the content key are
      // different keys with independent budgets.
      if (wrappingNonce === undefined || wrappingNonce.length !== GCMKW_IV_BYTES) {
        return { ok: false, failure: fail('policy_violation', 'wrapping_nonce_required') };
      }

      const wrapped = await wrapGcmKw(key.algorithm, key.material, wrappingNonce, cek);
      return wrapped.ok
        ? {
            ok: true,
            value: {
              encryptedKey: wrapped.value.encryptedKey,
              ephemeralPublicKey: undefined,
              gcmKw: { iv: wrapped.value.iv, tag: wrapped.value.tag },
            },
          }
        : { ok: false, failure: fail('backend_failure', 'key_wrapping_failed') };
    }

    case 'password_wrapping':
      // Receive-only: creating an object under a password-derived key would
      // rest its security on password strength, which requires a reviewed
      // policy and fresh random salt this entry point does not provide.
      return { ok: false, failure: fail('policy_violation', 'algorithm_receive_only') };

    case 'direct':
    case 'direct_agreement':
      // These never reach here: they determine the CEK and are resolved before
      // any wrapping loop runs.
      return { ok: false, failure: fail('policy_violation', 'direct_mode_cannot_wrap') };
  }
}

interface AgreedKey {
  readonly derived: Uint8Array;
  readonly ephemeralPublicKey: EphemeralPublicKey;
}

/**
 * Generates an ephemeral key, agrees with the recipient, and derives.
 *
 * The ephemeral public half is returned alongside the derived key because it
 * must be published as `epk` for the recipient to reproduce the agreement.
 */
async function deriveAgreedKey(
  recipientKey: UsableKey,
  algorithmId: string,
  keyBytes: number,
  party: PartyInfo,
): Promise<Produced<AgreedKey>> {
  if (recipientKey.keyType !== 'EC' && recipientKey.keyType !== 'OKP') {
    return { ok: false, failure: fail('incompatible_key', 'agreement_requires_ec_or_okp_key') };
  }

  const material = recipientKey.material as EcMaterial | OkpMaterial;
  if (!isAgreementCurve(material.curve)) {
    // A signing curve is never repurposed for agreement.
    return { ok: false, failure: fail('incompatible_key', 'curve_not_usable_for_agreement') };
  }

  // The key type decides which family generates the ephemeral half and whether
  // the published point carries a Y coordinate.
  let ownPrivate: EcMaterial | OkpMaterial;
  let ephemeralPublicKey: EphemeralPublicKey;
  let peer: { curve: string; x: Uint8Array; y?: Uint8Array | undefined };

  if (recipientKey.keyType === 'EC') {
    const ephemeral = await generateEphemeralEc(material.curve);
    if (!ephemeral.ok) {
      return { ok: false, failure: fail('backend_failure', 'ephemeral_generation_failed') };
    }
    ownPrivate = {
      curve: material.curve as EcMaterial['curve'],
      x: ephemeral.value.x,
      y: ephemeral.value.y,
      d: ephemeral.value.d,
    };
    ephemeralPublicKey = { kty: 'EC', crv: material.curve, x: ephemeral.value.x, y: ephemeral.value.y };
    peer = { curve: material.curve, x: material.x, y: (material as EcMaterial).y };
  } else {
    const ephemeral = await generateEphemeralOkp(material.curve);
    if (!ephemeral.ok) {
      return { ok: false, failure: fail('backend_failure', 'ephemeral_generation_failed') };
    }
    ownPrivate = {
      curve: material.curve as OkpMaterial['curve'],
      x: ephemeral.value.x,
      d: ephemeral.value.d,
    };
    ephemeralPublicKey = { kty: 'OKP', crv: material.curve, x: ephemeral.value.x, y: undefined };
    peer = { curve: material.curve, x: material.x };
  }

  const secret = await agree(ownPrivate, peer);
  if (!secret.ok) {
    ownPrivate.d?.fill(0);
    return { ok: false, failure: fail('backend_failure', 'key_agreement_failed') };
  }

  const encoded = encodeAscii(algorithmId);
  if (!encoded.ok) {
    secret.value.fill(0);
    ownPrivate.d?.fill(0);
    return { ok: false, failure: fail('invalid_header', 'algorithm_name_not_ascii') };
  }

  const derived = concatKdf(secret.value, {
    algorithmId: encoded.bytes,
    partyUInfo: partyInfo(party.partyU),
    partyVInfo: partyInfo(party.partyV),
    keyBytes,
  });
  secret.value.fill(0);
  ownPrivate.d?.fill(0);

  return {
    ok: true,
    value: {
      derived,
      ephemeralPublicKey,
    },
  };
}
