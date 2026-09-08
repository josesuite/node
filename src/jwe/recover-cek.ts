/**
 * CEK recovery for one selected recipient.
 *
 * Every path here reports a failed recovery the same way, as `undefined`
 * rather than a distinct reason. A wrong key, a failed unwrap, a failed OAEP
 * decode, and an agreement that produced the wrong size are all outcomes an
 * attacker can provoke by construction, and distinguishing them is what turns a
 * decryption endpoint into an oracle.
 *
 * A recovered CEK is checked against the size the content algorithm fixes. That
 * size comes from `enc`, never from the recovered length, so a value of the
 * wrong size is refused rather than stretched or truncated into something the
 * cipher would accept.
 */

import { contentEncryptionShape } from '../algorithms/content-encryption/index.ts';
import { aesKwKeySize, unwrapAesKw } from '../algorithms/jwe/aes-kw.ts';
import { unwrapGcmKw } from '../algorithms/jwe/aes-gcm-kw.ts';
import { checkWorkFactor, derivePbes2Key, pbes2Parameters } from '../algorithms/jwe/pbes2.ts';
import { concatKdf, partyInfo } from '../algorithms/jwe/concat-kdf.ts';
import { directCek } from '../algorithms/jwe/direct.ts';
import { agree } from '../algorithms/jwe/ecdh-es.ts';
import { agreementWrappingAlgorithm, type KeyManagementShape } from '../algorithms/jwe/index.ts';
import { decryptRsaOaep } from '../algorithms/jwe/rsaes-oaep.ts';
import { encodeAscii } from '../internal/encoding/ascii.ts';
import { isImportedKey, type UsableKey } from '../key/import.ts';
import type { EcMaterial, OkpMaterial, RsaPrivateMaterial } from '../key/validation.ts';

/** Wrapping IV and tag the GCM key-wrap mode carries in its header. */
export interface GcmKwHeaders {
  readonly iv: Uint8Array;
  readonly tag: Uint8Array;
}

/** Work factor and salt the password mode carries in its header. */
export interface Pbes2Headers {
  readonly saltInput: Uint8Array;
  readonly iterations: number;
}

/** Header values the agreement modes need, already validated as strings. */
export interface AgreementHeaders {
  /** Decoded `epk` coordinates; the sender's ephemeral public key. */
  readonly ephemeral: { readonly curve: string; readonly x: Uint8Array; readonly y: Uint8Array | undefined };
  /** Decoded `apu`, absent when the header omits it. */
  readonly partyU: Uint8Array | undefined;
  /** Decoded `apv`, absent when the header omits it. */
  readonly partyV: Uint8Array | undefined;
}

export type CekRecovery =
  /** The CEK was recovered and is the exact size `enc` requires. */
  | { readonly ok: true; readonly cek: Uint8Array; readonly owned: boolean }
  /** Recovery failed in a way an attacker could provoke; no detail is given. */
  | { readonly ok: false; readonly failure: 'recovery_failed' }
  /** The provider is unavailable, which is not an attacker-reachable outcome. */
  | { readonly ok: false; readonly failure: 'backend_failure' };

const FAILED: CekRecovery = { ok: false, failure: 'recovery_failed' };
const BACKEND: CekRecovery = { ok: false, failure: 'backend_failure' };

export interface RecoverInput {
  readonly keyAlgorithm: string;
  readonly contentAlgorithm: string;
  readonly shape: KeyManagementShape;
  readonly key: UsableKey;
  /** Decoded encrypted key, absent for the direct modes. */
  readonly encryptedKey: Uint8Array | undefined;
  readonly agreement: AgreementHeaders | undefined;
  readonly gcmKw: GcmKwHeaders | undefined;
  readonly pbes2: Pbes2Headers | undefined;
  /**
   * Password octets for the password mode, supplied by trusted configuration
   * rather than derived from anything in the object.
   */
  readonly password: Uint8Array | undefined;
}

export async function recoverCek(input: RecoverInput): Promise<CekRecovery> {
  // A record not produced by key import carries no validated material, so it is
  // refused here rather than dispatched on whatever it happens to hold.
  if (!isImportedKey(input.key)) {
    return FAILED;
  }

  const content = contentEncryptionShape(input.contentAlgorithm);
  if (content === undefined) {
    return FAILED;
  }

  switch (input.shape.mode) {
    case 'direct': {
      if (input.key.keyType !== 'oct') {
        return FAILED;
      }
      const result = directCek(input.contentAlgorithm, input.key.material);
      return result.ok ? { ok: true, cek: result.cek, owned: false } : FAILED;
    }

    case 'key_wrapping': {
      if (input.key.keyType !== 'oct' || input.encryptedKey === undefined) {
        return FAILED;
      }
      const unwrapped = await unwrapAesKw(input.keyAlgorithm, input.key.material, input.encryptedKey);
      if (!unwrapped.ok) {
        return unwrapped.failure === 'unsupported' ? FAILED : BACKEND;
      }
      return sized(unwrapped.value, content.cekBytes);
    }

    case 'key_transport': {
      if (input.key.keyType !== 'RSA' || input.encryptedKey === undefined) {
        return FAILED;
      }
      const material = input.key.material as RsaPrivateMaterial;
      if (material.d === undefined) {
        return FAILED;
      }
      const decrypted = await decryptRsaOaep(input.keyAlgorithm, material, input.encryptedKey);
      if (!decrypted.ok) {
        return decrypted.failure === 'unsupported' ? FAILED : BACKEND;
      }
      return sized(decrypted.value, content.cekBytes);
    }

    case 'direct_agreement': {
      // Direct agreement derives the CEK itself, so the KDF is bound to `enc`
      // and asked for exactly the content algorithm's key size.
      const agreed = await agreeWith(input);
      if (!agreed.ok) {
        return agreed.backendFailure ? BACKEND : FAILED;
      }
      const derived = deriveKey(agreed.secret, input.contentAlgorithm, content.cekBytes, input.agreement);
      agreed.secret.fill(0);
      return derived === undefined ? FAILED : { ok: true, cek: derived, owned: true };
    }

    case 'gcm_wrapping': {
      // The wrapping IV and tag come from the header and are distinct from the
      // content ones; using the content values here would unwrap nothing.
      if (input.key.keyType !== 'oct' || input.encryptedKey === undefined || input.gcmKw === undefined) {
        return FAILED;
      }
      const unwrapped = await unwrapGcmKw(
        input.keyAlgorithm,
        input.key.material,
        input.gcmKw.iv,
        input.encryptedKey,
        input.gcmKw.tag,
      );
      if (!unwrapped.ok) {
        return unwrapped.failure === 'unsupported' ? FAILED : BACKEND;
      }
      return sized(unwrapped.value, content.cekBytes);
    }

    case 'password_wrapping': {
      const parameters = pbes2Parameters(input.keyAlgorithm);
      if (parameters === undefined || input.encryptedKey === undefined || input.pbes2 === undefined) {
        return FAILED;
      }
      if (input.password === undefined) {
        // No password was configured for this key, so the mode is unusable
        // here regardless of what the object carries.
        return FAILED;
      }

      // The work factor is bounded before the derivation runs: the count is
      // attacker-supplied and decides how much work this side performs.
      const bounded = checkWorkFactor(input.keyAlgorithm, input.pbes2.saltInput, input.pbes2.iterations);
      if (!bounded.ok) {
        return FAILED;
      }

      const kek = await derivePbes2Key(
        input.keyAlgorithm,
        input.password,
        input.pbes2.saltInput,
        input.pbes2.iterations,
      );
      if (!kek.ok) {
        return kek.failure === 'unsupported' ? FAILED : BACKEND;
      }

      const unwrapped = await unwrapAesKw(parameters.wrappingAlgorithm, kek.value, input.encryptedKey);
      kek.value.fill(0);
      if (!unwrapped.ok) {
        return unwrapped.failure === 'unsupported' ? FAILED : BACKEND;
      }
      return sized(unwrapped.value, content.cekBytes);
    }

    case 'agreement_with_wrapping': {
      // Wrapped agreement derives a key-encryption key instead, so the KDF is
      // bound to `alg` and sized by the wrapping algorithm. Using `enc` here
      // would derive a key the sender never produced.
      const wrapping = agreementWrappingAlgorithm(input.keyAlgorithm);
      const kekBytes = wrapping === undefined ? undefined : aesKwKeySize(wrapping);
      if (wrapping === undefined || kekBytes === undefined || input.encryptedKey === undefined) {
        return FAILED;
      }

      const agreed = await agreeWith(input);
      if (!agreed.ok) {
        return agreed.backendFailure ? BACKEND : FAILED;
      }
      const kek = deriveKey(agreed.secret, input.keyAlgorithm, kekBytes, input.agreement);
      agreed.secret.fill(0);
      if (kek === undefined) {
        return FAILED;
      }

      const unwrapped = await unwrapAesKw(wrapping, kek, input.encryptedKey);
      kek.fill(0);
      if (!unwrapped.ok) {
        return unwrapped.failure === 'unsupported' ? FAILED : BACKEND;
      }
      return sized(unwrapped.value, content.cekBytes);
    }
  }
}

function sized(cek: Uint8Array | undefined, expectedBytes: number): CekRecovery {
  // A recovered key of the wrong size means the object was not built for this
  // content algorithm, which is a failed recovery rather than a usable key.
  if (cek === undefined || cek.length !== expectedBytes) {
    cek?.fill(0);
    return FAILED;
  }
  return { ok: true, cek, owned: true };
}

/**
 * Outcome of an agreement attempt.
 *
 * A provider outage is reported separately from a rejected agreement: collapsing
 * both into "no secret" would make an unavailable backend indistinguishable from
 * a forged token, so an operator would read an outage as an attack.
 */
type Agreement =
  | { readonly ok: true; readonly secret: Uint8Array }
  | { readonly ok: false; readonly backendFailure: boolean };

const NOT_AGREED: Agreement = { ok: false, backendFailure: false };

async function agreeWith(input: RecoverInput): Promise<Agreement> {
  const headers = input.agreement;
  if (headers === undefined) {
    return NOT_AGREED;
  }
  if (input.key.keyType !== 'EC' && input.key.keyType !== 'OKP') {
    return NOT_AGREED;
  }

  const material = input.key.material as EcMaterial | OkpMaterial;
  const secret = await agree(material, {
    curve: headers.ephemeral.curve,
    x: headers.ephemeral.x,
    y: headers.ephemeral.y,
  });

  if (secret.ok) {
    return { ok: true, secret: secret.value };
  }
  // An unsupported combination is a rejection; anything else is the provider
  // failing to perform an operation it accepted.
  return { ok: false, backendFailure: secret.failure !== 'unsupported' };
}

/**
 * Runs the KDF with the algorithm identifier the mode requires.
 *
 * The identifier is ASCII of `enc` for direct agreement and of `alg` for
 * wrapped agreement. Feeding the wrong one derives a key the peer will not
 * reproduce, so the caller passes it explicitly rather than it being inferred
 * here.
 */
function deriveKey(
  sharedSecret: Uint8Array,
  algorithmId: string,
  keyBytes: number,
  headers: AgreementHeaders | undefined,
): Uint8Array | undefined {
  const encoded = encodeAscii(algorithmId);
  if (!encoded.ok) {
    return undefined;
  }

  return concatKdf(sharedSecret, {
    algorithmId: encoded.bytes,
    partyUInfo: partyInfo(headers?.partyU),
    partyVInfo: partyInfo(headers?.partyV),
    keyBytes,
  });
}
