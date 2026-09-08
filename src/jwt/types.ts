import type { ErrorCategory, TrustStage } from '../errors/codes.ts';
import type { JsonObject, JsonValue } from '../internal/json/types.ts';
import type { CompactEncryptOptions } from '../jwe/compact.ts';
import type { DecryptOptions } from '../jwe/decrypt.ts';
import type { SignOptions } from '../jws/sign.ts';
import type { VerifyOptions } from '../jws/verify.ts';
import type { Limits } from '../policy/limits.ts';

export type JwtProfileName = 'project-jwt-v1' | 'project-single-use-jwt-v1' | 'oauth-at-jwt-v1';
export type JwtChain = 'JWS -> claims' | 'JWE -> JWS -> claims';

export interface TrustedClock {
  now(): bigint | Promise<bigint>;
}

export type ReplayAdmission = 'admitted' | 'already_present' | 'unavailable';

export interface ReplayStore {
  admit(namespace: string, identifier: string, retainUntil: bigint): Promise<ReplayAdmission>;
}

export interface JwtProfile {
  readonly name: JwtProfileName;
  readonly version: 1;
  readonly issuer: string;
  readonly audience: string;
  readonly type: string;
  readonly chain: JwtChain;
  readonly skew: bigint;
  readonly maximumLifetime: bigint;
  readonly verification: Omit<VerifyOptions, 'limits' | 'detachedPayload'>;
  readonly decryption?: Omit<DecryptOptions, 'limits'> | undefined;
  readonly clock: TrustedClock;
  readonly replayStore?: ReplayStore | undefined;
  readonly replayNamespace: string;
  readonly subject: (issuer: string, subject: string) => boolean | Promise<boolean>;
}

export interface JwtProfileInput extends Omit<
  JwtProfile,
  'name' | 'version' | 'skew' | 'maximumLifetime' | 'replayNamespace'
> {
  readonly name: string;
  readonly skew?: number | undefined;
  readonly maximumLifetime?: number | undefined;
}

export type JwtProfileResult = { readonly ok: true; readonly profile: JwtProfile } | JwtFailure;

export interface JwtFailure {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly stage: TrustStage;
  readonly reason: string;
}

export interface ValidatedJwt {
  readonly claims: Readonly<Record<string, unknown>>;
  readonly profile: JwtProfileName;
  readonly version: 1;
  readonly issuer: string;
  readonly principalId: string;
  readonly sharedSecretDomain: boolean;
  readonly validatedAt: bigint;
}

export type JwtValidationResult = { readonly ok: true; readonly value: ValidatedJwt } | JwtFailure;

export interface ValidateJwtOptions {
  readonly profile: JwtProfile;
  readonly limits: Limits;
}

export interface ValidatedClaims {
  readonly object: JsonObject;
  readonly issuer: string;
  readonly subject: string;
  readonly audience: readonly string[];
  readonly expiration: bigint;
  readonly issuedAt: bigint;
  readonly notBefore?: bigint | undefined;
  readonly jwtId?: string | undefined;
}

export type ClaimsResult = { readonly ok: true; readonly value: ValidatedClaims } | JwtFailure;

export type JsonClaimsInput = Readonly<
  Record<string, JsonValue | string | number | bigint | boolean | null | readonly string[]>
>;

export interface CreateJwtOptions {
  readonly profile: JwtProfile;
  readonly limits: Limits;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signing: Omit<SignOptions, 'limits' | 'protectedHeader' | 'detached' | 'unencoded'>;
  readonly encryption?: Omit<CompactEncryptOptions, 'limits' | 'protectedHeader'> | undefined;
}

export type CreateJwtResult = { readonly ok: true; readonly token: string } | JwtFailure;
