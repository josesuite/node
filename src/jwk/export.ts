/**
 * Public key export.
 *
 * The public representation is rebuilt from validated attributes rather than
 * produced by copying the source object and deleting its private members.
 * Copy-and-delete is unsafe in a way that is easy to miss: RSA CRT values,
 * post-quantum private seeds, symmetric key octets, vendor extension fields,
 * and cached provider state all survive a naive deletion of `d`, and any of
 * them published in a public key set would leak private material.
 *
 * Only the members listed for each key type are emitted, so a member that is
 * not explicitly allowed cannot appear in the output by default.
 */

import { encodeBase64url } from '../internal/encoding/base64url.ts';
import type { EcMaterial, OkpMaterial, RsaPublicMaterial } from '../key/validation.ts';

export type PublicJwk = Readonly<Record<string, string>>;

export interface ExportMetadata {
  readonly kid?: string | undefined;
  readonly alg?: string | undefined;
  readonly use?: string | undefined;
}

function withMetadata(base: Record<string, string>, metadata: ExportMetadata): PublicJwk {
  // Each field is copied individually so an unexpected property on the
  // metadata object cannot reach the exported key.
  if (metadata.kid !== undefined) {
    base['kid'] = metadata.kid;
  }
  if (metadata.alg !== undefined) {
    base['alg'] = metadata.alg;
  }
  if (metadata.use !== undefined) {
    base['use'] = metadata.use;
  }
  return Object.freeze(base);
}

export function exportRsaPublicJwk(material: RsaPublicMaterial, metadata: ExportMetadata = {}): PublicJwk {
  // Deliberately omits d, p, q, dp, dq, qi, and oth.
  return withMetadata(
    {
      kty: 'RSA',
      n: encodeBase64url(material.n),
      e: encodeBase64url(material.e),
    },
    metadata,
  );
}

export function exportEcPublicJwk(material: EcMaterial, metadata: ExportMetadata = {}): PublicJwk {
  // Deliberately omits d.
  return withMetadata(
    {
      kty: 'EC',
      crv: material.curve,
      x: encodeBase64url(material.x),
      y: encodeBase64url(material.y),
    },
    metadata,
  );
}

export function exportOkpPublicJwk(material: OkpMaterial, metadata: ExportMetadata = {}): PublicJwk {
  // Deliberately omits d.
  return withMetadata(
    {
      kty: 'OKP',
      crv: material.curve,
      x: encodeBase64url(material.x),
    },
    metadata,
  );
}

/**
 * Symmetric keys have no public representation at all: every octet of an `oct`
 * key is secret, so there is nothing that could be safely published. Callers
 * asking for one have made a mistake that should surface rather than produce an
 * empty or partial object.
 */
export function exportOctPublicJwk(): never {
  throw new TypeError('a symmetric key has no public representation');
}
