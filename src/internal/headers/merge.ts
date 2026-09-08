/**
 * Header source merging and collision detection.
 */

import type { ErrorCategory } from '../../errors/codes.ts';
import { isJsonObject, type JsonObject, type JsonValue } from '../json/types.ts';
import { type HeaderOrigin, type HeaderParameter, type MergedHeader } from './types.ts';

export interface HeaderSource {
  readonly origin: HeaderOrigin;
  readonly object: JsonObject;
  /** UTF-8 source octets of this object, including internal whitespace. */
  readonly sourceBytes: number;
}

export interface HeaderBudget {
  readonly headerSource: number;
  readonly totalHeaderSource: number;
  readonly mergedHeaderMembers: number;
}

export type MergeResult =
  | { readonly ok: true; readonly header: MergedHeader }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

/**
 * Merges the header sources of one signature or recipient.
 *
 * Source bytes and merged-member counts are tracked as separate budgets rather
 * than derived from one another: a shared header counts once toward the total
 * byte budget for the whole object, but once again in each entry's member
 * count, so collapsing them would misprice one or the other.
 */
export function mergeHeaders(sources: readonly HeaderSource[], budget: HeaderBudget): MergeResult {
  const parameters = new Map<string, HeaderParameter>();
  let sourceBytes = 0;

  for (const source of sources) {
    if (source.sourceBytes > budget.headerSource) {
      return { ok: false, category: 'resource_limit', reason: 'header_source_too_large' };
    }
    sourceBytes += source.sourceBytes;
    if (sourceBytes > budget.totalHeaderSource) {
      return { ok: false, category: 'resource_limit', reason: 'total_header_source_too_large' };
    }

    for (const [name, value] of source.object.members) {
      // Names must be disjoint across header sources. Equal duplicate
      // values do not make a collision valid, so the values are deliberately not
      // compared: the ambiguity itself is the defect, since two readers could
      // resolve the same name to different provenance.
      if (parameters.has(name)) {
        return { ok: false, category: 'invalid_header', reason: 'header_name_collision' };
      }

      if (parameters.size + 1 > budget.mergedHeaderMembers) {
        return { ok: false, category: 'resource_limit', reason: 'merged_header_too_many_members' };
      }

      parameters.set(name, { name, value, origin: source.origin });
    }
  }

  return { ok: true, header: { parameters, sourceBytes } };
}

/**
 * Validates that a decoded header component is a JSON object.
 *
 * Container types are strict: an array, string, or number in a header position
 * is rejected rather than coerced, because a coerced value would be read as
 * having members it does not have.
 */
export function requireHeaderObject(
  value: JsonValue,
):
  | { readonly ok: true; readonly object: JsonObject }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string } {
  if (!isJsonObject(value)) {
    return { ok: false, category: 'invalid_header', reason: 'header_not_an_object' };
  }
  return { ok: true, object: value };
}
