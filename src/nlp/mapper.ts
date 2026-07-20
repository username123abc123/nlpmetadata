import type {
  CanonicalField,
  MappingSuggestion,
  ObservedField,
  SourceType,
} from '../pipeline/types';

export interface MapperInput {
  observedFields: ObservedField[];
  sourceType: SourceType;
  canonicalFields: CanonicalField[];
  /** Canonical fields already confidently filled; skip suggesting these. */
  alreadyFilled: Set<string>;
}

export interface Mapper {
  readonly name: 'heuristic' | 'embedding';
  suggest(input: MapperInput): Promise<MappingSuggestion[]>;
}

export const DEFAULT_CONFIDENCE_THRESHOLD = 0.55;

/**
 * Greedy bipartite matching: walk all above-threshold suggestions from most
 * to least confident, assigning each observed field and canonical field at
 * most once. Considering every candidate pair (not just each field's top
 * pick) lets a field fall back to its second choice when its first choice is
 * claimed by a stronger match.
 */
export function selectBestSuggestions(
  suggestions: MappingSuggestion[],
  threshold: number,
): MappingSuggestion[] {
  const sorted = suggestions
    .filter((s) => s.confidence >= threshold)
    .sort((a, b) => b.confidence - a.confidence);

  const claimedObserved = new Set<string>();
  const claimedCanonical = new Set<string>();
  const result: MappingSuggestion[] = [];
  for (const s of sorted) {
    if (claimedObserved.has(s.observedField) || claimedCanonical.has(s.canonicalField)) {
      continue;
    }
    claimedObserved.add(s.observedField);
    claimedCanonical.add(s.canonicalField);
    result.push(s);
  }
  return result;
}
