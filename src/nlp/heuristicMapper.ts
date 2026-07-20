import type { MappingSuggestion } from '../pipeline/types';
import type { Mapper, MapperInput } from './mapper';
import { detectValueShape, shapeCompatible } from './valueShapes';

/** Groups of tokens treated as equivalent when comparing field names. */
const SYNONYM_GROUPS: string[][] = [
  ['src', 'source'],
  ['dst', 'dest', 'destination'],
  ['ip', 'address', 'addr'],
  ['port', 'portnumber'],
  ['proto', 'protocol'],
  ['transport', 'transportproto'],
  ['host', 'hostname', 'computer', 'machine', 'sensor'],
  ['user', 'username', 'account', 'accountname'],
  ['image', 'executable', 'imagepath'],
  ['cmd', 'cmdline', 'commandline', 'command'],
  ['pid', 'processid'],
  ['time', 'timestamp', 'utctime', 'datetime', 'utc'],
  ['app', 'application'],
  ['rule', 'signature'],
  ['severity', 'priority', 'level'],
];

const CANON: Map<string, string> = new Map();
for (const group of SYNONYM_GROUPS) {
  for (const token of group) CANON.set(token, group[0]);
}

/** Low-information tokens that add noise to name comparison. */
const STOPWORDS = new Set(['number', 'line']);

export function tokenize(name: string): string[] {
  const tokens = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0 && !STOPWORDS.has(t))
    .map((t) => CANON.get(t) ?? t);
  return [...new Set(tokens)];
}

function jaccard(a: string[], b: string[]): number {
  const setA = new Set(a);
  const setB = new Set(b);
  if (setA.size === 0 || setB.size === 0) return 0;
  let intersection = 0;
  for (const t of setA) if (setB.has(t)) intersection++;
  return intersection / (setA.size + setB.size - intersection);
}

/**
 * Deterministic fallback mapper: token overlap between field names (with
 * synonym normalization) blended with value-shape compatibility.
 */
export const heuristicMapper: Mapper = {
  name: 'heuristic',

  async suggest(input: MapperInput): Promise<MappingSuggestion[]> {
    const suggestions: MappingSuggestion[] = [];

    for (const observed of input.observedFields) {
      const observedTokens = tokenize(observed.name);
      const shape = detectValueShape(observed.value);

      for (const canonical of input.canonicalFields) {
        if (input.alreadyFilled.has(canonical.name)) continue;

        const nameScore = jaccard(observedTokens, tokenize(canonical.name));
        const compatible = shapeCompatible(shape, canonical.typeHints);
        if (!compatible) continue;

        // Shape agreement with a *specific* hint (ip, port, timestamp, path)
        // is strong evidence; generic string compatibility adds nothing.
        const specificShapeMatch =
          canonical.typeHints?.includes(shape) && shape !== 'string' && shape !== 'number';
        const confidence = Math.min(1, nameScore * 0.75 + (specificShapeMatch ? 0.25 : 0));

        if (confidence > 0.2) {
          suggestions.push({
            observedField: observed.name,
            canonicalField: canonical.name,
            confidence: round2(confidence),
            sampleValue: observed.value,
            sourceType: input.sourceType,
            mapper: 'heuristic',
          });
        }
      }
    }
    return suggestions;
  },
};

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
