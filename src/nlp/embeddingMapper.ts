import { env, pipeline } from '@xenova/transformers';
import type { FeatureExtractionPipeline } from '@xenova/transformers';
import type { CanonicalField, MappingSuggestion, ObservedField } from '../pipeline/types';
import type { Mapper, MapperInput } from './mapper';
import { cosineSimilarity } from './cosine';
import { detectValueShape, shapeCompatible } from './valueShapes';
import { tokenize } from './heuristicMapper';

export const MODEL_ID = 'Xenova/all-MiniLM-L6-v2';

let extractor: FeatureExtractionPipeline | null = null;
const embeddingCache = new Map<string, Float32Array>();

/**
 * Locks transformers.js to same-origin assets: model files under
 * `<base>/models/` and ONNX runtime WASM under `<base>/wasm/`. No remote
 * downloads are permitted at runtime (NIPR requirement).
 */
export function configureLocalEnv(baseUrl: string): void {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  env.allowRemoteModels = false;
  env.allowLocalModels = true;
  env.localModelPath = `${base}models/`;
  env.useBrowserCache = true;
  env.backends.onnx.wasm.wasmPaths = `${base}wasm/`;
}

export async function initEmbeddingModel(): Promise<void> {
  if (extractor) return;
  extractor = (await pipeline('feature-extraction', MODEL_ID, {
    quantized: true,
  })) as FeatureExtractionPipeline;
}

export function isModelReady(): boolean {
  return extractor !== null;
}

async function embed(text: string): Promise<Float32Array> {
  if (!extractor) throw new Error('Embedding model not loaded');
  const cached = embeddingCache.get(text);
  if (cached) return cached;
  const output = await extractor(text, { pooling: 'mean', normalize: true });
  const vector = new Float32Array(output.data as Float32Array);
  embeddingCache.set(text, vector);
  return vector;
}

/** Expands normalized tokens into words the sentence model understands. */
const TOKEN_EXPANSION: Record<string, string> = {
  src: 'source',
  dst: 'destination',
  ip: 'IP address',
  port: 'port number',
  proto: 'protocol',
  app: 'application',
  cmd: 'command line',
  pid: 'process id',
  time: 'timestamp',
  host: 'host name',
  user: 'user account name',
  image: 'executable file path',
};

function expandName(name: string): string {
  return tokenize(name)
    .map((t) => TOKEN_EXPANSION[t] ?? t)
    .join(' ');
}

export function observedDescriptor(field: ObservedField, sourceType: string): string {
  const sample = truncate(stringify(field.value), 80);
  return `log field: ${expandName(field.name)}. sample: ${sample}. source: ${sourceType}`;
}

export function canonicalDescriptor(field: CanonicalField): string {
  return `log field: ${expandName(field.name)}. ${field.description}`;
}

export const embeddingMapper: Mapper = {
  name: 'embedding',

  async suggest(input: MapperInput): Promise<MappingSuggestion[]> {
    if (!extractor) throw new Error('Embedding model not loaded');

    const candidates = input.canonicalFields.filter(
      (c) => !input.alreadyFilled.has(c.name),
    );
    const canonicalVectors = await Promise.all(
      candidates.map((c) => embed(canonicalDescriptor(c))),
    );

    const suggestions: MappingSuggestion[] = [];
    for (const observed of input.observedFields) {
      const observedVector = await embed(observedDescriptor(observed, input.sourceType));
      const shape = detectValueShape(observed.value);
      for (let i = 0; i < candidates.length; i++) {
        if (!shapeCompatible(shape, candidates[i].typeHints)) continue;

        const similarity = cosineSimilarity(observedVector, canonicalVectors[i]);
        // Agreement with a specific (non-generic) type hint is independent
        // evidence, so it earns a small confidence bonus.
        const specificShapeMatch =
          candidates[i].typeHints?.includes(shape) && shape !== 'string' && shape !== 'number';
        const confidence = Math.min(1, Math.max(0, similarity) + (specificShapeMatch ? 0.1 : 0));
        suggestions.push({
          observedField: observed.name,
          canonicalField: candidates[i].name,
          confidence: Math.round(confidence * 100) / 100,
          sampleValue: observed.value,
          sourceType: input.sourceType,
          mapper: 'embedding',
        });
      }
    }
    return suggestions;
  },
};

function stringify(value: unknown): string {
  if (typeof value === 'string') return value;
  return JSON.stringify(value) ?? 'null';
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}...` : s;
}
