import { env } from '@xenova/transformers';
import { initEmbeddingModel, embeddingMapper } from '../src/nlp/embeddingMapper';
import { selectBestSuggestions } from '../src/nlp/mapper';
import { ingest } from '../src/pipeline/ingest';
import { adaptEvents } from '../src/pipeline/adapters';
import { normalizeEvents } from '../src/pipeline/normalize';
import type { CanonicalSchema } from '../src/pipeline/types';
import schemaJson from '../src/schema/schema.json' with { type: 'json' };
import suricataDrifted from '../src/data/suricata_drifted.json' with { type: 'json' };
import sysmonDrifted from '../src/data/sysmon_drifted.json' with { type: 'json' };

const schema = schemaJson as CanonicalSchema;
env.allowRemoteModels = false;
env.allowLocalModels = true;
env.localModelPath = new URL('../public/models/', import.meta.url).pathname;
await initEmbeddingModel();

for (const [data, sourceType] of [
  [suricataDrifted, 'suricata'],
  [sysmonDrifted, 'sysmon'],
] as const) {
  const normalized = normalizeEvents(adaptEvents(ingest(JSON.stringify(data)), sourceType));
  const unmapped = new Map(
    normalized.flatMap((e) => e.unmappedObservedFields.map((f) => [f.name, f] as const)),
  );
  const suggestions = await embeddingMapper.suggest({
    observedFields: [...unmapped.values()],
    sourceType,
    canonicalFields: schema.fields,
    alreadyFilled: new Set(normalized.flatMap((e) => Object.keys(e.canonical))),
  });
  console.log(`\n=== ${sourceType} — all suggestions per field ===`);
  const byField = new Map<string, typeof suggestions>();
  for (const s of suggestions) {
    if (!byField.has(s.observedField)) byField.set(s.observedField, []);
    byField.get(s.observedField)!.push(s);
  }
  for (const [field, list] of byField) {
    const top = [...list].sort((a, b) => b.confidence - a.confidence).slice(0, 3);
    console.log(
      `${field}: ${top.map((s) => `${s.canonicalField}=${s.confidence}`).join(', ')}`,
    );
  }
  console.log('--- applied at 0.55:');
  for (const s of selectBestSuggestions(suggestions, 0.55)) {
    console.log(`  ${s.observedField} -> ${s.canonicalField} (${s.confidence})`);
  }
}
