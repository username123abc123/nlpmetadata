import { beforeAll, describe, expect, it } from 'vitest';
import { env } from '@xenova/transformers';
import {
  canonicalDescriptor,
  embeddingMapper,
  initEmbeddingModel,
  isModelReady,
  observedDescriptor,
} from '../nlp/embeddingMapper';
import { selectBestSuggestions } from '../nlp/mapper';
import { ingest } from '../pipeline/ingest';
import { adaptEvents } from '../pipeline/adapters';
import { normalizeEvents } from '../pipeline/normalize';
import { correlate } from '../pipeline/correlate';
import { evaluateDetections, totalAlerts } from '../pipeline/detections';
import type { CanonicalSchema, MappingTable, SourceType } from '../pipeline/types';
import schemaJson from '../schema/schema.json';
import suricataDrifted from '../data/suricata_drifted.json';
import sysmonDrifted from '../data/sysmon_drifted.json';

const schema = schemaJson as CanonicalSchema;

// Loads the locally bundled model artifacts with remote downloads disabled —
// the same guarantee the browser build relies on for offline (NIPR) use.
beforeAll(async () => {
  env.allowRemoteModels = false;
  env.allowLocalModels = true;
  env.localModelPath = new URL('../../public/models/', import.meta.url).pathname;
  await initEmbeddingModel();
}, 120_000);

describe('embedding mapper (local model, no network)', () => {
  it('loads the model from local artifacts', () => {
    expect(isModelReady()).toBe(true);
  });

  it('builds descriptor strings with expanded abbreviations', () => {
    expect(observedDescriptor({ name: 'SrcIP', value: '10.0.5.21' }, 'sysmon')).toBe(
      'log field: source IP address. sample: 10.0.5.21. source: sysmon',
    );
    expect(canonicalDescriptor(schema.fields[3])).toContain('source IP address');
  });

  it('maps drifted fields to the correct canonical fields', async () => {
    const suggestions = await embeddingMapper.suggest({
      observedFields: [
        { name: 'source_address', value: '10.0.5.21' },
        { name: 'destination.address', value: '192.0.2.44' },
        { name: 'transport_protocol', value: 'TCP' },
        { name: 'AccountName', value: 'CORP\\jdoe.synthetic' },
        { name: 'ProcessImagePath', value: 'C:\\Temp\\updater.exe' },
      ],
      sourceType: 'sysmon',
      canonicalFields: schema.fields,
      alreadyFilled: new Set(),
    });

    const applied = selectBestSuggestions(suggestions, 0.55);
    const table = Object.fromEntries(applied.map((s) => [s.observedField, s.canonicalField]));

    expect(table['source_address']).toBe('src.ip');
    expect(table['destination.address']).toBe('dst.ip');
    expect(table['transport_protocol']).toBe('network.transport');
    expect(table['AccountName']).toBe('user.name');
    expect(table['ProcessImagePath']).toBe('process.executable');
  }, 60_000);

  it('demo path: drifted logs -> embedding repair -> correlation restored', async () => {
    const extraMappings: Partial<Record<SourceType, MappingTable>> = {};

    for (const [data, sourceType] of [
      [suricataDrifted, 'suricata'],
      [sysmonDrifted, 'sysmon'],
    ] as const) {
      const normalized = normalizeEvents(
        adaptEvents(ingest(JSON.stringify(data)), sourceType),
      );
      const unmapped = new Map(
        normalized.flatMap((e) => e.unmappedObservedFields.map((f) => [f.name, f] as const)),
      );
      const alreadyFilled = new Set(normalized.flatMap((e) => Object.keys(e.canonical)));

      const suggestions = await embeddingMapper.suggest({
        observedFields: [...unmapped.values()],
        sourceType,
        canonicalFields: schema.fields,
        alreadyFilled,
      });
      const applied = selectBestSuggestions(suggestions, 0.55);
      extraMappings[sourceType] = Object.fromEntries(
        applied.map((s) => [s.observedField, s.canonicalField]),
      );
    }

    // Before repair: zero correlation.
    const netBroken = normalizeEvents(
      adaptEvents(ingest(JSON.stringify(suricataDrifted)), 'suricata'),
    );
    const endBroken = normalizeEvents(
      adaptEvents(ingest(JSON.stringify(sysmonDrifted)), 'sysmon'),
    );
    expect(correlate(netBroken, endBroken).matches).toHaveLength(0);
    expect(
      totalAlerts(evaluateDetections(netBroken, endBroken, correlate(netBroken, endBroken))),
    ).toBe(0);

    // After repair: correlation restored.
    const net = normalizeEvents(
      adaptEvents(ingest(JSON.stringify(suricataDrifted)), 'suricata'),
      { extraMappings },
    );
    const end = normalizeEvents(
      adaptEvents(ingest(JSON.stringify(sysmonDrifted)), 'sysmon'),
      { extraMappings },
    );
    const correlation = correlate(net, end);
    expect(correlation.matches.length).toBeGreaterThanOrEqual(4);

    // All preset detections fire again, matching the stable baseline of 7.
    expect(totalAlerts(evaluateDetections(net, end, correlation))).toBe(7);
  }, 120_000);
});
