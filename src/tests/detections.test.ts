import { describe, expect, it } from 'vitest';
import { ingest } from '../pipeline/ingest';
import { adaptEvents } from '../pipeline/adapters';
import { normalizeEvents } from '../pipeline/normalize';
import { correlate } from '../pipeline/correlate';
import { evaluateDetections, totalAlerts } from '../pipeline/detections';
import { heuristicMapper } from '../nlp/heuristicMapper';
import { selectBestSuggestions, DEFAULT_CONFIDENCE_THRESHOLD } from '../nlp/mapper';
import type { CanonicalSchema, MappingTable, SourceType } from '../pipeline/types';
import schemaJson from '../schema/schema.json';
import suricataStable from '../data/suricata_stable.json';
import suricataDrifted from '../data/suricata_drifted.json';
import sysmonStable from '../data/sysmon_stable.json';
import sysmonDrifted from '../data/sysmon_drifted.json';

const schema = schemaJson as CanonicalSchema;

function normalize(
  data: unknown,
  sourceType: SourceType,
  extraMappings?: Partial<Record<SourceType, MappingTable>>,
) {
  return normalizeEvents(adaptEvents(ingest(JSON.stringify(data)), sourceType), {
    extraMappings,
  });
}

function evaluate(
  suricata: unknown,
  sysmon: unknown,
  extraMappings?: Partial<Record<SourceType, MappingTable>>,
) {
  const net = normalize(suricata, 'suricata', extraMappings);
  const end = normalize(sysmon, 'sysmon', extraMappings);
  return evaluateDetections(net, end, correlate(net, end));
}

describe('detection rules on stable logs', () => {
  const results = evaluate(suricataStable, sysmonStable);
  const byId = Object.fromEntries(results.map((r) => [r.rule.id, r]));

  it('fires the expected alerts', () => {
    expect(byId['outbound-ssh'].fired).toHaveLength(1);
    expect(byId['external-smb'].fired).toHaveLength(1);
    expect(byId['http-nonstandard-port'].fired).toHaveLength(1);
    expect(byId['temp-process-netconn'].fired).toHaveLength(1);
    expect(byId['ids-alert-attributed'].fired).toHaveLength(3);
    expect(totalAlerts(results)).toBe(7);
  });

  it('reports no rules broken', () => {
    expect(results.every((r) => !r.broken)).toBe(true);
  });

  it('attributes the Temp-directory alert to the endpoint process', () => {
    expect(byId['temp-process-netconn'].fired[0].summary).toContain('updater.exe');
    expect(byId['temp-process-netconn'].fired[0].summary).toContain('WKSTN-ALPHA-01');
  });
});

describe('detection rules on drifted logs (silent breakage)', () => {
  const results = evaluate(suricataDrifted, sysmonDrifted);

  it('fires zero alerts', () => {
    expect(totalAlerts(results)).toBe(0);
  });

  it('marks every rule broken with the missing fields named', () => {
    for (const r of results) {
      expect(r.broken).toBe(true);
      expect(r.missingFields.length).toBeGreaterThan(0);
    }
    const smb = results.find((r) => r.rule.id === 'external-smb')!;
    expect(smb.missingFields).toEqual(['dst.port']);
  });
});

describe('detection rules after heuristic repair', () => {
  it('restores correlation-dependent alerts', async () => {
    const extraMappings: Partial<Record<SourceType, MappingTable>> = {};
    for (const [data, sourceType] of [
      [suricataDrifted, 'suricata'],
      [sysmonDrifted, 'sysmon'],
    ] as const) {
      const normalized = normalize(data, sourceType);
      const unmapped = new Map(
        normalized.flatMap((e) => e.unmappedObservedFields.map((f) => [f.name, f] as const)),
      );
      const suggestions = await heuristicMapper.suggest({
        observedFields: [...unmapped.values()],
        sourceType,
        canonicalFields: schema.fields,
        alreadyFilled: new Set(normalized.flatMap((e) => Object.keys(e.canonical))),
      });
      extraMappings[sourceType] = Object.fromEntries(
        selectBestSuggestions(suggestions, DEFAULT_CONFIDENCE_THRESHOLD).map((s) => [
          s.observedField,
          s.canonicalField,
        ]),
      );
    }

    const results = evaluate(suricataDrifted, sysmonDrifted, extraMappings);
    const byId = Object.fromEntries(results.map((r) => [r.rule.id, r]));
    expect(byId['external-smb'].fired).toHaveLength(1);
    expect(byId['temp-process-netconn'].fired).toHaveLength(1);
    expect(byId['ids-alert-attributed'].fired).toHaveLength(3);
    expect(totalAlerts(results)).toBeGreaterThanOrEqual(5);
  });
});
