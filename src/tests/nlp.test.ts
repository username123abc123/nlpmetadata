import { describe, expect, it } from 'vitest';
import { detectValueShape, shapeCompatible } from '../nlp/valueShapes';
import { cosineSimilarity } from '../nlp/cosine';
import { heuristicMapper, tokenize } from '../nlp/heuristicMapper';
import { selectBestSuggestions, DEFAULT_CONFIDENCE_THRESHOLD } from '../nlp/mapper';
import { ingest } from '../pipeline/ingest';
import { adaptEvents } from '../pipeline/adapters';
import { normalizeEvents } from '../pipeline/normalize';
import { correlate } from '../pipeline/correlate';
import type { CanonicalSchema, MappingTable, SourceType } from '../pipeline/types';
import schemaJson from '../schema/schema.json';
import suricataDrifted from '../data/suricata_drifted.json';
import sysmonDrifted from '../data/sysmon_drifted.json';

const schema = schemaJson as CanonicalSchema;

describe('detectValueShape', () => {
  it.each([
    ['10.0.5.21', 'ip'],
    ['2026-07-01T14:02:11.104Z', 'timestamp'],
    ['C:\\Windows\\System32\\rundll32.exe', 'path'],
    ['/usr/bin/synthetic', 'path'],
    ['CORP\\jdoe.synthetic', 'username'],
    ['WKSTN-ALPHA-01', 'hostname'],
  ] as const)('detects %s as %s', (value, expected) => {
    expect(detectValueShape(value)).toBe(expected);
  });

  it('detects ports and numbers', () => {
    expect(detectValueShape(443)).toBe('port');
    expect(detectValueShape(70000)).toBe('number');
  });

  it('rejects out-of-range IPv4 octets', () => {
    expect(detectValueShape('999.999.999.999')).not.toBe('ip');
  });

  it('shape compatibility respects hints', () => {
    expect(shapeCompatible('ip', ['ip'])).toBe(true);
    expect(shapeCompatible('ip', ['port'])).toBe(false);
    expect(shapeCompatible('port', ['number'])).toBe(true);
  });
});

describe('cosineSimilarity', () => {
  it('is 1 for identical vectors and 0 for orthogonal', () => {
    expect(cosineSimilarity([1, 2, 3], [1, 2, 3])).toBeCloseTo(1);
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0);
  });

  it('throws on length mismatch', () => {
    expect(() => cosineSimilarity([1], [1, 2])).toThrow();
  });
});

describe('tokenize', () => {
  it('splits camelCase and snake_case with synonym normalization', () => {
    expect(tokenize('DestinationIp')).toEqual(['dst', 'ip']);
    expect(tokenize('source_address')).toEqual(['src', 'ip']);
    expect(tokenize('SrcPortNumber')).toEqual(['src', 'port']);
  });
});

async function repairAndCorrelate() {
  const extraMappings: Partial<Record<SourceType, MappingTable>> = {};

  for (const [data, sourceType] of [
    [suricataDrifted, 'suricata'],
    [sysmonDrifted, 'sysmon'],
  ] as const) {
    const adapted = adaptEvents(ingest(JSON.stringify(data)), sourceType);
    const normalized = normalizeEvents(adapted);
    const unmapped = new Map(
      normalized.flatMap((e) => e.unmappedObservedFields.map((f) => [f.name, f] as const)),
    );
    const alreadyFilled = new Set(normalized.flatMap((e) => Object.keys(e.canonical)));

    const suggestions = await heuristicMapper.suggest({
      observedFields: [...unmapped.values()],
      sourceType,
      canonicalFields: schema.fields,
      alreadyFilled,
    });
    const applied = selectBestSuggestions(suggestions, DEFAULT_CONFIDENCE_THRESHOLD);
    extraMappings[sourceType] = Object.fromEntries(
      applied.map((s) => [s.observedField, s.canonicalField]),
    );
  }

  const net = normalizeEvents(
    adaptEvents(ingest(JSON.stringify(suricataDrifted)), 'suricata'),
    { extraMappings },
  );
  const end = normalizeEvents(
    adaptEvents(ingest(JSON.stringify(sysmonDrifted)), 'sysmon'),
    { extraMappings },
  );
  return { net, end, extraMappings };
}

describe('heuristic repair end-to-end', () => {
  it('recovers key drifted fields and restores correlation', async () => {
    const { net, end, extraMappings } = await repairAndCorrelate();

    expect(extraMappings.suricata?.['source_address']).toBe('src.ip');
    expect(extraMappings.suricata?.['destination.address']).toBe('dst.ip');
    expect(extraMappings.sysmon?.['SrcIP']).toBe('src.ip');
    expect(extraMappings.sysmon?.['DstIP']).toBe('dst.ip');

    expect(net[0].canonical['src.ip']).toBe('10.0.5.21');
    expect(end[0].canonical['src.ip']).toBe('10.0.5.21');

    const result = correlate(net, end);
    expect(result.matches.length).toBeGreaterThanOrEqual(4);
  });

  it('never double-assigns a canonical field', async () => {
    const { extraMappings } = await repairAndCorrelate();
    for (const table of Object.values(extraMappings)) {
      const targets = Object.values(table!);
      expect(new Set(targets).size).toBe(targets.length);
    }
  });
});
