import { describe, expect, it } from 'vitest';
import { ingest } from '../pipeline/ingest';
import { adaptEvents, flattenToObservedFields } from '../pipeline/adapters';
import { normalizeEvents } from '../pipeline/normalize';
import { correlate } from '../pipeline/correlate';
import { detectDrift } from '../pipeline/drift';
import type { CanonicalSchema } from '../pipeline/types';
import schemaJson from '../schema/schema.json';
import suricataStable from '../data/suricata_stable.json';
import suricataDrifted from '../data/suricata_drifted.json';
import sysmonStable from '../data/sysmon_stable.json';
import sysmonDrifted from '../data/sysmon_drifted.json';

const schema = schemaJson as CanonicalSchema;

function runPipeline(data: unknown, sourceType: 'suricata' | 'sysmon') {
  const parsed = ingest(JSON.stringify(data));
  const adapted = adaptEvents(parsed, sourceType);
  return normalizeEvents(adapted);
}

describe('ingest', () => {
  it('parses a JSON array into one event per element', () => {
    const events = ingest('[{"a":1},{"b":2}]');
    expect(events).toHaveLength(2);
    expect(events[0].json).toEqual({ a: 1 });
  });

  it('parses newline-delimited JSON', () => {
    const events = ingest('{"a":1}\n{"b":2}\n');
    expect(events).toHaveLength(2);
    expect(events[1].json).toEqual({ b: 2 });
  });

  it('keeps non-JSON lines as raw text', () => {
    const events = ingest('not json at all');
    expect(events).toHaveLength(1);
    expect(events[0].json).toBeNull();
    expect(events[0].raw).toBe('not json at all');
  });

  it('returns empty array for empty input', () => {
    expect(ingest('   ')).toEqual([]);
  });
});

describe('adapter flattening', () => {
  it('flattens nested objects to dot paths', () => {
    const fields = flattenToObservedFields({ alert: { severity: 2 }, src_ip: '10.0.0.1' });
    expect(fields).toContainEqual({ name: 'alert.severity', value: 2 });
    expect(fields).toContainEqual({ name: 'src_ip', value: '10.0.0.1' });
  });
});

describe('stable normalization', () => {
  it('maps all key Suricata fields to canonical names', () => {
    const normalized = runPipeline(suricataStable, 'suricata');
    const first = normalized[0].canonical;
    expect(first['src.ip']).toBe('10.0.5.21');
    expect(first['dst.ip']).toBe('192.0.2.44');
    expect(first['dst.port']).toBe(443);
    expect(first['network.transport']).toBe('tcp');
    expect(first['@timestamp']).toBe('2026-07-01T14:02:11.104Z');
    expect(first['rule.name']).toContain('SYNTH');
  });

  it('maps all key Sysmon fields to canonical names', () => {
    const normalized = runPipeline(sysmonStable, 'sysmon');
    const first = normalized[0].canonical;
    expect(first['src.ip']).toBe('10.0.5.21');
    expect(first['dst.ip']).toBe('192.0.2.44');
    expect(first['host.name']).toBe('WKSTN-ALPHA-01');
    expect(first['user.name']).toContain('jdoe.synthetic');
  });
});

describe('drift breaks normalization', () => {
  it('drifted Suricata logs lose src.ip and dst.ip', () => {
    const normalized = runPipeline(suricataDrifted, 'suricata');
    const report = detectDrift(normalized, schema);
    expect(report.missingFields).toContain('src.ip');
    expect(report.missingFields).toContain('dst.ip');
    expect(report.unmappedFieldNames).toContain('source_address');
    expect(report.unmappedFieldNames).toContain('destination.address');
  });

  it('drifted Sysmon logs lose src.ip and user.name', () => {
    const normalized = runPipeline(sysmonDrifted, 'sysmon');
    const report = detectDrift(normalized, schema);
    expect(report.missingFields).toContain('src.ip');
    expect(report.missingFields).toContain('user.name');
  });
});

describe('correlation', () => {
  it('correlates stable network and endpoint events', () => {
    const net = runPipeline(suricataStable, 'suricata');
    const end = runPipeline(sysmonStable, 'sysmon');
    const result = correlate(net, end);
    expect(result.matches.length).toBeGreaterThanOrEqual(4);
  });

  it('drift drops correlation to zero', () => {
    const net = runPipeline(suricataDrifted, 'suricata');
    const end = runPipeline(sysmonDrifted, 'sysmon');
    const result = correlate(net, end);
    expect(result.matches).toHaveLength(0);
  });

  it('does not match events outside the time window', () => {
    const net = runPipeline(suricataStable, 'suricata');
    const end = runPipeline(sysmonStable, 'sysmon');
    for (const e of end) {
      e.canonical['@timestamp'] = '2026-07-01T20:00:00.000Z';
    }
    expect(correlate(net, end).matches).toHaveLength(0);
  });
});
