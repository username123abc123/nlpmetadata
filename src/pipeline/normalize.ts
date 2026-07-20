import type {
  AdaptedEvent,
  MappingTable,
  NormalizedEvent,
  SourceType,
} from './types';

/**
 * Deterministic mappings for the known "stable" vendor field names.
 * Drifted field names are intentionally absent — the mapping/repair layer
 * must discover them.
 */
export const KNOWN_MAPPINGS: Record<SourceType, MappingTable> = {
  suricata: {
    timestamp: '@timestamp',
    event_type: 'event.type',
    src_ip: 'src.ip',
    src_port: 'src.port',
    dest_ip: 'dst.ip',
    dest_port: 'dst.port',
    proto: 'network.transport',
    app_proto: 'network.protocol',
    host: 'host.name',
    'alert.signature': 'rule.name',
    'alert.severity': 'event.severity',
  },
  sysmon: {
    UtcTime: '@timestamp',
    Computer: 'host.name',
    User: 'user.name',
    Image: 'process.executable',
    CommandLine: 'process.command_line',
    ProcessId: 'process.pid',
    SourceIp: 'src.ip',
    SourcePort: 'src.port',
    DestinationIp: 'dst.ip',
    DestinationPort: 'dst.port',
    Protocol: 'network.transport',
  },
};

export interface NormalizeOptions {
  /** Learned/repaired mappings applied on top of the deterministic table. */
  extraMappings?: Partial<Record<SourceType, MappingTable>>;
}

export function normalizeEvent(
  event: AdaptedEvent,
  options: NormalizeOptions = {},
): NormalizedEvent {
  const table: MappingTable = {
    ...KNOWN_MAPPINGS[event.sourceType],
    ...(options.extraMappings?.[event.sourceType] ?? {}),
  };

  const canonical: Record<string, unknown> = {};
  const unmappedObservedFields = [];

  for (const field of event.observedFields) {
    const canonicalName = table[field.name];
    if (canonicalName !== undefined) {
      canonical[canonicalName] = normalizeValue(canonicalName, field.value);
    } else {
      unmappedObservedFields.push(field);
    }
  }

  deriveEventCategory(event.sourceType, canonical);

  return {
    sourceType: event.sourceType,
    canonical,
    unmappedObservedFields,
    raw: event.raw,
  };
}

export function normalizeEvents(
  events: AdaptedEvent[],
  options: NormalizeOptions = {},
): NormalizedEvent[] {
  return events.map((e) => normalizeEvent(e, options));
}

function normalizeValue(canonicalName: string, value: unknown): unknown {
  if (canonicalName === 'network.transport' || canonicalName === 'network.protocol') {
    return typeof value === 'string' ? value.toLowerCase() : value;
  }
  return value;
}

function deriveEventCategory(
  sourceType: SourceType,
  canonical: Record<string, unknown>,
): void {
  if (canonical['event.category'] !== undefined) return;
  if (sourceType === 'suricata') {
    canonical['event.category'] = 'network';
  } else {
    canonical['event.category'] =
      canonical['src.ip'] !== undefined || canonical['dst.ip'] !== undefined
        ? 'network'
        : 'process';
  }
}
