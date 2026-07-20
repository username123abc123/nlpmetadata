export type SourceType = 'suricata' | 'sysmon';

export type TypeHint =
  | 'ip'
  | 'port'
  | 'timestamp'
  | 'string'
  | 'path'
  | 'hostname'
  | 'username'
  | 'number';

export interface CanonicalField {
  name: string;
  description: string;
  typeHints?: TypeHint[];
}

export interface CanonicalSchema {
  version: string;
  fields: CanonicalField[];
}

export interface ParsedEvent {
  raw: string;
  json: Record<string, unknown> | null;
}

export interface ObservedField {
  name: string;
  value: unknown;
}

export interface AdaptedEvent {
  sourceType: SourceType;
  observedFields: ObservedField[];
  raw: string;
}

export interface NormalizedEvent {
  sourceType: SourceType;
  canonical: Record<string, unknown>;
  unmappedObservedFields: ObservedField[];
  raw: string;
}

/** observed field name -> canonical field name */
export type MappingTable = Record<string, string>;

export interface MappingSuggestion {
  observedField: string;
  canonicalField: string;
  confidence: number;
  sampleValue: unknown;
  sourceType: SourceType;
  mapper: 'heuristic' | 'embedding';
}

export interface CorrelationMatch {
  networkIndex: number;
  endpointIndex: number;
  keys: string[];
}

export interface CorrelationResult {
  matches: CorrelationMatch[];
  networkEventCount: number;
  endpointEventCount: number;
}
