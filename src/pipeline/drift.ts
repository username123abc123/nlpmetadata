import type { CanonicalSchema, NormalizedEvent } from './types';

export interface DriftReport {
  /** Canonical fields present in at least one event. */
  presentFields: string[];
  /** Schema fields missing from every event. */
  missingFields: string[];
  /** Distinct unmapped observed field names across all events. */
  unmappedFieldNames: string[];
  /** Fraction of events with a value for each canonical field. */
  coverage: Record<string, number>;
}

export function detectDrift(
  events: NormalizedEvent[],
  schema: CanonicalSchema,
): DriftReport {
  const counts: Record<string, number> = {};
  const unmapped = new Set<string>();

  for (const event of events) {
    for (const key of Object.keys(event.canonical)) {
      counts[key] = (counts[key] ?? 0) + 1;
    }
    for (const field of event.unmappedObservedFields) {
      unmapped.add(field.name);
    }
  }

  const total = events.length || 1;
  const coverage: Record<string, number> = {};
  const presentFields: string[] = [];
  const missingFields: string[] = [];

  for (const field of schema.fields) {
    const count = counts[field.name] ?? 0;
    coverage[field.name] = count / total;
    if (count > 0) presentFields.push(field.name);
    else missingFields.push(field.name);
  }

  return {
    presentFields,
    missingFields,
    unmappedFieldNames: [...unmapped].sort(),
    coverage,
  };
}
