import type { AdaptedEvent, ObservedField, ParsedEvent, SourceType } from './types';

/**
 * Flattens nested JSON into dot-path observed fields, e.g.
 * { alert: { severity: 2 } } -> "alert.severity" = 2.
 * Arrays are stringified as values rather than expanded.
 */
export function flattenToObservedFields(
  obj: Record<string, unknown>,
  prefix = '',
): ObservedField[] {
  const fields: ObservedField[] = [];
  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      fields.push(...flattenToObservedFields(value as Record<string, unknown>, path));
    } else {
      fields.push({ name: path, value });
    } 
  }
  return fields;
}

export function adaptEvent(event: ParsedEvent, sourceType: SourceType): AdaptedEvent {
  const observedFields = event.json ? flattenToObservedFields(event.json) : [];
  return { sourceType, observedFields, raw: event.raw };
}

export function adaptEvents(events: ParsedEvent[], sourceType: SourceType): AdaptedEvent[] {
  return events.map((e) => adaptEvent(e, sourceType));
}
