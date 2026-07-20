import type { ParsedEvent } from './types';

/**
 * Accepts raw text that is either a JSON array, a single JSON object, or
 * newline-delimited JSON. Non-JSON lines are kept as raw text with json=null.
 */
export function ingest(rawText: string): ParsedEvent[] {
  const trimmed = rawText.trim();
  if (trimmed.length === 0) return [];

  if (trimmed.startsWith('[')) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) {
        return arr.map((item) => ({
          raw: JSON.stringify(item),
          json: isRecord(item) ? item : null,
        }));
      }
    } catch {
      // fall through to line-by-line handling
    }
  }

  return trimmed
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      try {
        const parsed = JSON.parse(line);
        return { raw: line, json: isRecord(parsed) ? parsed : null };
      } catch {
        return { raw: line, json: null };
      }
    });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
