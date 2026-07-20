import type { CorrelationResult, NormalizedEvent } from './types';

const REQUIRED_KEYS = ['src.ip', 'dst.ip', 'dst.port'] as const;
const OPTIONAL_KEYS = ['network.transport'] as const;
const TIME_WINDOW_MS = 60_000;

/**
 * Matches network (Suricata) events to endpoint (Sysmon-like) events on the
 * canonical src.ip/dst.ip/dst.port tuple within a +/-60s timestamp window.
 * network.transport must agree when both sides carry it. Missing required
 * canonical fields prevent a match — which is exactly what drift breaks.
 */
export function correlate(
  networkEvents: NormalizedEvent[],
  endpointEvents: NormalizedEvent[],
): CorrelationResult {
  const matches = [];

  for (let n = 0; n < networkEvents.length; n++) {
    const net = networkEvents[n].canonical;
    for (let e = 0; e < endpointEvents.length; e++) {
      const end = endpointEvents[e].canonical;

      const matchedKeys: string[] = [];
      let ok = true;
      for (const key of REQUIRED_KEYS) {
        if (!valuesMatch(net[key], end[key], true)) {
          ok = false;
          break;
        }
        matchedKeys.push(key);
      }
      if (!ok) continue;

      for (const key of OPTIONAL_KEYS) {
        if (net[key] === undefined || end[key] === undefined) continue;
        if (!valuesMatch(net[key], end[key], true)) {
          ok = false;
          break;
        }
        matchedKeys.push(key);
      }
      if (!ok) continue;

      const tNet = toEpochMs(net['@timestamp']);
      const tEnd = toEpochMs(end['@timestamp']);
      if (tNet === null || tEnd === null) continue;
      if (Math.abs(tNet - tEnd) > TIME_WINDOW_MS) continue;

      matches.push({ networkIndex: n, endpointIndex: e, keys: [...matchedKeys, '@timestamp'] });
    }
  }

  return {
    matches,
    networkEventCount: networkEvents.length,
    endpointEventCount: endpointEvents.length,
  };
}

function valuesMatch(a: unknown, b: unknown, requirePresent: boolean): boolean {
  if (a === undefined || b === undefined) return !requirePresent;
  return String(a).toLowerCase() === String(b).toLowerCase();
}

function toEpochMs(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}
