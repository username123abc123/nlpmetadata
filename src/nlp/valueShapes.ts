import type { TypeHint } from '../pipeline/types';

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/;
const WINDOWS_PATH = /^[A-Za-z]:\\/;
const UNIX_PATH = /^\/(?:[^/\0]+\/?)+$/;
const DOMAIN_USER = /^[\w.-]+\\[\w.$-]+$/;
const HOSTNAME = /^[A-Za-z][A-Za-z0-9-]*(?:-\d+)?$/;

/** Infers a coarse type from a sample value; used to sanity-check mappings. */
export function detectValueShape(value: unknown): TypeHint {
  if (typeof value === 'number') {
    if (Number.isInteger(value) && value >= 0 && value <= 65535) return 'port';
    return 'number';
  }
  if (typeof value !== 'string') return 'string';

  if (IPV4.test(value) && value.split('.').every((o) => Number(o) <= 255)) return 'ip';
  if (TIMESTAMP.test(value)) return 'timestamp';
  if (WINDOWS_PATH.test(value) || UNIX_PATH.test(value)) return 'path';
  if (DOMAIN_USER.test(value)) return 'username';
  if (/^\d+$/.test(value)) {
    const n = Number(value);
    return n >= 0 && n <= 65535 ? 'port' : 'number';
  }
  if (HOSTNAME.test(value) && value.includes('-')) return 'hostname';
  return 'string';
}

/** Whether an observed value shape is compatible with a canonical field's hints. */
export function shapeCompatible(shape: TypeHint, hints: TypeHint[] | undefined): boolean {
  if (!hints || hints.length === 0) return true;
  if (hints.includes(shape)) return true;
  // Numbers can fill port fields and vice versa; generic strings fit string-ish hints.
  if (shape === 'port' && hints.includes('number')) return true;
  if (shape === 'number' && hints.includes('port')) return true;
  if (shape === 'string' && (hints.includes('hostname') || hints.includes('username'))) {
    return true;
  }
  return hints.includes('string');
}
