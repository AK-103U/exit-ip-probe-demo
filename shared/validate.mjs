const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const MAX_INPUT_BYTES = 64 * 1024;
export const MAX_NODES_PER_TASK = 20;

export function isValidUuid(value) {
  return typeof value === 'string' && UUID_RE.test(value);
}

/**
 * Strips leading blank lines and trailing whitespace while preserving the first line's
 * indentation, so indented YAML pasted from a Clash `proxies:` block stays parseable.
 */
export function normalizeProbeInput(input) {
  return String(input).replace(/^(?:[ \t]*\r?\n)+/, '').trimEnd();
}

/**
 * Lightweight pre-validation in CF Worker to fail fast on empty or oversized input
 * without spending Worker CPU on full YAML parsing.
 */
export function validateProbeInput(input) {
  if (typeof input !== 'string') {
    return { ok: false, error: 'input must be a string' };
  }
  const normalized = normalizeProbeInput(input);
  if (!normalized.trim()) {
    return { ok: false, error: 'input cannot be empty' };
  }
  const byteLen = new TextEncoder().encode(normalized).byteLength;
  if (byteLen > MAX_INPUT_BYTES) {
    return { ok: false, error: `input exceeds ${MAX_INPUT_BYTES} bytes limit` };
  }
  return { ok: true, value: normalized };
}
