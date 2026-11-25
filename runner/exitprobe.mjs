/**
 * Exit IP probing through the node tunnel, per address family, with ordered fallbacks:
 *   1. ippure  (my.ippure.com/v1/info): exit IP + geo + fraud score / residential / broadcast
 *   2. Cloudflare cdn-cgi/trace:        exit IP + colo + warp flag
 *   3. ipify:                           exit IP only
 * ippure is dual-stack, so IPv4 / IPv6 are forced with curl --connect-to to its resolved
 * A / AAAA address while keeping SNI and Host intact.
 */
import { ipMatchesFamily, normalizeIppure, parseCfTrace } from './diagnostics.mjs';

export const IPPURE_HOST = 'my.ippure.com';
export const IPPURE_URL = `https://${IPPURE_HOST}/v1/info`;

function ippureTier(addr) {
  if (addr === null) return null;
  const tier = { kind: 'ippure', url: IPPURE_URL, timeoutSec: 10 };
  if (addr) tier.connectTo = `${IPPURE_HOST}:443:${addr.includes(':') ? `[${addr}]` : addr}:443`;
  return tier;
}

/**
 * @param {{ v4?: string, v6?: string }} targets resolved addresses of my.ippure.com
 *   (a family without an address skips the ippure tier for that family).
 */
export function buildFamilySpecs(targets = {}) {
  return {
    ipv4: {
      family: 4,
      tiers: [
        ippureTier(targets.v4 || null),
        { kind: 'cf-trace', url: 'https://1.1.1.1/cdn-cgi/trace', timeoutSec: 8 },
        { kind: 'ipify', url: 'https://api4.ipify.org?format=json', timeoutSec: 8 },
      ].filter(Boolean),
      hosts: [targets.v4, '1.1.1.1', 'api4.ipify.org'].filter(Boolean),
    },
    ipv6: {
      family: 6,
      tiers: [
        ippureTier(targets.v6 || null),
        { kind: 'cf-trace', url: 'https://[2606:4700:4700::1111]/cdn-cgi/trace', timeoutSec: 8 },
        { kind: 'ipify', url: 'https://api6.ipify.org?format=json', timeoutSec: 8 },
      ].filter(Boolean),
      hosts: [targets.v6, '2606:4700:4700::1111', 'api6.ipify.org'].filter(Boolean),
    },
    dual: {
      family: 0,
      tiers: [
        ippureTier(undefined),
        { kind: 'cf-trace', url: 'https://www.cloudflare.com/cdn-cgi/trace', timeoutSec: 8 },
        { kind: 'ipify', url: 'https://api64.ipify.org?format=json', timeoutSec: 8 },
      ],
      hosts: [IPPURE_HOST, 'www.cloudflare.com', 'api64.ipify.org'],
    },
  };
}

export function parseTierResponse(kind, body) {
  if (kind === 'ippure') {
    const json = JSON.parse(body);
    return { ip: json?.ip, geo: normalizeIppure(json) || undefined };
  }
  if (kind === 'cf-trace') {
    const t = parseCfTrace(body);
    return { ip: t.ip, colo: t.colo, warp: t.warp };
  }
  return { ip: JSON.parse(body)?.ip };
}

/**
 * Tries each tier until one returns an IP of the expected family.
 * curlFn(url, { timeoutSec, connectTo }) → { ok: true, body } | { ok: false, curlCode, message }.
 */
export async function probeFamily(spec, curlFn, now = Date.now) {
  const started = now();
  const attempts = [];
  for (const tier of spec.tiers) {
    // Two SOCKS-level failures in a row: the tunnel itself is down, more endpoints won't help.
    if (attempts.length >= 2 && attempts.slice(-2).every((a) => a.curlCode === 97)) break;

    const res = await curlFn(tier.url, { timeoutSec: tier.timeoutSec, connectTo: tier.connectTo });
    if (!res.ok) {
      attempts.push({ ...res, source: tier.kind });
      continue;
    }
    let parsed = null;
    try {
      parsed = parseTierResponse(tier.kind, res.body);
    } catch {
      parsed = null;
    }
    if (parsed && ipMatchesFamily(parsed.ip, spec.family)) {
      return { ok: true, ...parsed, source: tier.kind, ms: now() - started };
    }
    attempts.push({ ok: false, badResponse: true, source: tier.kind, message: `unexpected ${tier.kind} response` });
  }
  return { ok: false, attempts, ms: now() - started };
}
