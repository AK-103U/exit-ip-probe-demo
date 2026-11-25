/**
 * Network-facing helpers used by the Runner outside of the proxy tunnel:
 * ECH config retrieval over DoH, entry host resolution, IP geo lookup, Runner IPv6 check.
 */
import { lookup } from 'node:dns/promises';
import net from 'node:net';
import { echConfigToPem } from './parser.mjs';
import { isPublicIp, normalizeIpApi, normalizeIpWhois } from './diagnostics.mjs';

const DOH_URLS = [
  (name) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=HTTPS`,
  (name) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=HTTPS`,
];

function withTimeout(promise, ms, fallback) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(fallback), ms);
    }),
  ]);
}

/** Extracts the `ech=` SvcParam from DNS HTTPS (type 65) answers in DoH JSON form. */
export function echFromDohAnswer(data) {
  for (const ans of data?.Answer || []) {
    if (ans?.type !== 65) continue;
    const m = /(?:^|\s)ech="?([A-Za-z0-9+/=_-]+)"?/.exec(String(ans.data || ''));
    const pem = m && echConfigToPem(m[1]);
    if (pem) return pem;
  }
  return null;
}

export async function fetchEchConfig(name, fetchFn = fetch) {
  for (const build of DOH_URLS) {
    try {
      const res = await fetchFn(build(name), {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) continue;
      const pem = echFromDohAnswer(await res.json());
      if (pem) return pem;
    } catch {
      // try next resolver
    }
  }
  return null;
}

/**
 * For ECH nodes without an inline config, fetch the ECHConfigList via DoH and embed it,
 * so the probe does not depend on the Runner's system resolver answering HTTPS records.
 * Falls back to sing-box's own DNS query (`query_server_name`) when DoH fails.
 * Sets node.ech to 'inline' | 'doh' | 'dns'.
 */
export async function prepareEch(nodes, fetchFn = fetch) {
  const cache = new Map();
  for (const node of nodes) {
    const tls = node.outbound?.tls;
    if (!tls?.ech?.enabled) continue;
    if (tls.ech.config) {
      node.ech = 'inline';
      continue;
    }
    const name = tls.ech.query_server_name || tls.server_name || node.outbound.server;
    if (!cache.has(name)) cache.set(name, fetchEchConfig(name, fetchFn));
    const pem = await cache.get(name);
    if (pem) {
      tls.ech = { enabled: true, config: pem };
      node.ech = 'doh';
    } else {
      node.ech = 'dns';
    }
  }
}

export async function resolveEntry(server) {
  if (net.isIP(server)) return { ips: [server] };
  try {
    const addrs = await withTimeout(lookup(server, { all: true, verbatim: true }), 5000, null);
    if (!addrs) return { ips: [], error: 'lookup_timeout' };
    return { ips: [...new Set(addrs.map((a) => a.address))].slice(0, 8) };
  } catch (err) {
    return { ips: [], error: err?.code || 'lookup_failed' };
  }
}

let ipv6Check;
/** Whether the Runner itself can open IPv6 connections (GitHub-hosted runners usually cannot). */
export function runnerHasIpv6() {
  ipv6Check ??= new Promise((resolve) => {
    const sock = net.createConnection({ host: '2606:4700:4700::1111', port: 443, family: 6 });
    const done = (v) => {
      sock.destroy();
      resolve(v);
    };
    sock.setTimeout(2500, () => done(false));
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
  return ipv6Check;
}

const IPAPI_FIELDS = 'status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query';

/**
 * Looks up geo / ASN for exact IPs (queried directly from the Runner, not through a node),
 * so the attribution always matches the reported exit IP. ip-api batch first, ipwho.is fallback.
 * Returns Map<ip, geo>.
 */
export async function geoLookup(ips, fetchFn = fetch) {
  const unique = [...new Set(ips)].filter(isPublicIp).slice(0, 100);
  const out = new Map();
  if (unique.length === 0) return out;

  try {
    const res = await fetchFn(`http://ip-api.com/batch?fields=${IPAPI_FIELDS}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(unique),
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) {
      const rows = await res.json();
      // Batch responses preserve request order; IPv6 `query` may come back re-formatted.
      unique.forEach((ip, i) => {
        const geo = normalizeIpApi(rows?.[i]);
        if (geo) out.set(ip, { ...geo, geo_source: 'ip-api' });
      });
    }
  } catch {
    // fall through to per-IP fallback
  }

  const missing = unique.filter((ip) => !out.has(ip)).slice(0, 30);
  await Promise.all(
    missing.map(async (ip) => {
      try {
        const res = await fetchFn(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(6000) });
        if (!res.ok) return;
        const geo = normalizeIpWhois(await res.json());
        if (geo) out.set(ip, { ...geo, geo_source: 'ipwho.is' });
      } catch {
        // geo is best-effort
      }
    }),
  );
  return out;
}
