/**
 * Pure helpers for turning raw probe observations (sing-box log lines, curl failures,
 * exit IPs, geo data) into the result records sent back to the Worker.
 * Nothing here touches the network or prints to stdout, so it is unit-testable.
 */
import net from 'node:net';

const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;

export function stripAnsi(text) {
  return String(text).replace(ANSI_RE, '');
}

/** Normalizes one sing-box log line: drops colors, uptime counters and connection ids. */
export function cleanCoreLine(line) {
  return stripAnsi(line)
    .replace(/^([A-Z]+)\[\d+\]\s*/, '$1 ')
    .replace(/\[\d+ [\d.]+(?:ns|µs|us|ms|s|m|h)\]\s*/g, '')
    .trim();
}

/** Keeps the last `max` non-empty log lines from a stream of stdout/stderr chunks. */
export function createLineBuffer(max = 60) {
  const lines = [];
  let partial = '';
  return {
    push(chunk) {
      const parts = (partial + String(chunk)).split(/\r?\n/);
      partial = parts.pop() ?? '';
      for (const p of parts) {
        const cleaned = cleanCoreLine(p);
        if (cleaned) lines.push(cleaned);
      }
      if (lines.length > max) lines.splice(0, lines.length - max);
    },
    lines() {
      const tail = cleanCoreLine(partial);
      return tail ? [...lines, tail].slice(-max) : [...lines];
    },
  };
}

/**
 * Lists node-identifying strings (credentials, server, SNI, paths, resolved entry IPs)
 * that must never appear in error details. Longest first so overlapping values redact fully.
 */
export function collectSensitive(outbound = {}, entryIps = []) {
  const out = [];
  const push = (value, label) => {
    for (const v of Array.isArray(value) ? value : [value]) {
      if (typeof v === 'string' && v.length >= 3) out.push([v, label]);
    }
  };
  push(outbound.password, '<secret>');
  push(outbound.uuid, '<secret>');
  push(outbound.obfs?.password, '<secret>');
  push(outbound.tls?.reality?.public_key, '<secret>');
  push(outbound.tls?.reality?.short_id, '<secret>');
  push(outbound.server, '<server>');
  push(outbound.tls?.server_name, '<sni>');
  push(outbound.transport?.headers?.Host, '<host>');
  push(outbound.transport?.host, '<host>');
  push(outbound.transport?.path, '<path>');
  push(outbound.transport?.service_name, '<path>');
  push(entryIps, '<server-ip>');
  return out.sort((a, b) => b[0].length - a[0].length);
}

export function redact(text, sensitive = []) {
  let s = String(text);
  for (const [value, label] of sensitive) s = s.split(value).join(label);
  return s;
}

export const HINTS = {
  core_spawn_failed: '代理内核无法启动（Runner 上缺少 sing-box）',
  chain_invalid: '前置节点（dialer-proxy）无效：找不到同名节点，或链路成环 / 超过 3 层',
  core_start_failed: '代理内核启动失败：节点参数无效或当前内核不支持',
  auth_failed: '认证失败：密码 / UUID 错误，或账号已到期',
  reality_failed: 'REALITY 校验失败：public-key / short-id / SNI 不匹配',
  ech_failed: 'ECH 失败：未能获取 ECH 配置，或配置无效',
  ech_rejected: 'ECH 被拒绝或 TLS 握手失败：ECH 配置可能已过期或与服务端不匹配',
  tls_error: 'TLS 握手失败：证书、SNI 或 ALPN 不匹配',
  handshake_timeout: 'QUIC 握手超时：节点无回应（可能屏蔽了 Runner 所在的境外机房 IP、端口不通或节点离线）',
  connection_refused: '连接被拒绝：入口端口未监听',
  network_unreachable: '网络不可达',
  runner_no_ipv6: 'GitHub Runner 没有 IPv6 出口，无法连接仅 IPv6 入口的节点（不代表节点不可用）',
  dns_failed: '入口域名解析失败',
  connect_timeout: '连接入口超时：入口不可达或被防火墙丢弃',
  connection_reset: '连接被重置：协议参数不匹配、被拦截或服务端主动断开',
  request_timeout: '探测请求超时：隧道可能已建立，但经节点访问探测站点超时',
  proxy_handshake_failed: '代理链路建立失败：内核无法连上节点，或节点拒绝转发',
  proxy_unavailable: '本地代理端口不可用（内核可能已退出）',
  remote_tls_failed: '经节点访问探测站点时 TLS 中断（常见于 UUID / 密码错误被服务端静默断开，或节点阻断了目标站点）',
  empty_reply: '节点返回空响应：协议参数可能不匹配',
  bad_response: '探测站点返回了无法识别的内容',
  probe_failed: '探测失败（原因未能识别）',
};

/** Ordered: the first rule matching the most recent error line wins. */
const CORE_RULES = [
  ['auth_failed', /authentication failed|auth(?:entication)? error|unauthorized|status code: 40[13]\b|invalid user|user not found/i],
  ['reality_failed', /(?<![\w.-])reality(?![\w.-])/i],
  // Case-sensitive and not part of a hostname, so "cloudflare-ech.com" in a cert error doesn't match.
  ['ech_failed', /(?<![\w.-])ECH(?![\w.-])|[Ee]ncrypted [Cc]lient [Hh]ello/],
  ['tls_error', /x509|certificate|tls: |handshake failure|bad record mac/i],
  ['handshake_timeout', /no recent network activity|handshake did not complete|idle timeout/i],
  ['connection_refused', /connection refused/i],
  ['network_unreachable', /network is unreachable|no route to host|address family not supported|cannot assign requested address/i],
  ['dns_failed', /no such host|server misbehaving|lookup .*(?:failed|timeout)/i],
  ['connect_timeout', /i\/o timeout|dial (?:tcp|udp).*timeout|context deadline exceeded|operation timed out/i],
  ['connection_reset', /connection reset|broken pipe|unexpected eof|\bEOF\b|forcibly closed/i],
];

const CURL_CODES = {
  7: 'proxy_unavailable',
  28: 'request_timeout',
  35: 'remote_tls_failed',
  52: 'empty_reply',
  56: 'connection_reset',
  97: 'proxy_handshake_failed',
};

const isErrorLine = (line) => /^(?:FATAL|ERROR|WARN)\b/.test(line);

/** Log lines that mention any of `hosts` (e.g. the probe endpoints of one IP family). */
export function linesMentioning(lines, hosts) {
  return lines.filter((l) => hosts.some((h) => l.includes(h)));
}

function onlyIpv6(ips = []) {
  return ips.length > 0 && ips.every((ip) => net.isIP(ip) === 6);
}

/**
 * Classifies a failure from sing-box error lines first (most specific), then curl exit codes.
 * Returns { code, hint, detail } where detail is already redacted.
 */
export function classifyFailure({ lines = [], attempts = [], echEnabled = false, entry, runnerIpv6, sensitive = [] }) {
  const errLines = lines.filter(isErrorLine);
  for (let i = errLines.length - 1; i >= 0; i--) {
    const rule = CORE_RULES.find(([, re]) => re.test(errLines[i]));
    if (!rule) continue;
    let code = rule[0];
    if (code === 'tls_error' && echEnabled) code = 'ech_rejected';
    if (
      ['network_unreachable', 'connect_timeout', 'handshake_timeout'].includes(code) &&
      runnerIpv6 === false &&
      onlyIpv6(entry?.ips)
    ) {
      code = 'runner_no_ipv6';
    }
    return { code, hint: HINTS[code], detail: truncate(redact(errLines[i], sensitive)) };
  }

  const failed = attempts.filter((a) => a && !a.ok);
  const last = failed[failed.length - 1];
  let code = (last && CURL_CODES[last.curlCode]) || (last?.badResponse ? 'bad_response' : 'probe_failed');
  if (runnerIpv6 === false && onlyIpv6(entry?.ips)) code = 'runner_no_ipv6';
  const detail = last?.message ? truncate(redact(last.message, sensitive)) : undefined;
  return { code, hint: HINTS[code], detail };
}

function truncate(s, max = 240) {
  const str = String(s);
  return str.length > max ? `${str.slice(0, max - 1)}…` : str;
}

export function parseCfTrace(text) {
  const map = {};
  for (const line of String(text).split(/\r?\n/)) {
    const eq = line.indexOf('=');
    if (eq > 0) map[line.slice(0, eq)] = line.slice(eq + 1).trim();
  }
  return map;
}

export function ipMatchesFamily(ip, family) {
  const fam = net.isIP(String(ip || ''));
  return family ? fam === family : fam > 0;
}

/** Excludes loopback / private / link-local / CGNAT / benchmark (fake-ip) / ULA ranges. */
export function isPublicIp(ip) {
  const fam = net.isIP(String(ip || ''));
  if (fam === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  if (fam === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return false;
    if (/^f[cd]/.test(lower) || /^fe[89ab]/.test(lower) || lower.startsWith('ff')) return false;
    if (lower.startsWith('::ffff:')) return isPublicIp(lower.slice(7));
    return true;
  }
  return false;
}

export function normalizeIpApi(r) {
  if (!r || r.status !== 'success') return null;
  return {
    country: r.country || undefined,
    country_code: r.countryCode || undefined,
    region: r.regionName || undefined,
    city: r.city || undefined,
    isp: r.isp || undefined,
    org: r.org || undefined,
    asn: r.as || undefined,
    hosting: typeof r.hosting === 'boolean' ? r.hosting : undefined,
    proxy: typeof r.proxy === 'boolean' ? r.proxy : undefined,
    mobile: typeof r.mobile === 'boolean' ? r.mobile : undefined,
  };
}

export function normalizeIpWhois(r) {
  if (!r || r.success === false) return null;
  const c = r.connection || {};
  return {
    country: r.country || undefined,
    country_code: r.country_code || undefined,
    region: r.region || undefined,
    city: r.city || undefined,
    isp: c.isp || undefined,
    org: c.org || undefined,
    asn: c.asn ? `AS${c.asn} ${c.org || c.isp || ''}`.trim() : undefined,
  };
}

export function asnNumber(asText) {
  const m = /^AS(\d+)/i.exec(String(asText || ''));
  return m ? Number(m[1]) : null;
}

// Cloudflare, Fastly, Akamai CDN, Gcore. Deliberately excludes cloud hosting ASNs such as Linode.
export const CDN_ASNS = new Set([13335, 209242, 54113, 20940, 16625, 21342, 199524]);

/**
 * Relationship between the node entry (what the client dials) and the observed exit IPs:
 * direct (an exit equals an entry IP), cdn (entry is a CDN edge), same_network (same ASN,
 * different IP) or relay (entry and exit are unrelated, i.e. transit / split egress).
 * `opts.cdn` marks an entry verified as a CDN edge by other means (e.g. Cloudflare BYOIP).
 */
export function classifyRelation(entryIps = [], entryGeos = [], exits = [], opts = {}) {
  const exitList = exits.filter((e) => e?.ip);
  if (exitList.length === 0 || entryIps.length === 0) return 'unknown';
  if (exitList.some((e) => entryIps.includes(e.ip))) return 'direct';
  const entryAsns = entryGeos.map((g) => asnNumber(g?.asn)).filter(Boolean);
  if (opts.cdn || entryAsns.some((a) => CDN_ASNS.has(a))) return 'cdn';
  const exitAsns = exitList.map((e) => asnNumber(e.asn)).filter(Boolean);
  if (entryAsns.length > 0 && exitAsns.some((a) => entryAsns.includes(a))) return 'same_network';
  if (entryAsns.length === 0 || exitAsns.length === 0) return 'unknown';
  return 'relay';
}

function isWarp(exit, geo) {
  if (exit?.warp === 'on' || exit?.warp === 'plus') return true;
  return asnNumber(geo?.asn) === 13335 && /warp/i.test(`${geo?.org || ''} ${geo?.isp || ''}`);
}

function exitRecord(probe, geoMap, entryIps) {
  if (!probe?.ok) return null;
  const geo = geoMap.get(probe.ip) || {};
  return {
    ip: probe.ip,
    ...geo,
    warp: isWarp(probe, geo) || undefined,
    same_as_entry: entryIps.includes(probe.ip),
    colo: probe.colo || undefined,
    source: probe.source,
  };
}

/**
 * Builds the final, redacted per-node result from raw observations.
 * `probe` = { index, name, type, outbound, entry, families: { ipv4, ipv6, dual }, coreLines,
 *             coreFailure, timings, latency_ms, ech }
 */
export function buildNodeResult(probe, geoMap = new Map(), ctx = {}) {
  const { outbound = {}, entry = { ips: [] }, families = {}, coreLines = [] } = probe;
  const entryIps = entry.ips || [];
  // Front proxies (dialer-proxy) carry credentials too; redact them as well.
  const sensitive = [outbound, ...(probe.chain || [])]
    .flatMap((ob, i) => collectSensitive(ob, i === 0 ? entryIps : []))
    .sort((a, b) => b[0].length - a[0].length);
  const echEnabled = Boolean(outbound.tls?.ech?.enabled);

  const base = {
    index: probe.index,
    name: probe.name,
    type: probe.type,
    via: probe.via || undefined,
    ech: probe.ech || undefined,
    latency_ms: probe.latency_ms,
    timings: probe.timings,
  };

  const entryGeos = entryIps.map((ip) => geoMap.get(ip)).filter(Boolean);
  const entryGeo = entryGeos[0] || {};
  const cfEdge = entryIps.some((ip) => ctx.cdnEdges?.has(ip));
  const entryInfo = {
    ips: entryIps,
    error: entry.error || undefined,
    country_code: entryGeo.country_code,
    isp: entryGeo.isp,
    asn: entryGeo.asn,
    cdn: entryGeos.some((g) => CDN_ASNS.has(asnNumber(g.asn))) || cfEdge || undefined,
    // Cloudflare edge reached via an IP whose ASN is not Cloudflare's ("优选" / BYOIP range).
    cdn_edge: cfEdge ? 'cloudflare' : undefined,
  };

  if (probe.coreFailure) {
    const lines = coreLines;
    const fatal = [...lines].reverse().find(isErrorLine);
    return {
      ...base,
      ok: false,
      entry: entryInfo,
      error_code: probe.coreFailure,
      error: HINTS[probe.coreFailure],
      detail: fatal ? truncate(redact(fatal, sensitive)) : probe.coreFailureDetail,
    };
  }

  const ipv4 = exitRecord(families.ipv4, geoMap, entryIps);
  const ipv6 = exitRecord(families.ipv6, geoMap, entryIps);
  const dual = exitRecord(families.dual, geoMap, entryIps);
  const ok = Boolean(ipv4 || ipv6 || dual);

  if (!ok) {
    const failure = classifyFailure({
      lines: coreLines,
      attempts: [families.ipv4, families.dual, families.ipv6].flatMap((f) => f?.attempts || []),
      echEnabled,
      entry,
      runnerIpv6: ctx.runnerIpv6,
      sensitive,
    });
    return { ...base, ok: false, entry: entryInfo, error_code: failure.code, error: failure.hint, detail: failure.detail };
  }

  const primary = dual || ipv4 || ipv6;
  const familyErrors = {};
  for (const [fam, hosts] of [
    ['ipv4', ctx.hosts?.ipv4 || []],
    ['ipv6', ctx.hosts?.ipv6 || []],
  ]) {
    const f = families[fam];
    if (f && !f.ok) {
      const failure = classifyFailure({
        lines: linesMentioning(coreLines, hosts),
        attempts: f.attempts || [],
        echEnabled,
        sensitive,
      });
      familyErrors[fam] = { code: failure.code, detail: failure.detail };
    }
  }

  return {
    ...base,
    ok: true,
    exit_ip: primary.ip,
    country: primary.country_code || primary.country,
    region: primary.region,
    city: primary.city,
    isp: primary.isp || primary.org,
    asn: primary.asn,
    ipv4,
    ipv6,
    preferred: dual ? (net.isIP(dual.ip) === 6 ? 'ipv6' : 'ipv4') : undefined,
    entry: entryInfo,
    relation: classifyRelation(entryIps, entryGeos, [ipv4, ipv6, dual], { cdn: cfEdge }),
    family_errors: Object.keys(familyErrors).length > 0 ? familyErrors : undefined,
  };
}

/** Public-log-safe summary: counts per error code only, never names, IPs or details. */
export function summarizeCodes(results = []) {
  const counts = {};
  for (const r of results) {
    if (!r.ok && r.error_code) counts[r.error_code] = (counts[r.error_code] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([k, v]) => `${k}:${v}`)
    .join(',');
}
