import yaml from 'js-yaml';
import { MAX_NODES_PER_TASK } from '../shared/validate.mjs';

function parseBool(v) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.toLowerCase() === 'true' || v === '1';
  return Boolean(v);
}

function parseMbps(v) {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.round(v);
  if (typeof v === 'string') {
    const m = v.match(/(\d+(?:\.\d+)?)/);
    if (m) return Math.round(Number(m[1]));
  }
  return undefined;
}

function formatServerPorts(raw) {
  if (!raw) return undefined;
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  const mapped = list
    .map((item) => String(item).trim().replace(/-/g, ':'))
    .filter(Boolean);
  return mapped.length > 0 ? mapped : undefined;
}

const ECH_PEM_BEGIN = '-----BEGIN ECH CONFIGS-----';
const ECH_PEM_END = '-----END ECH CONFIGS-----';
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;

/**
 * Converts an ECHConfigList (base64, as used by mihomo `ech-opts.config` / share links)
 * or an existing PEM block into the line array sing-box expects in `tls.ech.config`.
 * Returns undefined when the value is not a structurally valid ECHConfigList.
 */
export function echConfigToPem(raw) {
  if (raw == null || raw === '') return undefined;
  const text = Array.isArray(raw) ? raw.join('\n') : String(raw);
  if (text.includes(ECH_PEM_BEGIN)) {
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    return lines.includes(ECH_PEM_END) ? lines : undefined;
  }
  const compact = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact)) return undefined;
  const bytes = Buffer.from(compact.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  // ECHConfigList = uint16 length prefix || ECHConfig...
  if (bytes.length < 4 || bytes.readUInt16BE(0) !== bytes.length - 2) return undefined;
  return [ECH_PEM_BEGIN, bytes.toString('base64'), ECH_PEM_END];
}

/**
 * Maps Clash/mihomo `ech-opts: { enable, config, query-server-name }` to sing-box `tls.ech`.
 */
export function parseEchOpts(opts) {
  if (!opts || typeof opts !== 'object') return undefined;
  if (!parseBool(opts.enable ?? opts.enabled)) return undefined;
  const ech = { enabled: true };
  const pem = echConfigToPem(opts.config);
  if (pem) ech.config = pem;
  const qsn = String(opts['query-server-name'] ?? opts.query_server_name ?? '').trim();
  if (qsn && DOMAIN_RE.test(qsn)) ech.query_server_name = qsn;
  return ech;
}

/**
 * Share-link `ech=` parameter: either a base64 ECHConfigList, or a domain whose DNS HTTPS
 * record carries the config (Xray style `domain+https://doh/...` is accepted, DoH part ignored).
 */
function echFromUriParam(value) {
  if (!value) return undefined;
  const v = String(value).trim();
  if (echConfigToPem(v)) return { enable: true, config: v };
  const domain = v.split('+')[0].trim();
  if (DOMAIN_RE.test(domain)) return { enable: true, 'query-server-name': domain };
  return undefined;
}

function buildTls(opts = {}) {
  const enabled = opts.enabled ?? true;
  if (!enabled) return undefined;
  const tls = { enabled: true };
  if (opts.serverName) tls.server_name = String(opts.serverName);
  if (opts.insecure) tls.insecure = true;
  if (Array.isArray(opts.alpn) && opts.alpn.length > 0) {
    tls.alpn = opts.alpn.map(String);
  } else if (typeof opts.alpn === 'string' && opts.alpn.trim()) {
    tls.alpn = opts.alpn.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (opts.reality?.publicKey) {
    tls.reality = {
      enabled: true,
      public_key: String(opts.reality.publicKey),
      short_id: opts.reality.shortId ? String(opts.reality.shortId) : '',
    };
  } else if (opts.ech) {
    // REALITY and ECH are mutually exclusive; REALITY wins when both are present.
    tls.ech = opts.ech;
  }
  if (opts.utlsFingerprint) {
    tls.utls = { enabled: true, fingerprint: String(opts.utlsFingerprint) };
  }
  return tls;
}

function buildTransport(network, opts = {}) {
  if (!network || network === 'tcp' || network === 'raw') return undefined;
  if (network === 'ws') {
    const t = { type: 'ws' };
    if (opts.path) t.path = String(opts.path);
    if (opts.headers && typeof opts.headers === 'object') t.headers = opts.headers;
    else if (opts.host) t.headers = { Host: String(opts.host) };
    return t;
  }
  if (network === 'grpc') {
    return {
      type: 'grpc',
      service_name: String(opts.serviceName || ''),
    };
  }
  if (network === 'httpupgrade') {
    const t = { type: 'httpupgrade' };
    if (opts.path) t.path = String(opts.path);
    if (opts.host) t.host = String(opts.host);
    return t;
  }
  if (network === 'http' || network === 'h2') {
    const t = { type: 'http' };
    if (opts.path) t.path = String(opts.path);
    if (opts.host) t.host = Array.isArray(opts.host) ? opts.host : [String(opts.host)];
    return t;
  }
  return undefined;
}

function clashProxyToSingBox(proxy, idx) {
  if (!proxy || typeof proxy !== 'object') return null;
  const rawType = String(proxy.type || '').toLowerCase();
  const server = proxy.server ? String(proxy.server).trim() : '';
  const port = Number(proxy.port);
  const name = String(proxy.name || `${rawType || 'node'}-${idx + 1}`);
  const tag = `proxy-${idx}`;

  if (!server) return null;

  if (rawType === 'hysteria2' || rawType === 'hy2') {
    const out = {
      type: 'hysteria2',
      tag,
      server,
      password: String(proxy.password ?? proxy.auth ?? ''),
      tls: buildTls({
        enabled: true,
        serverName: proxy.sni || proxy.servername || server,
        insecure: parseBool(proxy['skip-cert-verify']),
        alpn: proxy.alpn,
        ech: parseEchOpts(proxy['ech-opts']),
      }),
    };
    if (Number.isInteger(port) && port > 0) {
      out.server_port = port;
    } else {
      const sp = formatServerPorts(proxy.ports || proxy.mport);
      if (!sp) return null;
      out.server_ports = sp;
    }
    if (proxy.obfs && String(proxy.obfs).toLowerCase() !== 'none') {
      out.obfs = {
        type: String(proxy.obfs),
        password: String(proxy['obfs-password'] || ''),
      };
    }
    const up = parseMbps(proxy.up);
    const down = parseMbps(proxy.down);
    if (up) out.up_mbps = up;
    if (down) out.down_mbps = down;
    return { name, type: 'hysteria2', outbound: out };
  }

  if (!Number.isInteger(port) || port <= 0) return null;

  if (rawType === 'trojan') {
    const wsOpts = proxy['ws-opts'] || {};
    const grpcOpts = proxy['grpc-opts'] || {};
    const out = {
      type: 'trojan',
      tag,
      server,
      server_port: port,
      password: String(proxy.password || ''),
      tls: buildTls({
        enabled: true,
        serverName: proxy.sni || proxy.servername || server,
        insecure: parseBool(proxy['skip-cert-verify']),
        alpn: proxy.alpn,
        ech: parseEchOpts(proxy['ech-opts']),
        utlsFingerprint: proxy['client-fingerprint'],
      }),
    };
    const transport = buildTransport(proxy.network, {
      path: wsOpts.path,
      headers: wsOpts.headers,
      serviceName: grpcOpts['grpc-service-name'],
    });
    if (transport) out.transport = transport;
    return { name, type: 'trojan', outbound: out };
  }

  if (rawType === 'vless') {
    const wsOpts = proxy['ws-opts'] || {};
    const grpcOpts = proxy['grpc-opts'] || {};
    const realityOpts = proxy['reality-opts'] || {};
    const tlsEnabled = proxy.tls === undefined ? Boolean(realityOpts['public-key']) : parseBool(proxy.tls);
    const out = {
      type: 'vless',
      tag,
      server,
      server_port: port,
      uuid: String(proxy.uuid || ''),
    };
    if (proxy.flow) out.flow = String(proxy.flow);
    if (tlsEnabled) {
      out.tls = buildTls({
        enabled: true,
        serverName: proxy.servername || proxy.sni || server,
        insecure: parseBool(proxy['skip-cert-verify']),
        alpn: proxy.alpn,
        ech: parseEchOpts(proxy['ech-opts']),
        utlsFingerprint: proxy['client-fingerprint'] || (realityOpts['public-key'] ? 'chrome' : undefined),
        reality: realityOpts['public-key']
          ? { publicKey: realityOpts['public-key'], shortId: realityOpts['short-id'] || '' }
          : undefined,
      });
    }
    const transport = buildTransport(proxy.network, {
      path: wsOpts.path,
      headers: wsOpts.headers,
      serviceName: grpcOpts['grpc-service-name'],
    });
    if (transport) out.transport = transport;
    return { name, type: 'vless', outbound: out };
  }

  if (rawType === 'vmess') {
    const wsOpts = proxy['ws-opts'] || {};
    const grpcOpts = proxy['grpc-opts'] || {};
    const out = {
      type: 'vmess',
      tag,
      server,
      server_port: port,
      uuid: String(proxy.uuid || ''),
      security: String(proxy.cipher || 'auto'),
      alter_id: Number(proxy.alterId || 0),
    };
    if (parseBool(proxy.tls)) {
      out.tls = buildTls({
        enabled: true,
        serverName: proxy.servername || proxy.sni || server,
        insecure: parseBool(proxy['skip-cert-verify']),
        alpn: proxy.alpn,
        ech: parseEchOpts(proxy['ech-opts']),
      });
    }
    const transport = buildTransport(proxy.network, {
      path: wsOpts.path,
      headers: wsOpts.headers,
      serviceName: grpcOpts['grpc-service-name'],
    });
    if (transport) out.transport = transport;
    return { name, type: 'vmess', outbound: out };
  }

  if (rawType === 'ss' || rawType === 'shadowsocks') {
    return {
      name,
      type: 'shadowsocks',
      outbound: {
        type: 'shadowsocks',
        tag,
        server,
        server_port: port,
        method: String(proxy.cipher || ''),
        password: String(proxy.password || ''),
      },
    };
  }

  if (rawType === 'tuic') {
    return {
      name,
      type: 'tuic',
      outbound: {
        type: 'tuic',
        tag,
        server,
        server_port: port,
        uuid: String(proxy.uuid || ''),
        password: String(proxy.password || ''),
        congestion_control: String(proxy['congestion-controller'] || 'bbr'),
        udp_relay_mode: String(proxy['udp-relay-mode'] || 'native'),
        tls: buildTls({
          enabled: true,
          serverName: proxy.sni || proxy.servername || server,
          insecure: parseBool(proxy['skip-cert-verify']),
          alpn: proxy.alpn || ['h3'],
          ech: parseEchOpts(proxy['ech-opts']),
        }),
      },
    };
  }

  return null;
}

function decodeBase64Flexible(str) {
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, 'base64').toString('utf8');
}

function uriToSingBox(line, idx) {
  const trimmed = line.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith('vmess://')) {
    try {
      const json = JSON.parse(decodeBase64Flexible(trimmed.slice(8)));
      return clashProxyToSingBox(
        {
          name: json.ps || `vmess-${idx + 1}`,
          type: 'vmess',
          server: json.add,
          port: Number(json.port),
          uuid: json.id,
          alterId: Number(json.aid || 0),
          cipher: json.scy || 'auto',
          network: json.net,
          tls: json.tls === 'tls',
          sni: json.sni || json.host,
          'ws-opts': json.net === 'ws' ? { path: json.path, headers: json.host ? { Host: json.host } : undefined } : undefined,
          'grpc-opts': json.net === 'grpc' ? { 'grpc-service-name': json.path } : undefined,
        },
        idx,
      );
    } catch {
      return null;
    }
  }

  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }

  const scheme = url.protocol.replace(':', '').toLowerCase();
  const name = decodeURIComponent(url.hash.replace(/^#/, '')) || `${scheme}-${idx + 1}`;
  const server = url.hostname;
  const port = Number(url.port);
  const q = url.searchParams;

  if (scheme === 'hysteria2' || scheme === 'hy2') {
    const auth = url.password
      ? `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`
      : decodeURIComponent(url.username);
    return clashProxyToSingBox(
      {
        name,
        type: 'hysteria2',
        server,
        port: port || undefined,
        ports: q.get('mport') || undefined,
        password: auth,
        sni: q.get('sni') || undefined,
        'skip-cert-verify': q.get('insecure') === '1' || q.get('insecure') === 'true',
        obfs: q.get('obfs') || undefined,
        'obfs-password': q.get('obfs-password') || undefined,
        alpn: q.get('alpn') || undefined,
        'ech-opts': echFromUriParam(q.get('ech')),
      },
      idx,
    );
  }

  if (scheme === 'trojan') {
    return clashProxyToSingBox(
      {
        name,
        type: 'trojan',
        server,
        port: port || 443,
        password: decodeURIComponent(url.username),
        sni: q.get('sni') || q.get('peer') || undefined,
        'skip-cert-verify': q.get('allowInsecure') === '1' || q.get('insecure') === '1',
        network: q.get('type') || 'tcp',
        'ws-opts': q.get('type') === 'ws' ? { path: q.get('path'), headers: q.get('host') ? { Host: q.get('host') } : undefined } : undefined,
        'grpc-opts': q.get('type') === 'grpc' ? { 'grpc-service-name': q.get('serviceName') } : undefined,
        alpn: q.get('alpn') || undefined,
        'ech-opts': echFromUriParam(q.get('ech')),
      },
      idx,
    );
  }

  if (scheme === 'vless') {
    const security = q.get('security') || '';
    const net = q.get('type') || 'tcp';
    return clashProxyToSingBox(
      {
        name,
        type: 'vless',
        server,
        port: port || 443,
        uuid: decodeURIComponent(url.username),
        flow: q.get('flow') || undefined,
        tls: security === 'tls' || security === 'reality',
        servername: q.get('sni') || undefined,
        'client-fingerprint': q.get('fp') || undefined,
        'skip-cert-verify': q.get('allowInsecure') === '1' || q.get('insecure') === '1',
        'reality-opts': security === 'reality' ? { 'public-key': q.get('pbk'), 'short-id': q.get('sid') || '' } : undefined,
        network: net,
        'ws-opts': net === 'ws' ? { path: q.get('path'), headers: q.get('host') ? { Host: q.get('host') } : undefined } : undefined,
        'grpc-opts': net === 'grpc' ? { 'grpc-service-name': q.get('serviceName') } : undefined,
        alpn: q.get('alpn') || undefined,
        'ech-opts': echFromUriParam(q.get('ech')),
      },
      idx,
    );
  }

  if (scheme === 'ss') {
    let method = '';
    let password = '';
    if (url.password) {
      method = decodeURIComponent(url.username);
      password = decodeURIComponent(url.password);
    } else {
      const decoded = decodeBase64Flexible(decodeURIComponent(url.username));
      const colonIdx = decoded.indexOf(':');
      if (colonIdx <= 0) return null;
      method = decoded.slice(0, colonIdx);
      password = decoded.slice(colonIdx + 1);
    }
    return clashProxyToSingBox({ name, type: 'ss', server, port, cipher: method, password }, idx);
  }

  if (scheme === 'tuic') {
    return clashProxyToSingBox(
      {
        name,
        type: 'tuic',
        server,
        port: port || 443,
        uuid: decodeURIComponent(url.username),
        password: decodeURIComponent(url.password),
        sni: q.get('sni') || undefined,
        'congestion-controller': q.get('congestion_control') || 'bbr',
        'udp-relay-mode': q.get('udp_relay_mode') || 'native',
        'skip-cert-verify': q.get('allow_insecure') === '1' || q.get('insecure') === '1',
        alpn: q.get('alpn') || 'h3',
      },
      idx,
    );
  }

  return null;
}

const URI_PREFIX_RE = /^(hysteria2|hy2|vless|vmess|trojan|ss|tuic):\/\//i;

const indentOf = (line) => line.match(/^[ \t]*/)[0].length;

/** Removes the common leading indentation of all non-blank lines (like Python textwrap.dedent). */
export function dedent(text) {
  const lines = String(text).split(/\r?\n/);
  const indents = lines.filter((l) => l.trim()).map(indentOf);
  const min = indents.length > 0 ? Math.min(...indents) : 0;
  if (min === 0) return lines.join('\n');
  return lines.map((l) => l.slice(Math.min(min, indentOf(l)))).join('\n');
}

/**
 * Candidate repairs for YAML whose first line lost its indentation because a caller applied
 * trim() to an indented paste (e.g. items copied from under `proxies:` in a Clash config).
 */
function firstLineIndentRepairs(text) {
  const lines = String(text).split(/\r?\n/);
  if (indentOf(lines[0]) !== 0 || !/^-\s/.test(lines[0])) return [];
  const rest = lines.slice(1).filter((l) => l.trim());
  if (rest.length === 0) return [];

  const targets = new Set();
  const siblingIndents = rest.filter((l) => /^[ \t]*-\s/.test(l)).map(indentOf);
  if (siblingIndents.length > 0) targets.add(Math.min(...siblingIndents));
  // Block-style single item: "- name: a" whose keys sit two columns deeper than the dash.
  targets.add(Math.min(...rest.map(indentOf)) - 2);

  return [...targets]
    .filter((n) => n > 0)
    .map((n) => dedent([' '.repeat(n) + lines[0], ...lines.slice(1)].join('\n')));
}

function yamlProxyList(text) {
  let parsed;
  try {
    parsed = yaml.load(text);
  } catch {
    return [];
  }
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.proxies)) return parsed.proxies;
    if (parsed.server && parsed.type) return [parsed];
  }
  return [];
}

function convertClashList(rawList) {
  return rawList
    .slice(0, MAX_NODES_PER_TASK)
    .map((item, i) => clashProxyToSingBox(item, i))
    .filter(Boolean);
}

/**
 * Parses Clash YAML (full config, proxy list, or flow object), URI lines,
 * or Base64 subscription text into normalized sing-box outbound entries.
 * Indented pastes are accepted, including ones whose first line was already trimmed.
 */
export function parseNodesInput(rawInput) {
  // Drop leading blank lines and trailing whitespace but keep the first line's indentation.
  let text = String(rawInput || '').replace(/^(?:[ \t]*\r?\n)+/, '').trimEnd();
  if (!text.trim()) return [];

  // Try base64-encoded subscription body if it looks like a single opaque token
  const compact = text.trim();
  if (!compact.includes('://') && !compact.includes(':') && !compact.includes('{') && /^[A-Za-z0-9+/=_-]+$/.test(compact)) {
    try {
      const decoded = decodeBase64Flexible(compact).trim();
      if (decoded.includes('://') || decoded.includes('proxies:')) {
        text = decoded;
      }
    } catch {
      // keep original
    }
  }

  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length > 0 && lines.every((l) => URI_PREFIX_RE.test(l))) {
    return lines
      .slice(0, MAX_NODES_PER_TASK)
      .map((line, i) => uriToSingBox(line, i))
      .filter(Boolean);
  }

  // Pick the YAML reading that yields the most usable nodes.
  let best = [];
  for (const candidate of [dedent(text), ...firstLineIndentRepairs(text)]) {
    const nodes = convertClashList(yamlProxyList(candidate));
    if (nodes.length > best.length) best = nodes;
  }
  if (best.length > 0) return best;

  // Mixed lines fallback: pick any URI lines
  return lines
    .filter((l) => URI_PREFIX_RE.test(l))
    .slice(0, MAX_NODES_PER_TASK)
    .map((line, i) => uriToSingBox(line, i))
    .filter(Boolean);
}
