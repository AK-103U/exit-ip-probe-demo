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

/**
 * Parses Clash YAML (full config, proxy list, or flow object), URI lines,
 * or Base64 subscription text into normalized sing-box outbound entries.
 */
export function parseNodesInput(rawInput) {
  let text = String(rawInput || '').trim();
  if (!text) return [];

  // Try base64-encoded subscription body if it looks like a single opaque token
  if (!text.includes('://') && !text.includes(':') && !text.includes('{') && /^[A-Za-z0-9+/=_-]+$/.test(text)) {
    try {
      const decoded = decodeBase64Flexible(text).trim();
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

  let parsed;
  try {
    parsed = yaml.load(text);
  } catch {
    parsed = null;
  }

  let rawList = [];
  if (Array.isArray(parsed)) {
    rawList = parsed;
  } else if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.proxies)) {
      rawList = parsed.proxies;
    } else if (parsed.server && parsed.type) {
      rawList = [parsed];
    }
  }

  if (rawList.length > 0) {
    return rawList
      .slice(0, MAX_NODES_PER_TASK)
      .map((item, i) => clashProxyToSingBox(item, i))
      .filter(Boolean);
  }

  // Mixed lines fallback: pick any URI lines
  return lines
    .filter((l) => URI_PREFIX_RE.test(l))
    .slice(0, MAX_NODES_PER_TASK)
    .map((line, i) => uriToSingBox(line, i))
    .filter(Boolean);
}
