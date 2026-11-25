import test from 'node:test';
import assert from 'node:assert/strict';
import { echFromDohAnswer, geoLookup, prepareEch } from '../runner/netinfo.mjs';

function echB64() {
  const pn = Buffer.from('cloudflare-ech.com');
  const contents = Buffer.concat([
    Buffer.from([0x42, 0x00, 0x20, 0x00, 0x20]),
    Buffer.alloc(32, 9),
    Buffer.from([0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, pn.length]),
    pn,
    Buffer.from([0x00, 0x00]),
  ]);
  const cfg = Buffer.concat([Buffer.from([0xfe, 0x0d, contents.length >> 8, contents.length & 0xff]), contents]);
  return Buffer.concat([Buffer.from([cfg.length >> 8, cfg.length & 0xff]), cfg]).toString('base64');
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

test('echFromDohAnswer extracts the ech SvcParam from an HTTPS record', () => {
  const b64 = echB64();
  const pem = echFromDohAnswer({
    Answer: [
      { type: 5, data: 'alias.example.' },
      { type: 65, data: `1 . alpn=h3,h2 ipv4hint=104.18.10.118 ech=${b64} ipv6hint=2606:4700::1` },
    ],
  });
  assert.deepEqual(pem, ['-----BEGIN ECH CONFIGS-----', b64, '-----END ECH CONFIGS-----']);
  assert.equal(echFromDohAnswer({ Answer: [{ type: 65, data: '1 . alpn=h2' }] }), null);
  assert.equal(echFromDohAnswer({}), null);
});

test('prepareEch embeds DoH-fetched configs once per name and falls back to sing-box DNS', async () => {
  const b64 = echB64();
  const calls = [];
  const fetchFn = async (url) => {
    calls.push(url);
    if (url.includes('name=cloudflare-ech.com')) return jsonResponse({ Answer: [{ type: 65, data: `1 . ech=${b64}` }] });
    return jsonResponse({ Answer: [] });
  };
  const mk = (ech) => ({ outbound: { server: 's.example.com', tls: { enabled: true, server_name: 'a.example.com', ech } } });
  const nodes = [
    mk({ enabled: true, query_server_name: 'cloudflare-ech.com' }),
    mk({ enabled: true, query_server_name: 'cloudflare-ech.com' }),
    mk({ enabled: true, config: ['-----BEGIN ECH CONFIGS-----', b64, '-----END ECH CONFIGS-----'] }),
    mk({ enabled: true, query_server_name: 'no-ech.example.com' }),
    { outbound: { server: 'plain.example.com', tls: { enabled: true } } },
  ];

  await prepareEch(nodes, fetchFn);

  assert.deepEqual(nodes.map((n) => n.ech), ['doh', 'doh', 'inline', 'dns', undefined]);
  assert.deepEqual(nodes[0].outbound.tls.ech, { enabled: true, config: ['-----BEGIN ECH CONFIGS-----', b64, '-----END ECH CONFIGS-----'] });
  assert.equal(nodes[3].outbound.tls.ech.query_server_name, 'no-ech.example.com');
  assert.equal(calls.filter((u) => u.includes('name=cloudflare-ech.com')).length, 1, 'DoH result is cached per name');
});

test('geoLookup maps ip-api batch rows by request order and falls back to ipwho.is', async () => {
  const requests = [];
  const fetchFn = async (url, init) => {
    requests.push({ url, body: init?.body });
    if (url.startsWith('http://ip-api.com/batch')) {
      return jsonResponse([
        { status: 'success', query: '198.51.100.26', countryCode: 'AE', city: 'Dubai', isp: 'Oracle Corporation', as: 'AS31898 Oracle Corporation', hosting: true },
        // IPv6 query echoed back in a different textual form; must still map by position.
        { status: 'success', query: '2001:db8:860:0::1', countryCode: 'AU', isp: 'Cloudflare, Inc.', org: 'Cloudflare WARP', as: 'AS13335 Cloudflare, Inc.' },
        { status: 'fail', message: 'reserved range', query: '9.9.9.9' },
      ]);
    }
    if (url === 'https://ipwho.is/9.9.9.9') {
      return jsonResponse({ success: true, country_code: 'US', city: 'Berkeley', connection: { asn: 19281, org: 'Quad9', isp: 'Quad9' } });
    }
    return jsonResponse({}, 404);
  };

  const map = await geoLookup(['198.51.100.26', '2001:db8:860::1', '9.9.9.9', '10.0.0.1', '198.51.100.26'], fetchFn);

  assert.deepEqual(JSON.parse(requests[0].body), ['198.51.100.26', '2001:db8:860::1', '9.9.9.9']);
  assert.equal(map.get('198.51.100.26').hosting, true);
  assert.equal(map.get('198.51.100.26').geo_source, 'ip-api');
  assert.equal(map.get('2001:db8:860::1').org, 'Cloudflare WARP');
  assert.equal(map.get('9.9.9.9').asn, 'AS19281 Quad9');
  assert.equal(map.get('9.9.9.9').geo_source, 'ipwho.is');
  assert.equal(map.has('10.0.0.1'), false);
});
