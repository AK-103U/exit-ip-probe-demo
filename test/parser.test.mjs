import test from 'node:test';
import assert from 'node:assert/strict';
import { dedent, echConfigToPem, parseEchOpts, parseNodesInput } from '../runner/parser.mjs';

test('parses Clash YAML single flow line for hysteria2 with port hopping', () => {
  const line =
    '- { name: 🇭🇰【亚洲】香港01丨直连, server: 198.51.100.1, port: 20000, ports: 20000-50000, mport: 20000-50000, udp: true, skip-cert-verify: true, sni: example.com, type: hysteria2, password: demo-pass }';

  const nodes = parseNodesInput(line);
  assert.equal(nodes.length, 1);
  assert.equal(nodes[0].name, '🇭🇰【亚洲】香港01丨直连');
  assert.equal(nodes[0].type, 'hysteria2');
  assert.deepEqual(nodes[0].outbound, {
    type: 'hysteria2',
    tag: 'proxy-0',
    server: '198.51.100.1',
    server_port: 20000,
    password: 'demo-pass',
    tls: {
      enabled: true,
      server_name: 'example.com',
      insecure: true,
    },
  });
});

test('parses hysteria2 Clash node without fixed port using server_ports range', () => {
  const line =
    '- { name: hop-only, server: 1.2.3.4, ports: 20000-50000, sni: example.com, type: hysteria2, password: p1 }';
  const nodes = parseNodesInput(line);
  assert.equal(nodes.length, 1);
  assert.equal(nodes[0].outbound.server_port, undefined);
  assert.deepEqual(nodes[0].outbound.server_ports, ['20000:50000']);
});

test('parses URI lines for hysteria2, vless reality, trojan, and ss', () => {
  const input = [
    'hysteria2://pass123@198.51.100.1:20000?sni=example.com&insecure=1#HK-HY2',
    'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=01ab&flow=xtls-rprx-vision#VLESS-R',
    'trojan://trpass@t.example.com:443?sni=t.example.com&type=ws&path=/ws#TR-WS',
    'ss://YWVzLTEyOC1nY206c3NwYXNz@s.example.com:8388#SS-Node',
  ].join('\n');

  const nodes = parseNodesInput(input);
  assert.equal(nodes.length, 4);
  assert.equal(nodes[0].outbound.type, 'hysteria2');
  assert.equal(nodes[0].outbound.password, 'pass123');
  assert.equal(nodes[1].outbound.type, 'vless');
  assert.equal(nodes[1].outbound.tls.reality.public_key, 'PUBKEY');
  assert.equal(nodes[2].outbound.type, 'trojan');
  assert.equal(nodes[2].outbound.transport.type, 'ws');
  assert.equal(nodes[3].outbound.type, 'shadowsocks');
  assert.equal(nodes[3].outbound.method, 'aes-128-gcm');
});

test('parses base64-encoded subscription text', () => {
  const raw = 'hysteria2://p1@1.1.1.1:443?sni=a.com#N1\ntrojan://p2@2.2.2.2:443#N2';
  const b64 = Buffer.from(raw, 'utf8').toString('base64');
  const nodes = parseNodesInput(b64);
  assert.equal(nodes.length, 2);
  assert.equal(nodes[0].name, 'N1');
  assert.equal(nodes[1].name, 'N2');
});

// ---------- indentation (pastes copied from under `proxies:` in a Clash config) ----------

const INDENTED_FLOW = [
  '    - { name: A, type: ss, server: 198.51.100.1, port: 8388, cipher: aes-128-gcm, password: p1 }',
  '    - { name: B, type: ss, server: 198.51.100.2, port: 8388, cipher: aes-128-gcm, password: p2 }',
  '    - { name: C, type: hysteria2, server: 198.51.100.3, port: 443, password: p3 }',
  '    ',
].join('\n');

test('parses indented flow-style Clash list as pasted', () => {
  const nodes = parseNodesInput(INDENTED_FLOW);
  assert.deepEqual(nodes.map((n) => n.name), ['A', 'B', 'C']);
});

test('parses indented Clash list whose first line indentation was already trimmed', () => {
  // Older clients / API callers apply trim(), leaving "- {A}\n    - {B}\n    - {C}".
  const nodes = parseNodesInput(INDENTED_FLOW.trim());
  assert.deepEqual(nodes.map((n) => n.name), ['A', 'B', 'C']);
});

test('parses indented block-style Clash items, trimmed or not', () => {
  const block = [
    '  - name: Blk1',
    '    type: trojan',
    '    server: t1.example.com',
    '    port: 443',
    '    password: tp1',
    '  - name: Blk2',
    '    type: trojan',
    '    server: t2.example.com',
    '    port: 443',
    '    password: tp2',
  ].join('\n');
  assert.deepEqual(parseNodesInput(block).map((n) => n.name), ['Blk1', 'Blk2']);
  assert.deepEqual(parseNodesInput(block.trim()).map((n) => n.name), ['Blk1', 'Blk2']);

  const single = '  - name: Solo\n    type: trojan\n    server: t.example.com\n    port: 443\n    password: tp';
  assert.deepEqual(parseNodesInput(single.trim()).map((n) => n.name), ['Solo']);
});

test('dedent removes only the common indentation', () => {
  assert.equal(dedent('    a\n      b\n\n    c'), 'a\n  b\n\nc');
  assert.equal(dedent('a\n  b'), 'a\n  b');
});

// ---------- ECH ----------

/** Builds a structurally valid ECHConfigList (draft-13, X25519, public_name = given). */
function fakeEchConfigList(publicName = 'cloudflare-ech.com') {
  const pn = Buffer.from(publicName);
  const contents = Buffer.concat([
    Buffer.from([0x42, 0x00, 0x20, 0x00, 0x20]),
    Buffer.alloc(32, 7),
    Buffer.from([0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, pn.length]),
    pn,
    Buffer.from([0x00, 0x00]),
  ]);
  const cfg = Buffer.concat([Buffer.from([0xfe, 0x0d, contents.length >> 8, contents.length & 0xff]), contents]);
  return Buffer.concat([Buffer.from([cfg.length >> 8, cfg.length & 0xff]), cfg]).toString('base64');
}

test('maps Clash ech-opts with query-server-name to sing-box tls.ech', () => {
  const line =
    '- { name: CF-WS, type: vless, server: cdn.example.com, port: 443, uuid: 11111111-1111-1111-1111-111111111111, tls: true, servername: a.example.com, client-fingerprint: firefox, ech-opts: { enable: true, query-server-name: cloudflare-ech.com }, network: ws, ws-opts: { path: /, headers: { Host: a.example.com } } }';
  const [node] = parseNodesInput(line);
  assert.deepEqual(node.outbound.tls.ech, { enabled: true, query_server_name: 'cloudflare-ech.com' });
  assert.equal(node.outbound.tls.utls.fingerprint, 'firefox');
});

test('converts inline base64 ech-opts.config to PEM lines and rejects garbage', () => {
  const b64 = fakeEchConfigList();
  const pem = echConfigToPem(b64);
  assert.deepEqual(pem, ['-----BEGIN ECH CONFIGS-----', b64, '-----END ECH CONFIGS-----']);
  assert.deepEqual(echConfigToPem(pem), pem);
  assert.equal(echConfigToPem('not-base64!'), undefined);
  assert.equal(echConfigToPem(Buffer.from('short-or-wrong-length').toString('base64')), undefined);

  assert.deepEqual(parseEchOpts({ enable: true, config: b64 }), { enabled: true, config: pem });
  assert.equal(parseEchOpts({ enable: false, 'query-server-name': 'cloudflare-ech.com' }), undefined);
  assert.equal(parseEchOpts(undefined), undefined);
});

test('REALITY nodes never get ECH even if ech-opts is present', () => {
  const line =
    '- { name: R, type: vless, server: r.example.com, port: 443, uuid: 11111111-1111-1111-1111-111111111111, tls: true, servername: www.apple.com, reality-opts: { public-key: PUBKEY, short-id: 01ab }, ech-opts: { enable: true, query-server-name: cloudflare-ech.com } }';
  const [node] = parseNodesInput(line);
  assert.equal(node.outbound.tls.reality.enabled, true);
  assert.equal(node.outbound.tls.ech, undefined);
});

test('supports ech= in share links (domain, Xray domain+DoH, and base64 config)', () => {
  const b64 = fakeEchConfigList();
  const input = [
    'vless://11111111-1111-1111-1111-111111111111@cdn.example.com:443?security=tls&sni=a.example.com&type=ws&path=%2F&ech=cloudflare-ech.com#V1',
    'trojan://pw@cdn.example.com:443?sni=a.example.com&ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#T1',
    `hysteria2://pw@h.example.com:443?sni=a.example.com&ech=${encodeURIComponent(b64)}#H1`,
  ].join('\n');
  const nodes = parseNodesInput(input);
  assert.deepEqual(nodes[0].outbound.tls.ech, { enabled: true, query_server_name: 'cloudflare-ech.com' });
  assert.deepEqual(nodes[1].outbound.tls.ech, { enabled: true, query_server_name: 'cloudflare-ech.com' });
  assert.deepEqual(nodes[2].outbound.tls.ech.config[1], b64);
});
