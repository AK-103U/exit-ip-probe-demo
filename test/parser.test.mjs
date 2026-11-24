import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNodesInput } from '../runner/parser.mjs';

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
