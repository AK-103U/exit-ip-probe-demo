import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildNodeResult,
  classifyFailure,
  classifyRelation,
  cleanCoreLine,
  collectSensitive,
  createLineBuffer,
  isPublicIp,
  redact,
  summarizeCodes,
} from '../runner/diagnostics.mjs';

const OUTBOUND = {
  type: 'hysteria2',
  server: 'node.example.com',
  server_port: 443,
  password: 'TOP-SECRET-PASS',
  tls: { enabled: true, server_name: 'sni.example.com', insecure: true },
};

test('cleanCoreLine strips ANSI colors, uptime counters and connection ids', () => {
  const raw = '\x1b[31mERROR\x1b[0m[0006] [1502156949 5.0s] connection: open connection to www.cloudflare.com:443 using outbound/hysteria2[proxy-0]: timeout: no recent network activity';
  assert.equal(
    cleanCoreLine(raw),
    'ERROR connection: open connection to www.cloudflare.com:443 using outbound/hysteria2[proxy-0]: timeout: no recent network activity',
  );
});

test('createLineBuffer reassembles chunked output and keeps only the tail', () => {
  const buf = createLineBuffer(2);
  buf.push('ERROR one\nERR');
  buf.push('OR two\nERROR three');
  assert.deepEqual(buf.lines(), ['ERROR two', 'ERROR three']);
});

test('redact removes credentials, server, SNI and entry IPs from details', () => {
  const sensitive = collectSensitive(OUTBOUND, ['203.0.113.9']);
  const out = redact('dial udp 203.0.113.9:443 node.example.com sni.example.com auth TOP-SECRET-PASS', sensitive);
  assert.equal(out, 'dial udp <server-ip>:443 <server> <sni> auth <secret>');
});

test('classifyFailure maps sing-box errors to stable codes, newest error line first', () => {
  const sensitive = collectSensitive(OUTBOUND);
  const cases = [
    ['ERROR connection: open connection to 1.1.1.1:443 using outbound/hysteria2[proxy-0]: timeout: no recent network activity', 'handshake_timeout'],
    ['ERROR connection: open connection to 1.1.1.1:443 using outbound/hysteria2[proxy-0]: authentication failed, status code: 404', 'auth_failed'],
    ['ERROR connection: connection download closed: cipher: message authentication failed', 'auth_failed'],
    ['ERROR connection: open connection: tls: failed to verify certificate: x509: certificate is valid for a, not b', 'tls_error'],
    ['ERROR connection: open connection: no ECH config found in DNS records', 'ech_failed'],
    ['ERROR connection: dial tcp 203.0.113.9:443: connect: connection refused', 'connection_refused'],
    ['ERROR connection: dial tcp 203.0.113.9:443: i/o timeout', 'connect_timeout'],
    ['ERROR connection: connection download closed: unexpected EOF', 'connection_reset'],
  ];
  for (const [line, code] of cases) {
    assert.equal(classifyFailure({ lines: ['INFO started', line], sensitive }).code, code, line);
  }

  const latest = classifyFailure({
    lines: ['ERROR x: connection refused', 'ERROR y: timeout: no recent network activity'],
  });
  assert.equal(latest.code, 'handshake_timeout');
  assert.match(latest.hint, /握手超时/);
});

test('classifyFailure: ECH TLS errors, IPv6-only entries and curl fallbacks', () => {
  const tlsLine = 'ERROR open connection: tls: failed to verify certificate: x509: certificate is valid for cloudflare-ech.com';
  assert.equal(classifyFailure({ lines: [tlsLine], echEnabled: true }).code, 'ech_rejected');

  const unreachable = 'ERROR open connection: dial udp [2001:db8::1]:44001: connect: network is unreachable';
  assert.equal(
    classifyFailure({ lines: [unreachable], entry: { ips: ['2001:db8::1'] }, runnerIpv6: false }).code,
    'runner_no_ipv6',
  );
  assert.equal(classifyFailure({ lines: [unreachable], entry: { ips: ['2001:db8::1'] }, runnerIpv6: true }).code, 'network_unreachable');

  const curl = classifyFailure({ attempts: [{ ok: false, curlCode: 97, message: 'curl: (97) cannot complete SOCKS5 connection to 1.1.1.1. (1)' }] });
  assert.equal(curl.code, 'proxy_handshake_failed');
  assert.equal(curl.detail, 'curl: (97) cannot complete SOCKS5 connection to 1.1.1.1. (1)');
  assert.equal(classifyFailure({ attempts: [{ ok: false, curlCode: 28 }] }).code, 'request_timeout');
  assert.equal(classifyFailure({}).code, 'probe_failed');
});

test('isPublicIp filters private, loopback, CGNAT, fake-ip and ULA ranges', () => {
  for (const ip of ['8.8.8.8', '198.51.100.26', '2001:db8:bac1::1', '2606:4700:4700::1111']) assert.equal(isPublicIp(ip), true, ip);
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '100.64.0.1', '198.18.2.19', '169.254.1.1', '::1', 'fd00::1', 'fe80::1', 'nope'])
    assert.equal(isPublicIp(ip), false, ip);
});

test('classifyRelation distinguishes direct, cdn, same_network, relay and unknown', () => {
  const cf = { asn: 'AS13335 Cloudflare, Inc.' };
  const oracle = { asn: 'AS31898 Oracle Corporation' };
  const doc = { asn: 'AS14061 DigitalOcean, LLC' };
  assert.equal(classifyRelation(['1.2.3.4'], [doc], [{ ip: '1.2.3.4', ...doc }]), 'direct');
  assert.equal(classifyRelation(['104.16.0.1'], [cf], [{ ip: '198.51.100.103', asn: 'AS214677 X' }]), 'cdn');
  assert.equal(classifyRelation(['1.2.3.4'], [oracle], [{ ip: '1.2.3.5', ...oracle }]), 'same_network');
  assert.equal(classifyRelation(['1.2.3.4'], [doc], [{ ip: '5.6.7.8', ...oracle }]), 'relay');
  assert.equal(classifyRelation([], [], [{ ip: '5.6.7.8' }]), 'unknown');
  assert.equal(classifyRelation(['198.18.0.1'], [], [{ ip: '5.6.7.8', ...oracle }]), 'unknown');
});

test('buildNodeResult attributes geo to the exact exit IP per family and flags WARP', () => {
  const geo = new Map([
    ['203.0.113.119', { country_code: 'AU', city: 'Sydney', isp: 'Oracle Corporation', asn: 'AS31898 Oracle Corporation', hosting: true }],
    ['2001:db8:860::1', { country_code: 'AU', city: 'Sydney', isp: 'Cloudflare, Inc.', org: 'Cloudflare WARP', asn: 'AS13335 Cloudflare, Inc.', hosting: false }],
    ['203.0.113.100', { asn: 'AS31898 Oracle Corporation' }],
  ]);
  const result = buildNodeResult(
    {
      index: 0,
      name: 'SYD',
      type: 'hysteria2',
      outbound: OUTBOUND,
      entry: { ips: ['203.0.113.100'] },
      families: {
        ipv4: { ok: true, ip: '203.0.113.119', source: 'cf-trace', ms: 900 },
        ipv6: { ok: true, ip: '2001:db8:860::1', warp: 'on', colo: 'SYD', source: 'cf-trace', ms: 950 },
        dual: { ok: true, ip: '2001:db8:860::1', source: 'cf-trace', ms: 940 },
      },
      coreLines: [],
      latency_ms: 1000,
      timings: { core_ready_ms: 40 },
    },
    geo,
  );

  assert.equal(result.ok, true);
  assert.equal(result.ipv4.isp, 'Oracle Corporation');
  assert.equal(result.ipv4.hosting, true);
  assert.equal(result.ipv4.warp, undefined);
  assert.equal(result.ipv6.warp, true);
  assert.equal(result.preferred, 'ipv6');
  assert.equal(result.exit_ip, '2001:db8:860::1');
  assert.equal(result.isp, 'Cloudflare, Inc.');
  assert.equal(result.relation, 'same_network');
});

test('buildNodeResult reports partial IPv6 failure without failing the node, and redacts details', () => {
  const coreLines = [
    'ERROR connection: open connection to [2606:4700:4700::1111]:443 using outbound/hysteria2[proxy-0]: dial tcp: network is unreachable',
  ];
  const result = buildNodeResult(
    {
      index: 1,
      name: 'V4ONLY',
      type: 'hysteria2',
      outbound: OUTBOUND,
      entry: { ips: ['203.0.113.9'] },
      families: {
        ipv4: { ok: true, ip: '203.0.113.9', source: 'cf-trace' },
        ipv6: { ok: false, attempts: [{ ok: false, curlCode: 97, message: 'curl: (97) x' }] },
        dual: { ok: true, ip: '203.0.113.9', source: 'cf-trace' },
      },
      coreLines,
    },
    new Map(),
    { hosts: { ipv4: ['1.1.1.1'], ipv6: ['2606:4700:4700::1111'] } },
  );
  assert.equal(result.ok, true);
  assert.equal(result.relation, 'direct');
  assert.equal(result.ipv6, null);
  assert.equal(result.family_errors.ipv6.code, 'network_unreachable');

  const failed = buildNodeResult(
    {
      index: 2,
      name: 'DEAD',
      type: 'hysteria2',
      outbound: OUTBOUND,
      entry: { ips: ['203.0.113.9'] },
      families: { ipv4: { ok: false, attempts: [] }, ipv6: { ok: false, attempts: [] }, dual: { ok: false, attempts: [] } },
      coreLines: ['ERROR connection: dial udp 203.0.113.9:443 (node.example.com) TOP-SECRET-PASS: timeout: no recent network activity'],
    },
    new Map(),
  );
  assert.equal(failed.ok, false);
  assert.equal(failed.error_code, 'handshake_timeout');
  assert.equal(failed.detail.includes('TOP-SECRET-PASS'), false);
  assert.equal(failed.detail.includes('node.example.com'), false);
  assert.equal(failed.detail.includes('203.0.113.9'), false);
});

test('buildNodeResult surfaces core start failures with the redacted fatal line', () => {
  const result = buildNodeResult({
    index: 0,
    name: 'BAD',
    type: 'vless',
    outbound: OUTBOUND,
    entry: { ips: [] },
    coreFailure: 'core_start_failed',
    coreLines: ['FATAL decode config: outbounds[0].server: node.example.com invalid'],
  });
  assert.equal(result.ok, false);
  assert.equal(result.error_code, 'core_start_failed');
  assert.equal(result.detail, 'FATAL decode config: outbounds[0].server: <server> invalid');
});

test('summarizeCodes only exposes error-code counts', () => {
  assert.equal(
    summarizeCodes([{ ok: true }, { ok: false, error_code: 'handshake_timeout' }, { ok: false, error_code: 'handshake_timeout' }, { ok: false, error_code: 'runner_no_ipv6' }]),
    'handshake_timeout:2,runner_no_ipv6:1',
  );
});
