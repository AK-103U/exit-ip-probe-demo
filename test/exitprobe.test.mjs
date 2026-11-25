import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFamilySpecs, IPPURE_URL, parseTierResponse, probeFamily } from '../runner/exitprobe.mjs';

const IPPURE_BODY = JSON.stringify({
  ip: '198.51.100.7',
  asn: 979,
  asOrganization: 'Example Net',
  country: 'Hong Kong',
  countryCode: 'HK',
  region: 'Hong Kong',
  city: 'Hong Kong',
  timezone: 'Asia/Hong_Kong',
  fraudScore: 12,
  isResidential: true,
  isBroadcast: false,
});

test('buildFamilySpecs pins ippure to the resolved A / AAAA address per family', () => {
  const specs = buildFamilySpecs({ v4: '203.0.113.4', v6: '2001:db8::4' });
  assert.deepEqual(specs.ipv4.tiers.map((t) => t.kind), ['ippure', 'cf-trace', 'ipify']);
  assert.equal(specs.ipv4.tiers[0].connectTo, 'my.ippure.com:443:203.0.113.4:443');
  assert.equal(specs.ipv6.tiers[0].connectTo, 'my.ippure.com:443:[2001:db8::4]:443');
  assert.equal(specs.dual.tiers[0].url, IPPURE_URL);
  assert.equal(specs.dual.tiers[0].connectTo, undefined, 'dual-stack lets the node choose');
  assert.ok(specs.ipv4.hosts.includes('203.0.113.4'));
  assert.ok(specs.ipv6.hosts.includes('2001:db8::4'));

  const noV6 = buildFamilySpecs({ v4: '203.0.113.4' });
  assert.deepEqual(noV6.ipv6.tiers.map((t) => t.kind), ['cf-trace', 'ipify'], 'no AAAA → skip ippure for IPv6');
});

test('parseTierResponse normalizes ippure, Cloudflare trace and ipify bodies', () => {
  const pure = parseTierResponse('ippure', IPPURE_BODY);
  assert.equal(pure.ip, '198.51.100.7');
  assert.equal(pure.geo.asn, 'AS979 Example Net');
  assert.equal(pure.geo.fraud_score, 12);
  assert.equal(pure.geo.residential, true);
  assert.equal(pure.geo.broadcast, false);

  assert.deepEqual(parseTierResponse('cf-trace', 'fl=1\nip=203.0.113.9\ncolo=HKG\nwarp=off\n'), {
    ip: '203.0.113.9',
    colo: 'HKG',
    warp: 'off',
  });
  assert.deepEqual(parseTierResponse('ipify', '{"ip":"203.0.113.10"}'), { ip: '203.0.113.10' });
});

test('probeFamily uses ippure first and passes --connect-to through', async () => {
  const calls = [];
  const curl = async (url, opts) => {
    calls.push({ url, ...opts });
    return { ok: true, body: IPPURE_BODY };
  };
  const res = await probeFamily(buildFamilySpecs({ v4: '203.0.113.4' }).ipv4, curl);
  assert.equal(res.ok, true);
  assert.equal(res.source, 'ippure');
  assert.equal(res.geo.country_code, 'HK');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].connectTo, 'my.ippure.com:443:203.0.113.4:443');
});

test('probeFamily falls back to Cloudflare trace and rejects wrong-family answers', async () => {
  const spec = buildFamilySpecs({ v4: '203.0.113.4', v6: '2001:db8::4' }).ipv6;
  const curl = async (url) => {
    if (url === IPPURE_URL) return { ok: true, body: IPPURE_BODY }; // IPv4 answer on the IPv6 probe
    if (url.includes('cdn-cgi/trace')) return { ok: true, body: 'ip=2001:db8::99\ncolo=SIN\n' };
    return { ok: false, curlCode: 28 };
  };
  const res = await probeFamily(spec, curl);
  assert.equal(res.ok, true);
  assert.equal(res.source, 'cf-trace');
  assert.equal(res.ip, '2001:db8::99');
  assert.equal(res.colo, 'SIN');
});

test('probeFamily stops after two SOCKS-level failures instead of trying every endpoint', async () => {
  const urls = [];
  const curl = async (url) => {
    urls.push(url);
    return { ok: false, curlCode: 97, message: 'curl: (97) cannot complete SOCKS5 connection' };
  };
  const res = await probeFamily(buildFamilySpecs({ v4: '203.0.113.4' }).ipv4, curl);
  assert.equal(res.ok, false);
  assert.equal(urls.length, 2);
  assert.deepEqual(res.attempts.map((a) => a.source), ['ippure', 'cf-trace']);

  // Other failure kinds still walk all tiers.
  const urls2 = [];
  const res2 = await probeFamily(buildFamilySpecs({ v4: '203.0.113.4' }).ipv4, async (url) => {
    urls2.push(url);
    return { ok: false, curlCode: 28 };
  });
  assert.equal(res2.ok, false);
  assert.equal(urls2.length, 3);
});
