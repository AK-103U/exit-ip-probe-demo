import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { aesEncrypt, aesDecrypt, hmacSign, hmacVerify, timingSafeEqualStr } from '../shared/crypto.mjs';

test('AES-256-GCM encrypts and decrypts UTF-8 payloads', async () => {
  const key = randomBytes(32).toString('base64');
  const payload = JSON.stringify({
    task_id: '11111111-1111-4111-8111-111111111111',
    raw_input: '🇭🇰【亚洲】香港01丨直连 password=fake-password-for-test',
  });

  const cipher1 = await aesEncrypt(payload, key);
  const cipher2 = await aesEncrypt(payload, key);

  assert.notEqual(cipher1, cipher2, 'Random IV must produce distinct ciphertexts');
  assert.equal(await aesDecrypt(cipher1, key), payload);
  assert.equal(await aesDecrypt(cipher2, key), payload);
});

test('AES-256-GCM rejects tampered ciphertext or wrong key', async () => {
  const key1 = randomBytes(32).toString('base64');
  const key2 = randomBytes(32).toString('base64');
  const cipher = await aesEncrypt('secret', key1);

  await assert.rejects(() => aesDecrypt(cipher, key2));

  const buf = Buffer.from(cipher, 'base64');
  buf[buf.length - 1] ^= 0xff;
  await assert.rejects(() => aesDecrypt(buf.toString('base64'), key1));
});

test('HMAC-SHA256 signs and verifies callback payloads with skew check', async () => {
  const secret = 'test-callback-secret';
  const body = JSON.stringify({ ok: true });
  const nowSec = Math.floor(Date.now() / 1000);

  const sig = await hmacSign(secret, String(nowSec), body);
  assert.equal(await hmacVerify(secret, String(nowSec), body, sig), true);
  assert.equal(await hmacVerify(secret, String(nowSec), `${body} `, sig), false);
  assert.equal(await hmacVerify('wrong', String(nowSec), body, sig), false);

  const staleTs = String(nowSec - 600);
  const staleSig = await hmacSign(secret, staleTs, body);
  assert.equal(await hmacVerify(secret, staleTs, body, staleSig, 300), false);
});

test('timingSafeEqualStr compares strings accurately', async () => {
  assert.equal(await timingSafeEqualStr('abc123', 'abc123'), true);
  assert.equal(await timingSafeEqualStr('abc123', 'abc124'), false);
  assert.equal(await timingSafeEqualStr('abc123', 'abc1234'), false);
});
