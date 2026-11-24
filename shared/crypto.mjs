/**
 * Web Crypto helpers shared between Cloudflare Worker and Node.js (>=20) Runner.
 * Uses AES-256-GCM for payload confidentiality and HMAC-SHA256 for callback auth.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return null;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function importAesKey(base64Key, usage) {
  const raw = base64ToBytes(base64Key);
  if (raw.byteLength !== 32) {
    throw new Error('AES_KEY must decode to exactly 32 bytes (256 bits)');
  }
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [usage]);
}

/**
 * Encrypts a UTF-8 string with AES-256-GCM.
 * Output format: base64(12-byte IV || ciphertext+tag)
 */
export async function aesEncrypt(plaintext, base64Key) {
  const key = await importAesKey(base64Key, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = textEncoder.encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const cipherBytes = new Uint8Array(cipherBuf);
  const combined = new Uint8Array(iv.byteLength + cipherBytes.byteLength);
  combined.set(iv, 0);
  combined.set(cipherBytes, iv.byteLength);
  return bytesToBase64(combined);
}

/**
 * Decrypts a base64(IV || ciphertext+tag) payload with AES-256-GCM.
 */
export async function aesDecrypt(b64Payload, base64Key) {
  const combined = base64ToBytes(b64Payload);
  if (combined.byteLength <= 12) {
    throw new Error('Invalid encrypted payload');
  }
  const iv = combined.subarray(0, 12);
  const cipherBytes = combined.subarray(12);
  const key = await importAesKey(base64Key, 'decrypt');
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBytes);
  return textDecoder.decode(plainBuf);
}

async function importHmacKey(secret, usage) {
  return crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    [usage],
  );
}

/**
 * Computes HMAC-SHA256 hex signature over `${timestamp}.${body}`.
 */
export async function hmacSign(secret, timestamp, body) {
  const key = await importHmacKey(secret, 'sign');
  const data = textEncoder.encode(`${timestamp}.${body}`);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return bytesToHex(new Uint8Array(sig));
}

/**
 * Verifies timestamp freshness and HMAC-SHA256 hex signature.
 */
export async function hmacVerify(secret, timestamp, body, signatureHex, maxSkewSec = 300) {
  if (!secret || !timestamp || !signatureHex) return false;
  const tsNum = Number(timestamp);
  if (!Number.isFinite(tsNum)) return false;
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - tsNum) > maxSkewSec) return false;

  const sigBytes = hexToBytes(signatureHex);
  if (!sigBytes) return false;

  const key = await importHmacKey(secret, 'verify');
  const data = textEncoder.encode(`${timestamp}.${body}`);
  return crypto.subtle.verify('HMAC', key, sigBytes, data);
}

/**
 * Constant-time string equality check via SHA-256 digest comparison.
 */
export async function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', textEncoder.encode(a)),
    crypto.subtle.digest('SHA-256', textEncoder.encode(b)),
  ]);
  const ba = new Uint8Array(ha);
  const bb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < ba.length; i++) {
    diff |= ba[i] ^ bb[i];
  }
  return diff === 0 && a.length === b.length;
}
