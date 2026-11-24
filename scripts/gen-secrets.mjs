import { randomBytes } from 'node:crypto';

const secrets = {
  AES_KEY: randomBytes(32).toString('base64'),
  API_TOKEN: randomBytes(24).toString('base64url'),
  PULL_TOKEN: randomBytes(24).toString('base64url'),
  CALLBACK_SECRET: randomBytes(32).toString('hex'),
};

console.log('# Generated secrets for Worker & GitHub Actions');
console.log('# ------------------------------------------------');
for (const [k, v] of Object.entries(secrets)) {
  console.log(`${k}=${v}`);
}
