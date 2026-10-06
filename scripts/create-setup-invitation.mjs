import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const site = process.argv[2];
if (!site || !/^https:\/\//.test(site)) throw new Error('Usage: node scripts/create-setup-invitation.mjs https://YOUR-SITE.vercel.app');
const invitation = randomBytes(32).toString('base64url');
const directory = resolve('.veil-private');
mkdirSync(directory, { recursive: true });
const path = resolve(directory, 'setup-invitation.json');
writeFileSync(path, JSON.stringify({
  setupUrl: new URL('/#setup=' + invitation, site).href,
  setupHash: createHash('sha256').update(invitation).digest('hex'),
}, null, 2), { flag: 'wx', mode: 0o600 });
console.log('Private setup instructions saved to ' + path);
console.log('Set VEIL_SETUP_HASH from setupHash, then open setupUrl privately. This invitation is not your encryption key.');
