import assert from 'node:assert/strict';
import { derive, seal, unseal, toBase64 } from '../lib/veil-crypto.ts';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
const root = resolve('dist/server');
const files = readdirSync(root, { recursive: true }).filter(name => /\.(m?js)$/.test(name) && name !== 'index.js');
const runtime = new Miniflare({
  name: 'veil-api-test', host: '127.0.0.1', port: 0,
  modules: ['index.js', ...files].map(name => ({ type: 'ESModule', path: resolve(root, name) })),
  modulesRoot: root, compatibilityDate: '2026-05-15', compatibilityFlags: ['nodejs_compat'],
  d1Databases: { DB: 'veil-api-test' }, d1Persist: false,
  bindings: { VEIL_SETUP_HASH: createHash('sha256').update('LOCAL-TEST-INVITATION').digest('hex') },
  cf: false, log: new Log(LogLevel.ERROR),
});
try {
  const testDb = await runtime.getD1Database('DB');
  await testDb.exec(readFileSync(resolve('drizzle/0000_gray_madame_masque.sql'), 'utf8').replaceAll('\n', ' '));
const origin = (await runtime.ready).origin;
const url = origin + '/api/vault';
const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
const auth = await derive(crypto.randomUUID() + crypto.randomUUID(), salt);
const tasks = [{ id: crypto.randomUUID(), title: 'Confidential integration sentinel 🔐', done: false }];
const envelope = await seal(tasks, auth.key, salt);
const headers = { 'content-type': 'application/json', authorization: 'Bearer ' + auth.writeToken, connection: 'close' };
const write = async (revision, extra = {}, data = envelope) => {
  const result = await fetch(url, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify({ envelope: data, revision }) });
  const body = await result.text();
  return { status: result.status, body };
};
const before = await fetch(url); assert.equal(before.status, 200);
assert.equal((await before.json()).initialized, false);
assert.equal((await write(0)).status, 403, 'cannot claim without invitation');
assert.equal((await write(0, { 'x-veil-setup': 'bad' })).status, 403);
assert.equal((await write(0, { 'x-veil-setup': 'LOCAL-TEST-INVITATION' })).status, 200);
const publicResponse = await fetch(url);
assert.equal(publicResponse.headers.get('cache-control'), 'no-store');
const publicText = await publicResponse.text();
assert.equal(publicText.includes(tasks[0].title), false);
assert.equal(publicText.includes('write_hash'), false);
assert.equal(publicText.includes(auth.writeToken), false);
const data = JSON.parse(publicText); assert.equal(data.revision, 1);
assert.deepEqual(await unseal(data.envelope, auth.key), tasks);
assert.equal((await write(1, { authorization: 'Bearer ' + toBase64(crypto.getRandomValues(new Uint8Array(32))) })).status, 401);
assert.equal((await write(1, { origin: 'https://other.example' })).status, 403);
assert.equal((await write(0)).status, 409, 'stale revision rejected');
const next = await seal([{ ...tasks[0], done: true }], auth.key, salt);
const saved = await write(1, {}, next);
assert.equal(saved.status, 200, saved.body);
const staleClaim = await write(0, { authorization: 'Bearer ' + toBase64(crypto.getRandomValues(new Uint8Array(32))), 'x-veil-setup': 'LOCAL-TEST-INVITATION' });
assert.equal(staleClaim.status, 401, 'invitation cannot replace an initialized vault');
assert.equal((await write(2, {}, { ...next, salt: toBase64(crypto.getRandomValues(new Uint8Array(16))) })).status, 400);
assert.equal((await write(2, {}, { ...next, iv: 'invalid' })).status, 400);
console.log('PASS: public encrypted reads, private initialization, authorized saves, wrong credentials, replayed setup, foreign origins, stale revisions, invalid payloads.');

} finally { await runtime.dispose(); }

