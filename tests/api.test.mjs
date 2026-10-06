import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { BlobPreconditionFailedError } from '@vercel/blob';
import { derive, seal, unseal, toBase64 } from '../lib/veil-crypto.ts';
import { createVaultApi } from '../lib/vault-api.ts';
import { createBlobStore } from '../lib/vault-blob.ts';
const preview = JSON.parse(readFileSync(new URL('../lib/preview-envelope.json', import.meta.url)));
const invite = 'LOCAL-TEST-INVITATION';
const setupHash = createHash('sha256').update(invite).digest('hex');

// Two independently constructed server instances share one storage service.
// The fake implements atomic no-overwrite and conditional-write semantics.
function storageService() {
  let current = null, version = 0;
  return {
    async get(path, options) {
      assert.equal(path, 'veil/vault.json');
      assert.equal(options.access, 'private');
      assert.equal(options.useCache, false, 'read must bypass stale CDN data');
      if (!current) return null;
      const snapshot = current;
      return { statusCode: 200, stream: new Response(snapshot.text).body, blob: { etag: snapshot.etag } };
    },
    async put(path, text, options) {
      assert.equal(path, 'veil/vault.json');
      assert.equal(options.access, 'private');
      assert.equal(options.addRandomSuffix, false);
      if (current && !options.allowOverwrite) throw new Error('Blob already exists');
      if (options.allowOverwrite) {
        assert.ok(options.ifMatch, 'overwrite requires a concurrency precondition');
        if (options.ifMatch !== current?.etag) throw new BlobPreconditionFailedError();
      }
      current = { text, etag: 'version-' + ++version };
      return { etag: current.etag };
    },
  };
}

const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
const auth = await derive(crypto.randomUUID() + crypto.randomUUID(), salt);
const tasks = [{ id: crypto.randomUUID(), title: 'Confidential integration sentinel 🔐', done: false }];
const envelope = await seal(tasks, auth.key, salt);
function write(api, revision, extra = {}, data = envelope) {
  return api.POST(new Request('https://veil.example/api/vault', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + auth.writeToken, ...extra },
    body: JSON.stringify({ envelope: data, revision }),
  }));
}

test('encrypted API protocol persists privately and rejects unauthorized or stale mutations', async () => {
  const api = createVaultApi(createBlobStore(storageService()), () => setupHash, preview);
  assert.equal((await (await api.GET()).json()).initialized, false);
  assert.equal((await write(api, 0)).status, 403);
  assert.equal((await write(api, 0, { 'x-veil-setup': 'bad' })).status, 403);
  assert.equal((await write(api, 0, { 'x-veil-setup': invite })).status, 200);
  const publicResponse = await api.GET();
  assert.equal(publicResponse.headers.get('cache-control'), 'no-store');
  const publicText = await publicResponse.text();
  assert.equal(publicText.includes(tasks[0].title), false);
  assert.equal(publicText.includes('writeHash'), false);
  assert.equal(publicText.includes(auth.writeToken), false);
  const data = JSON.parse(publicText);
  assert.deepEqual(Object.keys(data).sort(), ['envelope', 'initialized', 'revision']);
  assert.equal(data.revision, 1);
  assert.deepEqual(await unseal(data.envelope, auth.key), tasks);
  const wrongAuth = { authorization: 'Bearer ' + toBase64(crypto.getRandomValues(new Uint8Array(32))) };
  assert.equal((await write(api, 1, wrongAuth)).status, 401);
  assert.equal((await write(api, 1, { origin: 'https://other.example' })).status, 403);
  assert.equal((await write(api, 0)).status, 409);
  const next = await seal([{ ...tasks[0], done: true }], auth.key, salt);
  assert.equal((await write(api, 1, {}, next)).status, 200);
  assert.equal((await write(api, 0, { ...wrongAuth, 'x-veil-setup': invite })).status, 401);
  assert.equal((await write(api, 2, {}, { ...next, salt: toBase64(crypto.getRandomValues(new Uint8Array(16))) })).status, 400);
  assert.equal((await write(api, 2, {}, { ...next, iv: 'invalid' })).status, 400);
  assert.equal((await write(api, 2, { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await write(api, 2, { 'content-length': '210001' })).status, 413);
  assert.equal((await api.POST(new Request('https://veil.example/api/vault', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'null' }))).status, 400);
  const stored = await (await api.GET()).json();
  assert.equal(stored.revision, 2);
  assert.equal((await unseal(stored.envelope, auth.key))[0].done, true);
});

test('concurrent setup and saves cannot overwrite another server instance', async () => {
  const client = storageService();
  const first = createVaultApi(createBlobStore(client), () => setupHash, preview);
  const second = createVaultApi(createBlobStore(client), () => setupHash, preview);
  const claims = await Promise.all([write(first, 0, { 'x-veil-setup': invite }), write(second, 0, { 'x-veil-setup': invite })]);
  assert.deepEqual(claims.map(r => r.status).sort(), [200, 409]);
  const left = await seal([{ ...tasks[0], title: 'left' }], auth.key, salt);
  const right = await seal([{ ...tasks[0], title: 'right' }], auth.key, salt);
  const saves = await Promise.all([write(first, 1, {}, left), write(second, 1, {}, right)]);
  assert.deepEqual(saves.map(r => r.status).sort(), [200, 409]);
  const stored = await (await second.GET()).json();
  assert.equal(stored.revision, 2);
  assert.ok(['left', 'right'].includes((await unseal(stored.envelope, auth.key))[0].title));
});