import { test } from 'node:test';
import assert from 'node:assert/strict';
import { derive, seal, unseal, toBase64, fromBase64 } from '../lib/veil-crypto.ts';

test('encrypted tasks round-trip; wrong keys and modified ciphertext fail', async () => {
  const secret = crypto.randomUUID() + crypto.randomUUID();
  const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
  const auth = await derive(secret, salt);
  const tasks = [{ id: crypto.randomUUID(), title: 'A confidential test task 🔐', done: true }];
  const envelope = await seal(tasks, auth.key, salt);
  assert.deepEqual(await unseal(envelope, auth.key), tasks);
  assert.equal(JSON.stringify(envelope).includes(tasks[0].title), false);
  assert.equal(auth.key.extractable, false);
  const repeated = await seal(tasks, auth.key, salt);
  assert.notEqual(repeated.iv, envelope.iv);
  assert.notEqual(repeated.ciphertext, envelope.ciphertext);
  const wrong = await derive(crypto.randomUUID(), salt);
  await assert.rejects(unseal(envelope, wrong.key));
  const modified = fromBase64(envelope.ciphertext); modified[0] ^= 1;
  await assert.rejects(unseal({ ...envelope, ciphertext: toBase64(modified) }, auth.key));
  const same = await derive(secret, salt);
  assert.equal(same.writeToken, auth.writeToken);
  assert.deepEqual(await unseal(envelope, same.key), tasks);
  const empty = await seal([], auth.key, salt);
  assert.deepEqual(await unseal(empty, auth.key), []);
  await assert.rejects(unseal(empty, wrong.key));
});
