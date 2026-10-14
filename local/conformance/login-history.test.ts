import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  LOGIN_HISTORY_KEY,
  loginCredential,
  loginDestination,
  loginScope,
  readLoginHistory,
  recognizeLogin,
  rememberLogin,
} from '../../crates/worker/ui/login-history.ts';

const connection = {
  issuer: 'https://mikaki.test',
  client: 'test-app',
  destination: 'https://rp.test',
  scope: 'openid',
};
const credential = 'a'.repeat(64);
function storage() {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => {
      values.set(key, value);
    },
  };
}

test('reading a new history never writes a visit or promotes a connection', () => {
  const store = storage();
  for (let i = 0; i < 3; i++)
    assert.equal(recognizeLogin(readLoginHistory(store), connection).kind, 'first');
  assert.equal(store.values.size, 0);
});

test('recognition belongs to an issuer, app and selected Passkey, and detects destination or scope changes', () => {
  const store = storage();
  rememberLogin(store, connection, credential);
  const history = readLoginHistory(store);
  assert.equal(recognizeLogin(history, connection, credential).kind, 'known');
  assert.equal(recognizeLogin(history, connection, 'b'.repeat(64)).kind, 'first');
  assert.equal(
    recognizeLogin(history, { ...connection, client: 'other-app' }, credential).kind,
    'first',
  );
  assert.equal(
    recognizeLogin(history, { ...connection, issuer: 'https://other.test' }, credential).kind,
    'first',
  );
  for (const change of [{ destination: 'https://rp.test:8443' }, { scope: 'openid profile' }]) {
    const result = recognizeLogin(history, { ...connection, ...change }, credential);
    assert.equal(result.kind, 'changed');
    assert.equal(result.previous?.destination, connection.destination);
  }
});

test('corrupt, oversized, future-dated and inaccessible storage are unknown rather than trusted', () => {
  const store = storage();
  for (const raw of [
    '{',
    'x'.repeat(65_537),
    JSON.stringify({
      version: 1,
      records: [{ ...connection, credential, last: Date.now() + 3_600_000 }],
    }),
  ]) {
    store.setItem(LOGIN_HISTORY_KEY, raw);
    assert.equal(recognizeLogin(readLoginHistory(store), connection).kind, 'unavailable');
  }
  const blocked = {
    getItem() {
      throw new Error('blocked');
    },
    setItem() {
      throw new Error('quota');
    },
  };
  assert.equal(readLoginHistory(blocked).available, false);
  assert.equal(rememberLogin(blocked, connection, credential), false);
});

test('successful writes merge other apps, replace the selected credential and bound retention', () => {
  const store = storage();
  rememberLogin(store, connection, credential);
  rememberLogin(store, { ...connection, client: 'other' }, credential);
  rememberLogin(store, { ...connection, destination: 'https://new.test' }, credential);
  assert.equal(readLoginHistory(store).records.length, 2);
  assert.equal(recognizeLogin(readLoginHistory(store), connection, credential).kind, 'changed');
  for (let i = 0; i < 40; i++)
    rememberLogin(store, { ...connection, client: `app-${i}` }, credential);
  assert.equal(readLoginHistory(store).records.length, 32);
});

test('destination identities keep schemes and ports, and scope order has no meaning', () => {
  assert.equal(
    loginDestination('https://rp.test:8443/callback?state=secret'),
    'https://rp.test:8443',
  );
  assert.equal(
    loginDestination('com.example.app:/callback?state=secret#code=secret'),
    'com.example.app:/callback',
  );
  assert.notEqual(
    loginDestination('com.example.other:/callback'),
    loginDestination('com.example.app:/callback'),
  );
  assert.equal(loginScope('profile openid profile'), 'openid profile');
});

test('credential recognition stores a scoped digest rather than a raw credential ID', async () => {
  const id = 'a-passkey-id';
  const fingerprint = await loginCredential(connection.issuer, id);
  assert.match(fingerprint, /^[a-f0-9]{64}$/);
  assert.notEqual(fingerprint, await loginCredential('https://other.test', id));
  const store = storage();
  rememberLogin(store, connection, fingerprint);
  assert.ok(!store.getItem(LOGIN_HISTORY_KEY)?.includes(id));
});
