import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const script = readFileSync(
  new URL(
    '../../apps/mikaki-client/plugins/app-session/android/src/main/assets/mikaki-app-session/credential-return.js',
    import.meta.url,
  ),
  'utf8',
);
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

function fixture(visible = true) {
  const windowEvents = new EventTarget();
  const documentEvents = new EventTarget();
  const first = new Uint8Array(32).fill(11);
  const second = new Uint8Array(32).fill(17);
  class Credential {
    getClientExtensionResults() {
      return { prf: { results: { first: first.buffer, second: second.buffer } } };
    }
  }
  let complete!: (value: unknown) => void;
  let reject!: (error: unknown) => void;
  const result = new Promise<unknown>((resolve, fail) => {
    complete = resolve;
    reject = fail;
  });
  let received: unknown;
  let calls = 0;
  class Credentials {
    get(options: unknown): Promise<unknown> {
      assert.equal(this, container, 'preserve the native API receiver');
      calls++;
      received = options;
      return result;
    }
  }
  const container = new Credentials();
  const timers = new Map<number, { callback: () => void; delay: number }>();
  let sequence = 0;
  const document = {
    visibilityState: 'visible',
    addEventListener: documentEvents.addEventListener.bind(documentEvents),
    removeEventListener: documentEvents.removeEventListener.bind(documentEvents),
  };
  const window = {
    __MIKAKI_WORKSPACE_VISIBLE__: visible,
    __MIKAKI_WORKSPACE_SELECTED__: true,
    CredentialsContainer: Credentials,
    PublicKeyCredential: Credential,
    addEventListener: windowEvents.addEventListener.bind(windowEvents),
    removeEventListener: windowEvents.removeEventListener.bind(windowEvents),
  };
  runInNewContext(script, {
    window,
    document,
    DOMException,
    ArrayBuffer,
    Uint8Array,
    setTimeout: (callback: () => void, delay: number) => {
      const id = ++sequence;
      timers.set(id, { callback, delay });
      return id;
    },
    clearTimeout: (id: number) => timers.delete(id),
  });
  return {
    window,
    document,
    first,
    second,
    container,
    credential: new Credential(),
    complete,
    reject,
    timers,
    calls: () => calls,
    received: () => received,
    activity: () => windowEvents.dispatchEvent(new Event('mikaki-workspace-visibility')),
    visibility: () => documentEvents.dispatchEvent(new Event('visibilitychange')),
    pagehide: () => windowEvents.dispatchEvent(new Event('pagehide')),
    cleared: () => first.every((byte) => byte === 0) && second.every((byte) => byte === 0),
  };
}

test('foreground Passkey return preserves the native request, result and PRF buffers', async () => {
  const f = fixture();
  const options = { publicKey: { challenge: new Uint8Array(32) } };
  const pending = f.container.get(options);
  f.complete(f.credential);
  assert.equal(await pending, f.credential);
  assert.equal(f.received(), options);
  assert.equal(f.calls(), 1);
  assert(f.first.every((byte) => byte === 11));
  assert(f.second.every((byte) => byte === 17));
  assert.equal(f.timers.size, 0);
});

test('completed Passkey waits for native resume even when the document is already visible', async () => {
  const f = fixture(false);
  const pending = f.container.get({});
  let settled = false;
  void pending.then(() => (settled = true));
  f.complete(f.credential);
  await turn();
  assert.equal(settled, false, 'the real-device result-before-onResume ordering');
  assert.equal(f.timers.size, 1);
  f.window.__MIKAKI_WORKSPACE_VISIBLE__ = true;
  f.activity();
  assert.equal(await pending, f.credential);
  assert.equal(f.calls(), 1, 'do not perform a second ceremony');
  assert.equal(f.cleared(), false);
  assert.equal(f.timers.size, 0);
});

test('native resume also requires a visible document before delivering the result', async () => {
  const f = fixture(false);
  f.document.visibilityState = 'hidden';
  const pending = f.container.get({});
  let settled = false;
  void pending.then(() => (settled = true));
  f.complete(f.credential);
  await turn();
  f.window.__MIKAKI_WORKSPACE_VISIBLE__ = true;
  f.activity();
  await turn();
  assert.equal(settled, false);
  f.document.visibilityState = 'visible';
  f.visibility();
  assert.equal(await pending, f.credential);
  assert.equal(f.timers.size, 0);
});

test('navigation, cancellation, pagehide and a new background transition discard both PRF outputs', async () => {
  for (const reason of ['already-left', 'leave', 'abort', 'pagehide', 'background'] as const) {
    const f = fixture(false);
    const controller = new AbortController();
    if (reason === 'already-left') f.window.__MIKAKI_WORKSPACE_SELECTED__ = false;
    const pending = f.container.get({ signal: controller.signal });
    const rejected = assert.rejects(pending, (error: unknown) => {
      assert(error instanceof DOMException);
      assert.equal(error.name, reason === 'abort' ? 'AbortError' : 'NotAllowedError');
      return true;
    });
    f.complete(f.credential);
    await turn();
    if (reason === 'leave') {
      f.window.__MIKAKI_WORKSPACE_SELECTED__ = false;
      f.activity();
    }
    if (reason === 'abort') controller.abort();
    if (reason === 'pagehide') f.pagehide();
    if (reason === 'background') {
      f.document.visibilityState = 'hidden';
      f.visibility();
    }
    await rejected;
    assert(f.cleared(), reason);
    assert.equal(f.timers.size, 0);
    f.window.__MIKAKI_WORKSPACE_SELECTED__ = true;
    f.window.__MIKAKI_WORKSPACE_VISIBLE__ = true;
    f.activity();
    assert(f.cleared(), 'a later visit cannot revive the rejected result');
  }
});

test('native foreground wait has a fixed one-second upper bound and cannot be extended', async () => {
  const f = fixture(false);
  const pending = f.container.get({});
  const rejected = assert.rejects(pending, { name: 'NotAllowedError' });
  f.complete(f.credential);
  await turn();
  const [timer] = [...f.timers.values()];
  assert(timer && timer.delay > 0 && timer.delay <= 1000);
  f.activity();
  f.activity();
  assert.equal(f.timers.size, 1);
  assert.equal([...f.timers.values()][0], timer, 'no deadline renewal');
  timer.callback();
  await rejected;
  assert(f.cleared());
  assert.equal(f.timers.size, 0);
});

test('a result returned after cancellation is discarded even in the foreground', async () => {
  const f = fixture();
  const controller = new AbortController();
  const pending = f.container.get({ signal: controller.signal });
  const rejected = assert.rejects(pending, (error) => error === controller.signal.reason);
  controller.abort();
  f.complete(f.credential);
  await rejected;
  assert(f.cleared());
  assert.equal(f.timers.size, 0);
});

test('underlying failures and non-PublicKeyCredential results retain their original behavior', async () => {
  const f = fixture(false);
  const error = new DOMException('Provider cancellation', 'NotAllowedError');
  const pending = f.container.get({});
  const rejected = assert.rejects(pending, (value) => value === error);
  f.reject(error);
  await rejected;
  assert.equal(f.timers.size, 0);
  for (const value of [null, { kind: 'another credential type' }]) {
    const other = fixture(false);
    const result = other.container.get({});
    other.complete(value);
    assert.equal(await result, value);
    assert.equal(other.timers.size, 0);
  }
});
