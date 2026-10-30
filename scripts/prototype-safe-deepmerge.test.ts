import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const merge: typeof import('../tools/prototype-safe-deepmerge/index.js') = require('deepmerge');
const upstream: typeof merge = require('../local/conformance/fixtures/deepmerge-4.3.1.cjs');

test('the installed Svelte configuration dependency resolves to the reviewed local fork', () => {
  const pluginRequire = createRequire(require.resolve('@sveltejs/vite-plugin-svelte'));
  assert.equal(
    pluginRequire.resolve('deepmerge'),
    require.resolve('../tools/prototype-safe-deepmerge/index.cjs'),
  );
});

test('the local override remains a valid application SBOM dependency', () => {
  const bom = JSON.parse(
    execFileSync('npm', ['sbom', '--sbom-format=cyclonedx', '--sbom-type=application'], {
      cwd: new URL('../', import.meta.url),
      encoding: 'utf8',
      timeout: 30_000,
    }),
  );
  assert.ok(
    bom.components.some(
      (component: { purl: string; version: string }) =>
        component.purl === 'pkg:npm/deepmerge@4.3.1-mikaki.1' &&
        component.version === '4.3.1-mikaki.1',
    ),
  );
});

test('reported clone/null-prototype/own-key attacks cannot change returned object prototypes', () => {
  const attack = JSON.parse('{"session":{"__proto__":{"admin":true}}}');
  const vulnerable = upstream<{ session: Record<string, unknown> | null }>(
    { session: null },
    attack,
  );
  assert.ok(vulnerable.session);
  assert.equal(vulnerable.session.admin, true, 'original fixture reproduces the report');
  const targets: Record<string, unknown>[] = [
    { session: null },
    { session: {} },
    Object.create(null),
    JSON.parse('{"__proto__": {"admin":true}}'),
  ];
  for (const target of targets) {
    for (const source of [
      attack,
      JSON.parse('{"__proto__":{"admin":true}}'),
      JSON.parse('{"constructor":{"prototype":{"admin":true}}}'),
    ]) {
      const result = merge<Record<string, unknown>>(target, source);
      assert.equal(Object.getPrototypeOf(result), Object.prototype);
      assert.equal(result.admin, undefined);
      assert.equal(Object.hasOwn(result, '__proto__'), false);
      assert.equal(Object.hasOwn(result, 'constructor'), false);
      if (result.session && typeof result.session === 'object') {
        assert.equal(Object.getPrototypeOf(result.session), Object.prototype);
        assert.equal(Reflect.get(result.session, 'admin'), undefined);
      }
    }
  }
  assert.equal(({} as Record<string, unknown>).admin, undefined);
});

test('target copying never invokes inherited setters and hostile Proxy inspection fails closed', () => {
  let invoked = false;
  const name = '__mikaki_merge_setter_probe';
  Object.defineProperty(Object.prototype, name, {
    set() {
      invoked = true;
    },
    configurable: true,
  });
  try {
    const result = merge({ [name]: 'own value' }, {});
    assert.equal(invoked, false);
    assert.equal(Object.getOwnPropertyDescriptor(result, name)?.value, 'own value');
  } finally {
    Reflect.deleteProperty(Object.prototype, name);
  }
  const target = new Proxy(
    {},
    {
      has() {
        throw new Error('hostile has trap');
      },
    },
  );
  assert.throws(() => merge(target, { value: true }), /Cannot inspect merge target/);
});

test('ordinary Svelte compiler/preprocessor configuration merging preserves upstream semantics', () => {
  const preprocess = () => ({ code: 'unchanged' });
  const symbol = Symbol('config');
  const options = { arrayMerge: (_a: unknown[], b: unknown[]) => b };
  const a = {
    compilerOptions: { dev: false, css: 'external' },
    preprocess: [preprocess],
    [symbol]: { a: 1 },
  };
  const b = {
    compilerOptions: { dev: true },
    preprocess: [preprocess, preprocess],
    [symbol]: { b: 2 },
  };
  assert.deepEqual(merge(a, b, options), upstream(a, b, options));
  assert.deepEqual(merge.all([a, b], options), upstream.all([a, b], options));
  assert.equal(merge(a, b, options).preprocess[0], preprocess);
  assert.deepEqual(a.compilerOptions, { dev: false, css: 'external' });
  assert.deepEqual(merge([1], [2]), [1, 2]);
});
