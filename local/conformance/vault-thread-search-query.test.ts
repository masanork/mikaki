import assert from 'node:assert/strict';
import { test } from 'node:test';
import { threadSearchTerms } from '../../crates/worker/ui/vault-thread-search-query.ts';

test('shared query validation accepts exactly eight terms and rejects unsupported input before dispatch', () => {
  assert.deepEqual(threadSearchTerms('ＡＢＣ　住所\t申請'), ['abc', '住所', '申請']);
  assert.deepEqual(threadSearchTerms('園 '.repeat(8)), Array(8).fill('園'));
  assert.deepEqual(threadSearchTerms('園　'.repeat(8)), Array(8).fill('園'));
  assert.deepEqual(threadSearchTerms(' \t\n'), []);
  assert.deepEqual(threadSearchTerms('a'.repeat(256)), ['a'.repeat(256)]);
  for (const value of ['園 '.repeat(9), '園　'.repeat(9), 'a'.repeat(257), '\ud800abc', null, 123])
    assert.throws(() => threadSearchTerms(value), /invalid query/);
});

test('real SQLite preserves literal NUL queries and rejects lossy Unicode projections', async () => {
  const [{ default: init }, { ThreadSearchProjection }] = await Promise.all([
    import('@sqlite.org/sqlite-wasm'),
    import('../../crates/worker/ui/vault-thread-search.ts'),
  ]);
  Object.assign(globalThis, {
    sqlite3ApiConfig: {
      disable: {
        vfs: { kvvfs: true, opfs: true, 'opfs-vfs': true, 'opfs-sahpool': true, 'opfs-wl': true },
      },
      log: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    },
  });
  const sqlite = await init();
  const projection = new ThreadSearchProjection(() => {
    const db = new sqlite.oo1.DB(':memory:');
    return {
      exec: (value) =>
        typeof value === 'string' ? db.exec(value) : db.exec(value.sql, { bind: value.bind }),
      selectObjects: (sql, bind) => db.selectObjects(sql, bind),
      close: () => db.close(),
    };
  });
  const record = (text: string) => [
    {
      id: 'selected',
      revision: 1,
      archive: {
        format_version: 1,
        title: 'Synthetic',
        messages: [
          { speaker: 'Human', actor: 'human', text, timestamp: '2026-10-03T00:00:00.000Z' },
        ],
      },
    },
  ];
  try {
    projection.replace(record('abc\0def'));
    for (const query of ['\0def', 'abc\0', 'def'])
      assert.equal(projection.search(query, ['selected']).hits[0]?.message, 0);
    assert.throws(() => projection.search('a '.repeat(9), ['selected']), /invalid query/);
    assert.equal(
      projection.search('def', ['selected']).hits.length,
      1,
      'invalid query keeps the valid projection usable',
    );
    assert.throws(() => projection.replace(record('\ud800abc')), /invalid archive unicode/);
    assert.throws(() => projection.search('abc', ['selected']), /locked/);
    projection.replace(record('�abc'));
    assert.throws(() => projection.search('\ud801abc', ['selected']), /invalid query/);
    assert.equal(projection.search('�abc', ['selected']).hits.length, 1);
  } finally {
    projection.dispose();
  }
});
