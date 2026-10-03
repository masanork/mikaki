import init from '/sqlite/index.mjs';

// Disposable synthetic probe. No production keys, Vault API or authentication.
const started = performance.now();
let sqlite;
let startupMs;
const ready = init({ print: () => {}, printErr: () => {} }).then((runtime) => {
  sqlite = runtime;
  startupMs = performance.now() - started;
});
let db;
let allowed = [];
const norm = (text) => text.normalize('NFKC').toLowerCase();
const rows = (sql, bind = []) =>
  db.exec({ sql, bind, rowMode: 'object', returnValue: 'resultRows' });
const schema = `
CREATE TABLE items(id INTEGER PRIMARY KEY, thread TEXT NOT NULL, body TEXT NOT NULL, normalized TEXT NOT NULL);
CREATE INDEX items_thread ON items(thread);
CREATE VIRTUAL TABLE ft USING fts5(normalized, content=items, content_rowid=id, tokenize=trigram);
CREATE TRIGGER ai AFTER INSERT ON items BEGIN INSERT INTO ft(rowid,normalized) VALUES(new.id,new.normalized); END;
CREATE TRIGGER ad AFTER DELETE ON items BEGIN INSERT INTO ft(ft,rowid,normalized) VALUES('delete',old.id,old.normalized); END;
CREATE TRIGGER au AFTER UPDATE ON items BEGIN
INSERT INTO ft(ft,rowid,normalized) VALUES('delete',old.id,old.normalized);
INSERT INTO ft(rowid,normalized) VALUES(new.id,new.normalized); END;`;

function search(query, scope = allowed) {
  if (!db) throw new Error('locked');
  if (!scope.length || scope.some((id) => !allowed.includes(id))) throw new Error('scope denied');
  const terms = norm(query).trim().split(/\s+/u).filter(Boolean);
  if (!terms.length || terms.length > 8 || query.length > 256) throw new Error('invalid query');
  const long = terms.filter((term) => [...term].length >= 3);
  const binds = [...scope];
  const where = [`i.thread IN (${scope.map(() => '?').join(',')})`];
  if (long.length) {
    where.push('ft MATCH ?');
    binds.push(long.map((term) => `"${term.replaceAll('"', '""')}"`).join(' AND '));
  }
  // Literal predicates keep long and short terms consistent, including %/_/quotes.
  for (const term of terms) {
    where.push('instr(i.normalized, ?) > 0');
    binds.push(term);
  }
  return rows(
    `SELECT i.id,i.thread,i.body FROM items i ${long.length ? 'JOIN ft ON ft.rowid=i.id' : ''}
    WHERE ${where.join(' AND ')} ORDER BY ${long.length ? 'bm25(ft), ' : ''}i.id LIMIT 20`,
    binds,
  );
}

function put(id, thread, body) {
  if (!allowed.includes(thread)) throw new Error('scope denied');
  db.exec({
    sql: 'INSERT INTO items VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body, normalized=excluded.normalized',
    bind: [id, thread, body, norm(body)],
  });
}

async function run(size, scope) {
  allowed = scope;
  db = new sqlite.oo1.DB(':memory:');
  db.exec(schema);
  const buildStart = performance.now();
  db.exec('BEGIN');
  const stmt = db.prepare('INSERT INTO items VALUES(?,?,?,?)');
  try {
    for (let i = 1; i <= size; i++) {
      const thread = i % 2 ? 'human' : 'ai';
      if (!allowed.includes(thread)) continue;
      const body = `架空の会話${i}。${i % 37 === 0 ? '住所変更の申請を準備する。' : '日程と必要書類を相談する。'}${'関連する説明を確認して次の作業を整理する。'.repeat(8)}`;
      stmt.bind([i, thread, body, norm(body)]).step();
      stmt.reset();
    }
  } finally {
    stmt.finalize();
  }
  db.exec('COMMIT');
  const buildMs = performance.now() - buildStart;
  const check = (condition, label) => {
    if (!condition) throw new Error(label);
  };
  put(-1, 'human', '住所変更の申請を準備する。100%確実とは言えない。ＡＢＣ "引用" 🐈');
  check(
    search('住所').some((r) => r.id === -1),
    'short Japanese',
  );
  check(
    search('住所変更 申請').some((r) => r.id === -1),
    'mixed AND',
  );
  check(search('住所 不在語').length === 0, 'AND mismatch');
  check(
    search('100%').some((r) => r.id === -1),
    'literal wildcard',
  );
  check(
    search('abc').some((r) => r.id === -1),
    'normalization',
  );
  check(
    search('"引用"').some((r) => r.id === -1),
    'literal quotes',
  );
  check(
    search('🐈').some((r) => r.id === -1),
    'Unicode short term',
  );
  check(
    search('住所', ['human']).every((r) => r.thread === 'human'),
    'thread filter',
  );
  let denied = false;
  try {
    search('住所', ['forbidden']);
  } catch {
    denied = true;
  }
  check(denied, 'forbidden scope');
  put(-1, 'human', '撤回後の説明');
  check(!search('住所変更').some((r) => r.id === -1), 'edit removes FTS');
  check(
    search('撤回後').some((r) => r.id === -1),
    'edit adds FTS',
  );
  db.exec({ sql: 'DELETE FROM items WHERE id=?', bind: [-1] });
  check(search('撤回後').length === 0, 'delete removes FTS');
  db.exec("INSERT INTO ft(ft) VALUES('rebuild')");
  const before = search('住所変更');
  const queries = {};
  for (const query of ['住所変更', '住所', '申請', '住所変更 申請', '存在しない検索語', '無']) {
    const times = [];
    for (let i = 0; i < 15; i++) {
      const t = performance.now();
      search(query);
      times.push(performance.now() - t);
    }
    times.sort((a, b) => a - b);
    queries[query] = { p50Ms: times[7], p95Ms: times[14] };
  }
  const exportStart = performance.now();
  const image = sqlite.capi.sqlite3_js_db_export(db.pointer);
  const exportMs = performance.now() - exportStart;
  const bytes = image.byteLength;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    JSON.stringify({ version: 1, owner: 'fictional', scope: allowed }),
  );
  const cryptoStart = performance.now();
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    image,
  );
  image.fill(0);
  const encryptionMs = performance.now() - cryptoStart;
  let tamperRejected = false;
  const tampered = new Uint8Array(encrypted.slice(0));
  tampered[0] ^= 1;
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, tampered);
  } catch {
    tamperRejected = true;
  }
  check(tamperRejected, 'ciphertext authentication');
  let wrongScopeRejected = false;
  try {
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('wrong scope') },
      key,
      encrypted,
    );
  } catch {
    wrongScopeRejected = true;
  }
  check(wrongScopeRejected, 'scope metadata authentication');
  db.close();
  const restoreStart = performance.now();
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, encrypted),
  );
  db = new sqlite.oo1.DB(':memory:');
  // Fixed-size client-owned allocation, released after DB close, per official API.
  const p = sqlite.wasm.allocFromTypedArray(plain);
  db.onclose = {
    after() {
      sqlite.wasm.heap8u().fill(0, p, p + bytes);
      sqlite.wasm.dealloc(p);
    },
  };
  db.checkRc(
    sqlite.capi.sqlite3_deserialize(
      db.pointer,
      'main',
      p,
      bytes,
      bytes,
      sqlite.capi.SQLITE_DESERIALIZE_READONLY,
    ),
  );
  plain.fill(0);
  check(JSON.stringify(search('住所変更')) === JSON.stringify(before), 'snapshot restores hits');
  const restoreMs = performance.now() - restoreStart;
  const result = {
    sqlite: sqlite.capi.sqlite3_libversion(),
    size,
    indexed: rows('SELECT count(*) AS n FROM items')[0].n,
    startupMs,
    buildMs,
    bytes,
    exportMs,
    encryptionMs,
    restoreMs,
    queries,
    threads: rows('SELECT DISTINCT thread FROM items ORDER BY thread').map((r) => r.thread),
    wasmHeapCapacityBytes: sqlite.wasm.heap8u().byteLength,
    checks: [
      'short/mixed/literal/Unicode queries',
      'scope rejection',
      'edit/delete/rebuild',
      'authenticated snapshot round trip',
    ],
  };
  db.close();
  db = undefined;
  allowed = [];
  let locked = false;
  try {
    search('住所');
  } catch {
    locked = true;
  }
  check(locked, 'closed DB cannot search');
  return result;
}

self.onmessage = async ({ data }) => {
  try {
    await ready;
    self.postMessage({ result: await run(data.size, data.scope) });
  } catch (error) {
    db?.close();
    self.postMessage({ error: String(error.stack ?? error) });
  }
};
