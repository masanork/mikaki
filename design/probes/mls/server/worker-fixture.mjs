// LOCAL qualification entrypoint only. Faults modify actual D1 authority before
// Rust writes/reads; there are no synthetic principals or authentication bypasses.
import { initSync, fetch } from './qualification.js';
import module from './qualification_bg.wasm';
initSync({ module });
function database(db) {
  const native = new WeakMap();
  async function fault(sql) {
    const f = await db.prepare('SELECT * FROM fixture_messaging_fault WHERE id=1').first();
    if (!f || !sql.includes(f.pattern)) return;
    await db.prepare('UPDATE fixture_messaging_fault SET remaining=remaining-1 WHERE id=1').run();
    if (f.remaining > 1) return;
    await db.prepare('DELETE FROM fixture_messaging_fault WHERE id=1').run();
    if (['lost_enrollment_reply', 'lost_delivery_reply', 'lost_invitation_reply', 'lost_recovery_reply'].includes(f.mode)) return 'lose_reply';
    if (f.mode === 'proof_expiry') {
      await new Promise((resolve) => setTimeout(resolve, 3000));
      return;
    }
    const changes = {
      account: 'UPDATE account_security SET active=0 WHERE account_id=?',
      epoch: 'UPDATE account_security SET epoch=epoch+1 WHERE account_id=?',
      credential: 'UPDATE credential SET active=0 WHERE account_id=?',
      session: 'UPDATE sso_session SET revoked=1 WHERE account_id=?',
      expiry: 'UPDATE sso_session SET expires_at=unixepoch()-1 WHERE account_id=?',
    };
    if (!changes[f.mode]) throw new Error('invalid_fixture_fault');
    await db.prepare(changes[f.mode]).bind(f.account_id).run();
  }
  function statement(stmt, sql) {
    const proxy = new Proxy(stmt, {
      get(target, key) {
        if (key === 'bind') return (...args) => statement(target.bind(...args), sql);
        if (['run', 'first', 'all'].includes(key))
          return async (...args) => {
            await fault(sql);
            return target[key](...args);
          };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    native.set(proxy, { stmt, sql });
    return proxy;
  }
  return new Proxy(db, {
    get(target, key) {
      if (key === 'constructor') return target.constructor;
      if (key === 'prepare') return (sql) => statement(target.prepare(sql), sql);
      if (key === 'batch')
        return async (statements) => {
          const originals = statements.map((stmt) => native.get(stmt));
          const mode = await fault(originals.map((v) => v.sql).join('\n'));
          const result = await target.batch(originals.map((v) => v.stmt));
          if (mode === 'lose_reply') throw new Error('synthetic_database_reply_lost');
          return result;
        };
      if (key === 'withSession')
        return (...args) => {
          const session = target.withSession(...args);
          return new Proxy(session, {
            get(s, k) {
              if (k === 'prepare') return (sql) => statement(s.prepare(sql), sql);
              if (k === 'batch')
                return async (statements) => {
                  const originals = statements.map((stmt) => native.get(stmt));
                  await fault(originals.map((v) => v.sql).join('\n'));
                  return s.batch(originals.map((v) => v.stmt));
                };
              const value = Reflect.get(s, k, s);
              return typeof value === 'function' ? value.bind(s) : value;
            },
          });
        };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
export default {
  fetch(request, env, ctx) {
    return fetch(request, { ...env, DB: database(env.DB) }, ctx);
  },
};
