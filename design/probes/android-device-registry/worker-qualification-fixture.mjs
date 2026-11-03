// Local fault injection only. The Rust Worker still authenticates and performs
// every write against D1; faults run immediately before its completion batch.
import { initSync, fetch } from './qualification.js';
import module from './qualification_bg.wasm';
initSync({ module });

function database(db) {
  return new Proxy(db, {
    get(target, key) {
      if (key === 'constructor') return target.constructor;
      if (key === 'withSession')
        return (...args) => {
          const session = target.withSession(...args);
          return new Proxy(session, {
            get(s, k) {
              if (k === 'batch')
                return async (statements) => {
                  const fault = await db
                    .prepare('SELECT mode FROM fixture_installation_fault WHERE id=1')
                    .first();
                  if (fault) {
                    await db.prepare('DELETE FROM fixture_installation_fault WHERE id=1').run();
                    const mutations = {
                      session: "UPDATE sso_session SET revoked=1 WHERE sso_id='session'",
                      expiry:
                        "UPDATE sso_session SET expires_at=unixepoch()-1 WHERE sso_id='session'",
                      dbsc: "INSERT INTO dbsc_session VALUES('dbsc','session',zeroblob(65),'{}',unixepoch()-10,unixepoch()-10,unixepoch()-1)",
                      account: "UPDATE account_security SET active=0 WHERE account_id='account'",
                      epoch: "UPDATE account_security SET epoch=epoch+1 WHERE account_id='account'",
                      credential: "UPDATE credential SET active=0 WHERE credential_id='credential'",
                      client: 'UPDATE client SET active=0,revision=revision+1',
                      redirect: 'UPDATE client_redirect_uri SET active=0',
                    };
                    if (!mutations[fault.mode]) throw new Error('unknown_fixture_fault');
                    await db.prepare(mutations[fault.mode]).run();
                  }
                  return s.batch(statements);
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
