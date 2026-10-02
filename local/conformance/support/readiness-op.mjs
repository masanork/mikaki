// Disposable local fault-injection adapter; never used by production Wrangler configs.
import op from '../../../crates/worker/build/worker/shim.mjs';

const heads = [];
const dependencies = [];
export default {
  fetch(request, env, context) {
    const url = new URL(request.url);
    if (url.pathname === '/__test/r2-heads') return Response.json(heads);
    if (url.pathname === '/__test/dependencies') return Response.json(dependencies);
    const bucket = new Proxy(env.VAULT_BLOBS, {
      get(target, property) {
        if (property === 'head')
          return async (key) => {
            heads.push(key);
            if (url.searchParams.get('r2_fault') === 'error')
              throw new Error('Injected R2 failure');
            if (url.searchParams.get('r2_fault') === 'pending') return new Promise(() => {});
            return target.head(key);
          };
        if (['get', 'put', 'delete', 'list'].includes(property)) {
          throw new Error('Readiness must only call R2 HEAD');
        }
        return Reflect.get(target, property, target);
      },
    });
    const database = new Proxy(env.DB, {
      get(target, property) {
        if (property === 'prepare')
          return (sql) => {
            const statement = target.prepare(sql);
            if (!sql.includes('FROM d1_migrations')) return statement;
            return new Proxy(statement, {
              get(statementTarget, method) {
                if (method === 'first')
                  return async (...args) => {
                    dependencies.push('d1');
                    if (url.searchParams.get('ready_fault') === 'd1') return new Promise(() => {});
                    return statementTarget.first(...args);
                  };
                const value = Reflect.get(statementTarget, method, statementTarget);
                return typeof value === 'function' && method !== 'constructor'
                  ? value.bind(statementTarget)
                  : value;
              },
            });
          };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' && property !== 'constructor'
          ? value.bind(target)
          : value;
      },
    });
    const claims = new Proxy(env.USERINFO_CLAIMS, {
      get(target, property) {
        if (property === 'fetch')
          return async (...args) => {
            dependencies.push('claim');
            if (url.searchParams.get('ready_fault') === 'claim') return new Promise(() => {});
            return target.fetch(...args);
          };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' && property !== 'constructor'
          ? value.bind(target)
          : value;
      },
    });
    return new op(context, {
      ...env,
      VAULT_BLOBS: bucket,
      DB: database,
      USERINFO_CLAIMS: claims,
    }).fetch(request);
  },
};
