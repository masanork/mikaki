// Disposable local fault-injection adapter; never used by production Wrangler configs.
import op from '../../../crates/worker/build/worker/shim.mjs';

const heads = [];
export default {
  fetch(request, env, context) {
    const url = new URL(request.url);
    if (url.pathname === '/__test/r2-heads') return Response.json(heads);
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
    return new op(context, { ...env, VAULT_BLOBS: bucket }).fetch(request);
  },
};
