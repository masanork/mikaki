/** Test-only fault/race observation around the real compiled Rust OP. */
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function nativeProviderObserver(root: string, main: string) {
  const generated = join(root, 'local/generated');
  await mkdir(generated, { recursive: true });
  const directory = await mkdtemp(join(generated, 'native-oidc-verifier-'));
  const wrapper = join(directory, 'worker.mjs');
  await writeFile(
    wrapper,
    `
    import Op from ${JSON.stringify(main)};
    export * from ${JSON.stringify(main)};
    export default class extends Op {
      async fetch(request) {
        const fault = request.headers.get('X-Test-Native-Fault');
        const originalImport = crypto.subtle.importKey;
        const originalVerify = crypto.subtle.verify;
        const observations = [];
        let verifiedNative = 0;
        crypto.subtle.importKey = async function(format, data, algorithm, extractable, usages) {
          if (format === 'raw' && algorithm.name === 'ECDSA') {
            observations.push({ bytes: data.byteLength, extractable, usages });
            if (fault === 'import') throw new Error('injected native import failure');
            if (fault === 'extractable') extractable = true;
          }
          return originalImport.call(this, format, data, algorithm, extractable, usages);
        };
        const db = this.env.DB;
        crypto.subtle.verify = async function(...args) {
          if (fault === 'verify') throw new Error('injected native verify failure');
          if (fault === 'false') return false;
          if (fault === 'truthy') return 1;
          const verified = await originalVerify.apply(this, args);
          if (verified === true) verifiedNative++;
          if (fault === 'revoke-client') await db.prepare(
            "UPDATE client_key SET active=0,revision=revision+1 WHERE client_id='rp' AND kid='client'"
          ).run();
          return verified;
        };
        try {
          const response = await super.fetch(request);
          const result = new Response(response.body, response);
          result.headers.set('X-Test-Native-Imports', JSON.stringify(observations));
          result.headers.set('X-Test-Native-Verified', String(verifiedNative));
          return result;
        } finally {
          crypto.subtle.importKey = originalImport;
          crypto.subtle.verify = originalVerify;
        }
      }
    }
  `,
  );
  return { main: wrapper, close: () => rm(directory, { recursive: true, force: true }) };
}
