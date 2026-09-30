import { readFileSync, mkdirSync, chmodSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import init, * as wasm from '../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
import { MdsStore } from '../local/mds.ts';
import type { Config, Input } from '../local/mds.ts';
await init({
  module_or_path: readFileSync(
    new URL('../crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm', import.meta.url),
  ),
});
const [command, configuration, database] = process.argv.slice(2);
if (!['refresh', 'status', 'watch'].includes(command) || !configuration || !database)
  throw Error(
    'Usage: node scripts/mds-refresh.ts refresh|status|watch CONFIG.json DATABASE.sqlite',
  );
const config: Config = JSON.parse(readFileSync(configuration, 'utf8'));
const path = resolve(database);
mkdirSync(dirname(path), { recursive: true });
const store = new MdsStore(path, config, {
  verify: (input: Input) => JSON.parse(wasm.verify_mds(JSON.stringify(input))),
  crlUrls: (jwt, profile) => JSON.parse(wasm.mds_crl_urls_with_profile(jwt, profile)),
});
chmodSync(path, 0o600);
let stopping = false;
process.on('SIGTERM', () => {
  stopping = true;
});
process.on('SIGINT', () => {
  stopping = true;
});
try {
  do {
    if (command !== 'status') {
      try {
        await store.refresh();
      } catch {
        process.exitCode = 1;
      }
    }
    console.log(JSON.stringify(store.status()));
    if (command !== 'watch') break;
    // Respect the public feed's once/hour rate limit, including failure retries.
    for (let seconds = 0; seconds < 3600 && !stopping; seconds++)
      await new Promise((r) => setTimeout(r, 1000));
  } while (!stopping);
} finally {
  store.close();
}
