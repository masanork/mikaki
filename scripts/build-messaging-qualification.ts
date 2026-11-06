/** Local Wasm entrypoint for real SSO/D1 messaging adapters. Never deploy. */
import { buildQualificationWorker } from './qualification-worker-builder.ts';

await buildQualificationWorker({
  name: 'messaging',
  fixture: 'design/probes/mls/server/worker-fixture.mjs',
  bindgenVariable: 'MIKAKI_MESSAGING_BINDGEN',
  bundle: false,
});
