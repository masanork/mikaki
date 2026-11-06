/** Local Wasm entrypoint for real SSO/D1 installation adapters. Never deploy. */
import { buildQualificationWorker } from './qualification-worker-builder.ts';

await buildQualificationWorker({
  name: 'installation',
  fixture: 'design/probes/android-device-registry/worker-qualification-fixture.mjs',
  bindgenVariable: 'MIKAKI_INSTALLATION_BINDGEN',
  bundle: true,
});
