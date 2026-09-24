import { diagnostic_stage } from '../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
// Only accept payload-free diagnostics. Never log an exception or request body.
export function webauthnDiagnostic(error: unknown) {
  if (typeof error === 'string' && error.length <= 128) {
    try {
      const { code, stage } = JSON.parse(error);
      if (typeof code === 'string' && typeof stage === 'string' && diagnostic_stage(code) === stage)
        return { code, stage };
    } catch {
      /* Fall through to a fixed adapter code. */
    }
  }
  return { code: 'credential', stage: 'credential' };
}
