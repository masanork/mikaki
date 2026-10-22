/** Bounded control-plane retry. Never retry activation, triggers, schema or resource creation. */
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

export function retryableWrangler(args: string[], error: unknown): boolean {
  const read =
    (args[0] === 'versions' && args[1] === 'view') ||
    (args[0] === 'deployments' && args[1] === 'list') ||
    (args[0] === 'd1' && args[1] === 'migrations' && args[2] === 'list');
  // Upload creates only another inactive version of the same verified bundle;
  // it cannot enroll a checkpoint, change traffic or execute a Work operation.
  const upload = args[0] === 'versions' && args[1] === 'upload';
  if ((!read && !upload) || !error || typeof error !== 'object' || !('stderr' in error))
    return false;
  const stderr = error.stderr;
  if (typeof stderr !== 'string' || stderr.length > 65536) return false;
  const text = stderr.replace(/\x1b\[[0-9;]*m/g, '');
  return (
    / -> (?:500|502|503|504)\b/.test(text) ||
    (/Received a malformed response from the API/.test(text) && / -> 200 OK\b/.test(text))
  );
}
export async function productionWrangler(
  args: string[],
  execute: (args: string[]) => string,
  wait: (milliseconds: number) => Promise<unknown> = delay,
): Promise<string> {
  for (let attempt = 0; ; attempt++) {
    try {
      return execute(args);
    } catch (error) {
      if (attempt === 2 || !retryableWrangler(args, error)) throw error;
      // Do not log stderr, secret-file paths or error response bodies.
      console.log(
        JSON.stringify({
          event: 'production_control_retry',
          command: args.slice(0, 2),
          attempt: attempt + 2,
        }),
      );
      await wait(1000 * (attempt + 1));
    }
  }
}

/** Read a just-uploaded version until its metadata becomes visible, then validate it as usual. */
export async function uploadedVersionView(
  id: string,
  config: string,
  execute: (args: string[]) => string | Promise<string>,
  wait: (milliseconds: number) => Promise<unknown> = delay,
): Promise<string> {
  assert.match(id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
  const args = ['versions', 'view', id, '--config', config, '--json'];
  for (let attempt = 0; ; attempt++) {
    try {
      return await execute(args);
    } catch (error) {
      if (attempt === 4 || !uploadedVersionNotVisible(id, error)) throw error;
      // Log neither CLI stderr nor the config path. This loop only repeats GET metadata.
      console.log(
        JSON.stringify({
          event: 'production_uploaded_version_wait',
          version_id: id,
          attempt: attempt + 2,
        }),
      );
      await wait(1000 * 2 ** attempt);
    }
  }
}

function uploadedVersionNotVisible(id: string, error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('stderr' in error)) return false;
  const stderr = error.stderr;
  if (typeof stderr !== 'string' || stderr.length > 65536) return false;
  const text = stderr.replace(/\x1b\[[0-9;]*m/g, '');
  return (
    text.includes(`/versions/${id})`) &&
    /The requested Worker version could not be found\b/.test(text) &&
    /\[code:\s*100146\]/.test(text)
  );
}
