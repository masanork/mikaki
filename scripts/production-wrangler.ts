/** Bounded control-plane retry. Never retry activation, triggers, schema or resource creation. */
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
