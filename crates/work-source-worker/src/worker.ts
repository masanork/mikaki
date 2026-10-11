import { WorkerEntrypoint } from 'cloudflare:workers';
import { readRegisteredSource } from './core';
export class WorkSourceReader extends WorkerEntrypoint<Cloudflare.Env> {
  async readRegisteredSource(input: string): Promise<string> {
    if (String(this.env.WORK_SOURCE_READER_ENABLED) !== 'true')
      throw new Error('source_unavailable');
    try {
      return await readRegisteredSource(this.env.ARTIFACTS, input);
    } catch {
      throw new Error('source_unavailable');
    }
  }
  fetch(): Response {
    return new Response(null, { status: 404 });
  }
}
// HTTP cannot invoke this capability, including on the named entrypoint.
export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
};
