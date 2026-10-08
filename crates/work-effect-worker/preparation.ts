/** Opaque private composition trigger. Rust owns evidence validation/promotion. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, opaque } from './protocol';
import { jsonBody, op } from './worker';
interface Env {
  WORK_PREPARATION_GATE_ENABLED: string;
  OP_EFFECT_STORE: Fetcher;
}
export class WorkPreparationGate extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    try {
      if (
        this.env.WORK_PREPARATION_GATE_ENABLED !== 'true' ||
        request.method !== 'POST' ||
        new URL(request.url).pathname !== '/verify-preparation'
      )
        throw new Error('preparation_denied');
      const input: unknown = await jsonBody(request);
      if (!closed(input, ['preparation_id']) || !opaque(input.preparation_id))
        throw new Error('preparation_invalid');
      const value = await op(this.env, {
        action: 'preparation-verify',
        preparation_id: input.preparation_id,
      });
      return Response.json(value, { headers: { 'Cache-Control': 'no-store' } });
    } catch {
      return Response.json(
        { error: 'preparation_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
