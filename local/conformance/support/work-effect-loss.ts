/** Manual remote qualification only: drop a real create result, including its token. */
import { WorkerEntrypoint } from 'cloudflare:workers';
interface Env {
  ARTIFACTS: Pick<Artifacts, 'create' | 'get'>;
}
export class LostCreate extends WorkerEntrypoint<Env> {
  async create(name: string, options: NonNullable<Parameters<Artifacts['create']>[1]>) {
    await this.env.ARTIFACTS.create(name, options);
    throw new Error('synthetic_lost_create_result');
  }
  get(name: string) {
    return this.env.ARTIFACTS.get(name);
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
