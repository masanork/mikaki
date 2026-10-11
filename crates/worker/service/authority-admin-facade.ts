/** Only the separate named facade supplies the OP's own Env to raw Wasm glue. */
import { WorkerEntrypoint } from 'cloudflare:workers';
type RustOp = new (
  context: ExecutionContext,
  env: Env,
) => WorkerEntrypoint<Env> & {
  fetch(request: Request): Promise<Response>;
  administer_op_authority(request: Request, env: Env): Promise<Response>;
  administer_work_effect(request: Request, env: Env): Promise<Response>;
};
function denied() {
  return Promise.resolve(Response.json({ error: 'not_found' }, { status: 404 }));
}
export function authorityFacades(Op: RustOp) {
  class Admin extends Op {
    fetch(request: Request): Promise<Response> {
      return super.administer_op_authority(request, this.env);
    }
    administer_op_authority(): Promise<Response> {
      return denied();
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
  }
  class Effect extends Op {
    fetch(request: Request): Promise<Response> {
      return super.administer_work_effect(request, this.env);
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
    administer_op_authority(): Promise<Response> {
      return denied();
    }
  }
  class Public extends Op {
    administer_op_authority(): Promise<Response> {
      return denied();
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
  }
  return { Admin, Effect, Public };
}
