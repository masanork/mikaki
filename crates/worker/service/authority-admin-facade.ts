/** Only the separate named facade supplies the OP's own Env to raw Wasm glue. */
import { WorkerEntrypoint } from 'cloudflare:workers';
type RustOp = new (
  context: ExecutionContext,
  env: Env,
) => WorkerEntrypoint<Env> & {
  fetch(request: Request): Promise<Response>;
  administer_op_authority(request: Request, env: Env): Promise<Response>;
  administer_work_effect(request: Request, env: Env): Promise<Response>;
  administer_work_copy(request: Request, env: Env): Promise<Response>;
};
function denied() {
  return Promise.resolve(Response.json({ error: 'not_found' }, { status: 404 }));
}
// A base denial closes raw copy RPC on every other named/public facade.
export function authorityFacades(Op: RustOp) {
  class Closed extends Op {
    administer_work_copy(): Promise<Response> {
      return denied();
    }
  }
  class Copy extends Op {
    fetch(request: Request): Promise<Response> {
      if (new URL(request.url).pathname !== '/copy-job') return denied();
      return super.administer_work_copy(request, this.env);
    }
    administer_work_copy(): Promise<Response> {
      return denied();
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
    administer_op_authority(): Promise<Response> {
      return denied();
    }
  }
  class Admin extends Closed {
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
  class Effect extends Closed {
    fetch(request: Request): Promise<Response> {
      if (new URL(request.url).pathname !== '/effect') return denied();
      return super.administer_work_effect(request, this.env);
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
    administer_op_authority(): Promise<Response> {
      return denied();
    }
  }
  class Mint extends Closed {
    fetch(request: Request): Promise<Response> {
      if (new URL(request.url).pathname !== '/mint-effect') return denied();
      return super.administer_work_effect(request, this.env);
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
    administer_op_authority(): Promise<Response> {
      return denied();
    }
  }
  class Git extends Closed {
    fetch(request: Request): Promise<Response> {
      if (new URL(request.url).pathname !== '/git-effect') return denied();
      return super.administer_work_effect(request, this.env);
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
    administer_op_authority(): Promise<Response> {
      return denied();
    }
  }
  class Public extends Closed {
    administer_op_authority(): Promise<Response> {
      return denied();
    }
    administer_work_effect(): Promise<Response> {
      return denied();
    }
  }
  return { Admin, Effect, Mint, Git, Copy, Public };
}
