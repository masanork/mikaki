declare module '*.mjs' {
  import { WorkerEntrypoint } from 'cloudflare:workers';
  class RustOp extends WorkerEntrypoint<Env> {
    fetch(request: Request): Promise<Response>;
    administer_op_authority(request: Request, env: Env): Promise<Response>;
    administer_work_effect(request: Request, env: Env): Promise<Response>;
  }
  export default RustOp;
}
