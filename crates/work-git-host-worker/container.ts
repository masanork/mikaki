/** Bundle this Linux entry; a Worker cannot execute Git child processes. */
import { gitHostBootstrap } from '../../scripts/work-git-host-bootstrap.ts';
const value = (name: string) => {
  const v = process.env[name];
  if (!v) throw new Error('git_host_configuration_missing');
  return v;
};
try {
  const host = await gitHostBootstrap({
    account: value('WORK_ARTIFACTS_ACCOUNT'),
    namespace: value('WORK_ARTIFACTS_NAMESPACE'),
    authority: value('WORK_AUTHORITY_ID'),
    registrySha256: value('WORK_GIT_REGISTRY_SHA256'),
    temporaryParent: '/tmp',
  });
  host.server.listen(8080, '0.0.0.0');
  process.once('SIGTERM', () => {
    void host.close().finally(() => process.exit(0));
  });
} catch {
  console.error(JSON.stringify({ event: 'git_host_start_refused' }));
  process.exitCode = 1;
}
