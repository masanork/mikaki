import { execFileSync } from 'node:child_process';
import { sourceIsCurrent } from './deploy-production.ts';
execFileSync('git', ['fetch', 'origin', 'main'], { stdio: 'inherit' });
execFileSync('git', ['merge-base', '--is-ancestor', process.env.GITHUB_SHA!, 'origin/main']);
const changed = execFileSync(
  'git',
  ['diff', '--name-only', process.env.GITHUB_SHA!, 'origin/main'],
  { encoding: 'utf8' },
).trim();
if (sourceIsCurrent(changed ? changed.split('\n') : [])) {
  for (const config of ['website/wrangler.jsonc', 'website/wrangler.app.jsonc'])
    execFileSync('node_modules/.bin/wrangler', ['deploy', '--config', config], {
      stdio: 'inherit',
    });
} else console.log('A newer application revision is on main; leaving the website to its CI run.');
