import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(
  new URL('../.github/workflows/mls-probe.yml', import.meta.url),
  'utf8',
);

function section(start: string, end: string) {
  const from = workflow.indexOf(start);
  assert.notEqual(from, -1, `missing workflow section: ${start}`);
  const to = workflow.indexOf(end, from + start.length);
  assert.notEqual(to, -1, `missing workflow section terminator: ${end}`);
  return workflow.slice(from, to);
}

test('Chat coverage survives failed-only workflow reruns', () => {
  const upload = section('      - name: Upload source-verified Chat coverage\n', '\n  coverage:\n');
  assert.match(upload, /\n          name: messaging-chromium-coverage\n/);
  assert.match(upload, /\n          overwrite: true\n/);
  assert.doesNotMatch(upload, /github\.run_attempt/);

  const download = section('\n  coverage:\n', '\n      - name: Require measured Chat coverage\n');
  assert.match(download, /\n          name: messaging-chromium-coverage\n/);
  assert.doesNotMatch(download, /github\.run_attempt/);
});
