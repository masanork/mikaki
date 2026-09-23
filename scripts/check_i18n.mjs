import assert from 'node:assert/strict';
import { messages } from '../local/ui/src/messages.ts';
assert.deepEqual(Object.keys(messages.ja).sort(), Object.keys(messages.en).sort());
for (const catalog of Object.values(messages))
  for (const value of Object.values(catalog)) assert.ok(value.trim().length > 0);
console.log(`i18n: ${Object.keys(messages.ja).length} keys; ja/en complete`);
