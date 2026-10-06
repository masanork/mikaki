import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
const messages = Object.fromEntries(
  await Promise.all(
    ['ja', 'en'].map(async (locale) => [
      locale,
      JSON.parse(await readFile(`messages/${locale}.json`, 'utf8')),
    ]),
  ),
) as Record<string, Record<string, string>>;
assert.deepEqual(Object.keys(messages.ja).sort(), Object.keys(messages.en).sort());
const placeholders = (message: string) =>
  [...message.matchAll(/\{([A-Za-z_][A-Za-z_0-9]*)\}/g)].map((match) => match[1]).sort();
for (const [key, japanese] of Object.entries(messages.ja)) {
  const english = messages.en[key];
  assert.equal(typeof japanese, 'string', `${key}: ja must be a string`);
  assert.equal(typeof english, 'string', `${key}: en must be a string`);
  assert.ok(japanese.trim(), `${key}: ja is empty`);
  assert.ok(english.trim(), `${key}: en is empty`);
  assert.deepEqual(placeholders(japanese), placeholders(english), `${key}: placeholder mismatch`);
}
// Svelte builds can erase a missing Paraglide export into `void 0`, leaving a
// runtime failure even when both locale catalogs have the same keys.
for (const entry of await readdir('crates/worker/ui')) {
  if (!/\.(svelte|ts)$/.test(entry)) continue;
  const source = await readFile(`crates/worker/ui/${entry}`, 'utf8');
  if (!source.includes('paraglide/messages')) continue;
  for (const match of source.matchAll(/\bm\.(\w+)\s*\(/g))
    assert.ok(Object.hasOwn(messages.en, match[1]), `${entry}: unknown message ${match[1]}`);
}
console.log(`i18n: ${Object.keys(messages.ja).length} keys; ja/en complete`);
