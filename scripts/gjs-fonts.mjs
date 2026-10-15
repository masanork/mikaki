// Build-time bridge to the user's gjs checkout; no subsetter runs in the browser.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const [wasmDir, jobFile] = process.argv.slice(2);
const bg = await import(pathToFileURL(join(wasmDir, 'font_subsetter_bg.js')));
const { instance } = await WebAssembly.instantiate(
  readFileSync(join(wasmDir, 'font_subsetter_bg.wasm')),
  { './font_subsetter_bg.js': bg },
);
bg.__wbg_set_wasm(instance.exports);
instance.exports.__wbindgen_start?.();
const jobs = JSON.parse(readFileSync(jobFile, 'utf8'));
let currentSource, font;
for (const job of jobs) {
  if (currentSource !== job.source) {
    font = readFileSync(job.source);
    currentSource = job.source;
  }
  if (typeof job.text !== 'string') throw new Error('Missing subset text');
  const bytes = bg.subset_font_raw(font, job.text);
  if (!bytes.length) throw new Error(`Empty font: ${job.output}`);
  writeFileSync(job.output, bytes);
}
