/** Run the publisher's panic scenario against the exact legacy package flagged by OSV. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

test('block-buffer 0.10.4 keeps its separate cursor valid after the reported caught panic', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-legacy-block-buffer-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, 'src'));
  writeFileSync(
    join(directory, 'Cargo.toml'),
    `[package]
name = "mikaki-block-buffer-advisory-fixture"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
block-buffer = "=0.10.4"
`,
  );
  writeFileSync(
    join(directory, 'src/lib.rs'),
    `#[test]
fn caught_compression_panic_preserves_cursor() {
    use block_buffer::{EagerBuffer, generic_array::typenum::U4};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let mut buffer = EagerBuffer::<U4>::new(&[1, 2]);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        buffer.digest_blocks(&[3, 0xff], |_| panic!("synthetic compression panic"));
    })).is_err());
    assert_eq!(buffer.get_pos(), 2);
    buffer.digest_blocks(&[7], |_| panic!("no complete block"));
    assert_eq!(buffer.get_pos(), 3);
}
`,
  );
  const result = execFileSync(
    'cargo',
    ['test', '--quiet', '--manifest-path', join(directory, 'Cargo.toml')],
    {
      env: { ...process.env, CARGO_TARGET_DIR: join(directory, 'target') },
      encoding: 'utf8',
      timeout: 120_000,
    },
  );
  assert.match(result, /1 passed; 0 failed/);
});
