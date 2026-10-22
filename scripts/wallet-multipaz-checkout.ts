import assert from 'node:assert/strict';
import { lstat, realpath } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

/** SDK tests execute local code: require ownership and reject writes by other users. */
export async function ownedMultipazCheckout(requested: string): Promise<string> {
  const uid = process.getuid?.();
  assert.notEqual(uid, undefined, 'SDK checkout validation requires POSIX ownership');
  const checkout = await realpath(resolve(requested));
  let current = checkout;
  while (true) {
    const info = await lstat(current);
    assert.ok(info.isDirectory(), 'SDK checkout and its parents must be directories');
    assert.ok(
      info.uid === uid || (current !== checkout && info.uid === 0),
      'SDK checkout must belong to the operator; parents must belong to the operator or root',
    );
    assert.ok(
      current !== checkout || (info.mode & 0o077) === 0,
      'SDK checkout must be private to the operator (chmod 700 before running)',
    );
    // A root-owned sticky parent protects its operator-owned child from replacement.
    // The checkout itself must never be writable by another user or group.
    const protectedParent = current !== checkout && info.uid === 0 && (info.mode & 0o1000) !== 0;
    assert.ok(
      (info.mode & 0o022) === 0 || protectedParent,
      'SDK checkout and its parents must not permit replacement or writes by other users',
    );
    const parent = dirname(current);
    if (parent === current) return checkout;
    current = parent;
  }
}
