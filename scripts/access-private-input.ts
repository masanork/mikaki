import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

/** Read the operator-selected private JSON from the same file descriptor we inspect. */
export async function readAccessPrivateInput(path: string): Promise<Record<string, unknown>> {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') {
    throw new Error('input requires POSIX ownership and permission checks');
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); // NOSONAR: The operator selects this input; the opened file is checked before reading.
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      (stat.mode & 0o077) !== 0 ||
      stat.uid !== process.getuid() ||
      stat.size > 16384
    )
      throw new Error('input must be an owner-only regular file owned by the current user');
    const bytes = Buffer.alloc(16385);
    let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    if (used > 16384) throw new Error('input exceeds 16 KiB');
    return JSON.parse(bytes.subarray(0, used).toString('utf8'));
  } finally {
    await handle.close();
  }
}
