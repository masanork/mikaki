import { cpSync, rmSync } from 'node:fs';

const target = new URL('./ui/fonts', import.meta.url);
rmSync(target, { recursive: true, force: true });
cpSync(new URL('../../assets/fonts', import.meta.url), target, { recursive: true });
