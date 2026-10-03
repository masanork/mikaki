import init from '@sqlite.org/sqlite-wasm';
import { installThreadSearchWorker } from './vault-thread-search-worker.ts';

// The pinned runtime accepts Emscripten options, although its published init type
// omits them. A compatible call signature keeps the verified options explicit.
const initialize: (options: {
  locateFile: (name: string) => string;
  print: () => void;
  printErr: () => void;
}) => ReturnType<typeof init> = init;
installThreadSearchWorker(
  self,
  initialize({
    locateFile: () => new URL('/vault/sqlite3.wasm', self.location.origin).href,
    print: () => {},
    printErr: () => {},
  }).then((sqlite) => () => {
    const db = new sqlite.oo1.DB(':memory:');
    return {
      exec: (input) =>
        typeof input === 'string' ? db.exec(input) : db.exec(input.sql, { bind: input.bind }),
      selectObjects: (sql, bind) => db.selectObjects(sql, bind),
      close: () => db.close(),
    };
  }),
);
