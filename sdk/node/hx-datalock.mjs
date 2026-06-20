#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { main } from './dist/cli.js';
import { DataLockError } from './dist/errors.js';

export * from './dist/index.js';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    if (error instanceof DataLockError) {
      console.error(`HXDL_ERROR code=${error.code} message=${error.message}`);
    } else {
      console.error(`error: ${error.message}`);
    }
    process.exitCode = 1;
  });
}
