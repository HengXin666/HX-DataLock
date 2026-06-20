#!/usr/bin/env node
import {
  DataLockError,
  loadKeyring,
  makeSenderDataLock,
  makeUserDataLock,
} from '../../sdk/node/hx-datalock.mjs';
import { readFileSync } from 'node:fs';

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      throw new Error(`Unexpected argument: ${token}`);
    }
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }
    options[key] = value;
    i += 1;
  }
  return options;
}

function requireOption(options, name) {
  if (!options[name]) {
    throw new Error(`Missing required option --${name}`);
  }
  return options[name];
}

function masterPasswordFromEnv(options) {
  const envName = requireOption(options, 'password-env');
  const value = process.env[envName];
  if (!value) {
    throw new Error(`Environment variable ${envName} is empty or missing`);
  }
  return value;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const publicPath = requireOption(options, 'public');
  const keyringPath = requireOption(options, 'keyring');
  const inputPath = requireOption(options, 'in');
  const envelopePath = requireOption(options, 'envelope');
  const outputPath = requireOption(options, 'out');

  const sender = makeSenderDataLock(JSON.parse(readFileSync(publicPath, 'utf8')));
  sender.lockFile(inputPath, envelopePath);

  const user = makeUserDataLock(loadKeyring(keyringPath), {
    masterPassword: masterPasswordFromEnv(options),
  });
  try {
    user.openFile(envelopePath, outputPath);
  } finally {
    user.close();
  }
}

main().catch((error) => {
  if (error instanceof DataLockError) {
    console.error(`HXDL_ERROR code=${error.code} message=${error.message}`);
  } else {
    console.error(`error: ${error.message}`);
  }
  process.exitCode = 1;
});
