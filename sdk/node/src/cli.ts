import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { stdin as input, stdout as output } from 'node:process';
import { fileURLToPath } from 'node:url';
import { DEFAULT_SCRYPT_N } from './constants.js';
import { DataLockError } from './errors.js';
import { PublicKeyDocument } from './documents.js';
import {
  createKeyring,
  exportPublicKeyDocument,
  loadKeyring,
  makeSenderDataLock,
  makeUserDataLock,
  verifyKeyringFile,
  verifyPublicKeyDocumentFile,
} from './sdk.js';

function usage() {
  console.log(`HX-DataLock

Usage:
  node sdk/node/hx-datalock.mjs init [--keyring keyring.hxdl.json] [--password-env NAME] [--scrypt-n N]
  node sdk/node/hx-datalock.mjs export-public [--keyring keyring.hxdl.json] [--out public.hxdl.json]
  node sdk/node/hx-datalock.mjs lock --public public.hxdl.json [--expect-key-id x25519:...] --in plain.bin --out sealed.hxdl.json
  node sdk/node/hx-datalock.mjs open --keyring keyring.hxdl.json --in sealed.hxdl.json --out plain.bin [--password-env NAME]
  node sdk/node/hx-datalock.mjs verify-keyring [--keyring keyring.hxdl.json]
  node sdk/node/hx-datalock.mjs verify-public --public public.hxdl.json
  node sdk/node/hx-datalock.mjs bench [--keyring keyring.hxdl.json] [--password-env NAME] [--sizes 1048576,10485760,26214400]
`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i];
    if (!token.startsWith('--')) {
      throw new Error(`Unexpected argument: ${token}`);
    }
    const key = token.slice(2);
    const next = rest[i + 1];
    if (!next || next.startsWith('--')) {
      options[key] = true;
    } else {
      options[key] = next;
      i += 1;
    }
  }
  return { command, options };
}

async function readPassword(options, prompt = 'Master password: ') {
  if (options['password-env']) {
    const value = process.env[options['password-env']];
    if (!value) {
      throw new Error(`Environment variable ${options['password-env']} is empty or missing`);
    }
    return value;
  }

  if (!input.isTTY || !output.isTTY) {
    throw new Error('Interactive password input requires a TTY; use --password-env for automation');
  }

  output.write(prompt);
  input.setRawMode(true);
  input.resume();
  input.setEncoding('utf8');

  return await new Promise((resolvePassword, rejectPassword) => {
    let password = '';
    function cleanup() {
      input.setRawMode(false);
      input.pause();
      input.off('data', onData);
      output.write('\n');
    }
    function onData(chunk) {
      if (chunk === '\u0003') {
        cleanup();
        rejectPassword(new Error('Password input cancelled'));
        return;
      }
      if (chunk === '\r' || chunk === '\n' || chunk === '\r\n') {
        cleanup();
        resolvePassword(password);
        return;
      }
      if (chunk === '\b' || chunk === '\u007f') {
        password = password.slice(0, -1);
        return;
      }
      password += chunk;
    }
    input.on('data', onData);
  });
}

async function commandInit(options) {
  const password = await readPassword(options);
  const keyring = createKeyring(password, { scryptN: Number(options['scrypt-n'] || DEFAULT_SCRYPT_N) });
  const outPath = options.keyring || options.out || 'keyring.hxdl.json';
  keyring.write(outPath);
  console.log(`Keyring written: ${outPath}`);
  console.log(`Write Key ID: ${keyring.keyId}`);
}

function commandExportPublic(options) {
  const document = exportPublicKeyDocument(loadKeyring(options.keyring || 'keyring.hxdl.json'));
  if (options.out) {
    document.write(options.out);
    console.log(`Public Key Document written: ${options.out}`);
  }
  console.log(`Write Key ID: ${document.keyId}`);
}

function commandLock(options) {
  if (!options.public || !options.in || !options.out) {
    throw new Error('lock requires --public, --in, and --out');
  }
  makeSenderDataLock(PublicKeyDocument.read(options.public), { expectedKeyId: options['expect-key-id'] }).lockFile(options.in, options.out);
  console.log(`Data Envelope written: ${options.out}`);
}

async function commandOpen(options) {
  if (!options.in || !options.out) {
    throw new Error('open requires --in and --out');
  }
  const user = makeUserDataLock(loadKeyring(options.keyring || 'keyring.hxdl.json'), {
    masterPassword: await readPassword(options),
  });
  user.openFile(options.in, options.out);
  console.log(`Plaintext written: ${options.out}`);
}

function commandVerifyKeyring(options) {
  const keyring = verifyKeyringFile(options.keyring || 'keyring.hxdl.json', { requireStableJson: true });
  console.log(`Valid Keyring: ${keyring.keyId}`);
}

function commandVerifyPublic(options) {
  if (!options.public) {
    throw new Error('verify-public requires --public');
  }
  const document = verifyPublicKeyDocumentFile(options.public, { requireStableJson: true });
  console.log(`Valid Public Key Document: ${document.keyId}`);
}

function emitMeasurement(operation, sizeBytes, elapsedMs) {
  console.log(JSON.stringify({ operation, sizeBytes, elapsedMs: Math.round(elapsedMs * 1000) / 1000 }));
}

async function commandBench(options) {
  const sizes = String(options.sizes || '1048576,10485760,26214400').split(',').map((item) => Number(item));
  const keyring = loadKeyring(options.keyring || 'keyring.hxdl.json');
  const started = performance.now();
  const user = makeUserDataLock(keyring, { masterPassword: await readPassword(options) });
  emitMeasurement('unlockKeyring', sizes[0], performance.now() - started);
  const tempDir = mkdtempSync(resolve(tmpdir(), 'hxdl-bench-'));
  try {
    for (const sizeBytes of sizes) {
      const payload = Buffer.alloc(sizeBytes, 0x78);
      let operationStarted = performance.now();
      const envelope = user.lockBytes(payload);
      emitMeasurement('lockBytes', sizeBytes, performance.now() - operationStarted);
      operationStarted = performance.now();
      user.openBytes(envelope);
      emitMeasurement('openBytes', sizeBytes, performance.now() - operationStarted);
      const inputPath = resolve(tempDir, `payload-${sizeBytes}.bin`);
      const envelopePath = resolve(tempDir, `payload-${sizeBytes}.hxdl.json`);
      const outputPath = resolve(tempDir, `opened-${sizeBytes}.bin`);
      writeFileSync(inputPath, payload);
      operationStarted = performance.now();
      user.lockFile(inputPath, envelopePath);
      emitMeasurement('lockFile', sizeBytes, performance.now() - operationStarted);
      operationStarted = performance.now();
      user.openFile(envelopePath, outputPath);
      emitMeasurement('openFile', sizeBytes, performance.now() - operationStarted);
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

export async function main(argv = process.argv.slice(2)) {
  const { command, options } = parseArgs(argv);
  switch (command) {
    case 'init':
      await commandInit(options);
      break;
    case 'export-public':
      commandExportPublic(options);
      break;
    case 'lock':
      commandLock(options);
      break;
    case 'open':
      await commandOpen(options);
      break;
    case 'verify-keyring':
      commandVerifyKeyring(options);
      break;
    case 'verify-public':
      commandVerifyPublic(options);
      break;
    case 'bench':
      await commandBench(options);
      break;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      usage();
      break;
    case 'public-key':
    case 'encrypt':
    case 'decrypt':
      throw new Error(`Legacy command ${command} is not part of the v1 CLI; use export-public, lock, or open`);
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

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
