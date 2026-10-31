import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  exportPublicKeyDocument,
  loadKeyring,
  makeSenderDataLock,
  makeUserDataLock,
} from '../../sdk/node/dist/index.js';

const [command, ...rest] = process.argv.slice(2);

function cursor(bytes) {
  return {
    offset: 0,
    read(n) {
      const slice = bytes.subarray(this.offset, this.offset + n);
      this.offset += slice.length;
      return Buffer.from(slice);
    },
  };
}

if (command === 'open') {
  const [keyringPath, manifestPath, chunkDir, outPath] = rest;
  const password = process.env.HXDL_TEST_PASSWORD;
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const chunks = manifest.chunks.map((_, index) => readFileSync(resolve(chunkDir, `chunk-${index}.bin`)));
  const user = makeUserDataLock(loadKeyring(keyringPath), password);
  const opened = user.openChunked(manifest, chunks);
  writeFileSync(outPath, opened.plaintext);
} else if (command === 'seal') {
  const [keyringPath, inputPath, chunkSize, fileId, outDir] = rest;
  const keyring = loadKeyring(keyringPath);
  const sender = makeSenderDataLock(exportPublicKeyDocument(keyring), { expectedKeyId: keyring.keyId });
  const plaintext = readFileSync(inputPath);
  const sealed = sender.sealChunked(cursor(plaintext), { chunkSize: Number(chunkSize), fileId });
  writeFileSync(resolve(outDir, 'manifest.json'), `${JSON.stringify(sealed.manifest, null, 2)}\n`);
  sealed.chunks.forEach((chunk, index) => writeFileSync(resolve(outDir, `chunk-${index}.bin`), chunk));
} else {
  console.error('usage: manifest_tool.mjs open|seal ...');
  process.exit(2);
}

void readdirSync;
