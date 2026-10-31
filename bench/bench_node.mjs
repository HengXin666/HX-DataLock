// Run `npm run build` in sdk/node first. This script imports the compiled dist, which is gitignored.
import { performance } from 'node:perf_hooks';
import { createKeyring, makeUserDataLock } from '../sdk/node/dist/index.js';

const password = 'correct horse battery staple for hx datalock';
const sizes = process.argv.slice(2).map(Number);
const chosen = sizes.length ? sizes : [64 * 1024, 256 * 1024];
const keyring = createKeyring(password, { scryptN: 16384, allowLowScryptN: true });
const user = makeUserDataLock(keyring, { masterPassword: password });

function median(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

for (const size of chosen) {
  const payload = Buffer.alloc(size, size % 251);
  user.lockBytes(payload.subarray(0, 1024));
  const samples = [];
  for (let i = 0; i < 5; i += 1) {
    const envelope = user.lockBytes(payload);
    const started = performance.now();
    const opened = user.openBytes(envelope);
    samples.push(performance.now() - started);
    if (opened.length !== payload.length) throw new Error('openBytes mismatch');
  }
  console.log(`openBytes size=${size} median_ms=${median(samples).toFixed(2)} n=${samples.length}`);
}
