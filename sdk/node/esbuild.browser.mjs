import { build } from 'esbuild';

await build({
  entryPoints: ['src/browser.ts'],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  outfile: 'dist/browser.bundle.js',
  sourcemap: true,
});
