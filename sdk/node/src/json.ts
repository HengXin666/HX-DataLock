import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { MAX_ENVELOPE_JSON_BYTES } from './constants.js';
import { DataLockError, DataLockErrorCode } from './errors.js';

export function readJson(path, maxBytes = MAX_ENVELOPE_JSON_BYTES) {
  if (statSync(path).size > maxBytes) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'JSON document exceeds the v1 size limit');
  }
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, 'JSON document must be an object');
  }
  return raw;
}

export function writeJson(path, value) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
