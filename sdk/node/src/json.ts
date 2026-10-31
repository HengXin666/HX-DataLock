import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { MAX_ENVELOPE_JSON_BYTES } from './constants.js';
import { DataLockError, DataLockErrorCode } from './errors.js';
import type { JsonObject, JsonValue } from './types.js';

export function readJson(path: string, maxBytes = MAX_ENVELOPE_JSON_BYTES): JsonObject {
  if (statSync(path).size > maxBytes) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'JSON document exceeds the v1 size limit');
  }
  const raw: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, 'JSON document must be an object');
  }
  return raw as JsonObject;
}

export function writeJson(path: string, value: JsonValue | object) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  // writeFileSync only applies mode at creation, so an existing file with looser
  // permissions would keep them. Converge explicitly.
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  if (process.platform !== 'win32') chmodSync(path, 0o600);
}

export function isStableJson(path: string, value: JsonValue | object) {
  return readFileSync(path, 'utf8') === `${JSON.stringify(value, null, 2)}\n`;
}
