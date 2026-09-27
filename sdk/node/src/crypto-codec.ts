import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { DataLockError, DataLockErrorCode } from './errors.js';
import {
  ENVELOPE_ALG,
  ENVELOPE_SCHEMA,
  KEY_LENGTH,
  KEYRING_SCHEMA,
  MAX_SCRYPT_N,
  MAX_SCRYPT_P,
  MAX_SCRYPT_R,
  MAX_V1_FILE_BYTES,
  MIN_SCRYPT_N,
} from './constants.js';

const X25519_SPKI_MAX_BYTES = 512;
const WRAPPED_READ_KEY_MAX_BYTES = 4096;

export function b64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

function maxB64Chars(maxBytes: number) {
  return Math.ceil(maxBytes / 3) * 4;
}

/**
 * Validate standard base64 without a backtracking regular expression.
 *
 * The previous pattern was anchored and nested, so V8 rejected it on
 * `RangeError: Maximum call stack size exceeded` once the subject reached about
 * 4.47M characters. A 25 MB payload encodes to roughly 33 MB of base64, so every
 * v1 file helper above ~3.2 MB threw inside the regex instead of round-tripping.
 * A linear scan has no such ceiling and matches the same language.
 */
function isStandardBase64(text: string): boolean {
  if (text.length === 0 || text.length % 4 !== 0) return false;
  // Padding may only be a trailing run of at most two '=' characters.
  let padding = 0;
  while (padding < 2 && text.charCodeAt(text.length - 1 - padding) === 61) {
    padding += 1;
  }
  const dataEnd = text.length - padding;
  if (padding === 2 && text.charCodeAt(dataEnd - 1) === 61) return false;
  for (let i = 0; i < dataEnd; i += 1) {
    const c = text.charCodeAt(i);
    const isAlpha = (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
    const isDigit = c >= 48 && c <= 57;
    if (!isAlpha && !isDigit && c !== 43 && c !== 47) return false;
  }
  return true;
}

export function fromB64(text, field, code: string = DataLockErrorCode.INVALID_KEYRING, options: any = {}) {
  if (typeof text !== 'string' || !isStandardBase64(text)) {
    throw new DataLockError(code, `Missing or invalid base64 field: ${field}`);
  }
  if (options.exactLength !== undefined && text.length > maxB64Chars(options.exactLength)) {
    throw new DataLockError(code, `Invalid binary length for field: ${field}`);
  }
  if (options.maxLength !== undefined && text.length > maxB64Chars(options.maxLength)) {
    throw new DataLockError(code, `Invalid binary length for field: ${field}`);
  }
  const decoded = Buffer.from(text, 'base64');
  if (options.exactLength !== undefined && decoded.length !== options.exactLength) {
    throw new DataLockError(code, `Invalid binary length for field: ${field}`);
  }
  if (options.maxLength !== undefined && decoded.length > options.maxLength) {
    throw new DataLockError(code, `Invalid binary length for field: ${field}`);
  }
  return decoded;
}

export function sha256Base64Url(buffer) {
  return createHash('sha256').update(buffer).digest('base64url');
}

export function utcNow() {
  return new Date().toISOString();
}

export function aadForKeyring(keyId) {
  return Buffer.from(`${KEYRING_SCHEMA}:${keyId}:scrypt:AES-256-GCM`, 'utf8');
}

export function aadForEnvelope(keyId, alg = ENVELOPE_ALG) {
  return Buffer.from(`${ENVELOPE_SCHEMA}:${keyId}:${alg.kem}:${alg.kdf}:${alg.aead}`, 'utf8');
}

export function requireEnvelopeAlg(raw) {
  // The declared algorithm object must be exactly the v1 triple. Checking only
  // the three known keys would let a document carry extra fields and still be
  // accepted here, while the AAD is built from whatever object was supplied:
  // that diverged from the Python SDK, which compares the whole object.
  const declared = raw?.alg;
  const matches =
    declared !== null &&
    typeof declared === 'object' &&
    !Array.isArray(declared) &&
    Object.keys(declared).length === 3 &&
    declared.kem === ENVELOPE_ALG.kem &&
    declared.kdf === ENVELOPE_ALG.kdf &&
    declared.aead === ENVELOPE_ALG.aead;
  if (!matches) {
    throw new DataLockError(
      DataLockErrorCode.UNSUPPORTED_ALGORITHM,
      'Data Envelope must use X25519, HKDF-SHA256, and AES-256-GCM',
    );
  }
}

export function derivePasswordKey(password, kdf) {
  validateScryptParams(kdf);
  return scryptSync(Buffer.from(password.normalize('NFC'), 'utf8'), fromB64(kdf.salt, 'encryptedReadKey.kdf.salt', DataLockErrorCode.INVALID_KEYRING, { exactLength: 32 }), kdf.keyLength, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: Math.max(512 * 1024 * 1024, 256 * kdf.N * kdf.r),
  });
}

export function encryptAesGcm(key, plaintext, aad) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };
}

export function decryptAesGcm(key, sealed, aad, code) {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.tag);
    return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
  } catch (error) {
    throw new DataLockError(code, 'Ciphertext authentication failed');
  }
}

export function validateScryptN(value) {
  if (!Number.isInteger(value) || value < MIN_SCRYPT_N || value > MAX_SCRYPT_N || (value & (value - 1)) !== 0) {
    throw new Error(`scrypt_n must be a power of two between ${MIN_SCRYPT_N} and ${MAX_SCRYPT_N}`);
  }
}

function requireInt(raw, field, code) {
  const value = raw?.[field];
  if (!Number.isInteger(value)) {
    throw new DataLockError(code, `Invalid scrypt parameter: ${field}`);
  }
  return value;
}

export function validateScryptParams(kdf, code = DataLockErrorCode.INVALID_KEYRING) {
  if (!kdf || typeof kdf !== 'object' || kdf.name !== 'scrypt') {
    throw new DataLockError(
      DataLockErrorCode.UNSUPPORTED_ALGORITHM,
      `Unsupported password KDF: ${kdf?.name}`,
    );
  }
  const n = requireInt(kdf, 'N', code);
  const r = requireInt(kdf, 'r', code);
  const p = requireInt(kdf, 'p', code);
  const keyLength = requireInt(kdf, 'keyLength', code);
  if (n < MIN_SCRYPT_N || n > MAX_SCRYPT_N || (n & (n - 1)) !== 0) {
    throw new DataLockError(code, 'Invalid scrypt N parameter');
  }
  if (r < 1 || r > MAX_SCRYPT_R) {
    throw new DataLockError(code, 'Invalid scrypt r parameter');
  }
  if (p < 1 || p > MAX_SCRYPT_P) {
    throw new DataLockError(code, 'Invalid scrypt p parameter');
  }
  if (keyLength !== KEY_LENGTH) {
    throw new DataLockError(code, 'Invalid scrypt keyLength parameter');
  }
  fromB64(kdf.salt, 'encryptedReadKey.kdf.salt', code, { exactLength: 32 });
}

export function validateKeyringEncryptedReadKey(encrypted) {
  if (!encrypted || typeof encrypted !== 'object') {
    throw new DataLockError(DataLockErrorCode.INVALID_KEYRING, 'Keyring must contain encrypted Read Key');
  }
  validateScryptParams(encrypted.kdf, DataLockErrorCode.INVALID_KEYRING);
  if (!encrypted.aead || typeof encrypted.aead !== 'object') {
    throw new DataLockError(DataLockErrorCode.INVALID_KEYRING, 'encryptedReadKey must contain AEAD metadata');
  }
  if (encrypted.aead.name !== 'AES-256-GCM') {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'encryptedReadKey must use AES-256-GCM');
  }
  fromB64(encrypted.aead.nonce, 'encryptedReadKey.aead.nonce', DataLockErrorCode.INVALID_KEYRING, { exactLength: 12 });
  fromB64(encrypted.aead.tag, 'encryptedReadKey.aead.tag', DataLockErrorCode.INVALID_KEYRING, { exactLength: 16 });
  fromB64(encrypted.ciphertext, 'encryptedReadKey.ciphertext', DataLockErrorCode.INVALID_KEYRING, { maxLength: WRAPPED_READ_KEY_MAX_BYTES });
}

export function validateEnvelopeFields(raw) {
  if (typeof raw?.recipientKeyId !== 'string' || raw.recipientKeyId.length === 0) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Data Envelope must contain recipientKeyId');
  }
  fromB64(raw.ephemeralPublicKey, 'ephemeralPublicKey', DataLockErrorCode.TAMPERED_ENVELOPE, { maxLength: X25519_SPKI_MAX_BYTES });
  fromB64(raw.hkdfSalt, 'hkdfSalt', DataLockErrorCode.TAMPERED_ENVELOPE, { exactLength: 32 });
  fromB64(raw.nonce, 'nonce', DataLockErrorCode.TAMPERED_ENVELOPE, { exactLength: 12 });
  fromB64(raw.tag, 'tag', DataLockErrorCode.TAMPERED_ENVELOPE, { exactLength: 16 });
  if (typeof raw.ciphertext !== 'string') {
    throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Missing or invalid base64 field: ciphertext');
  }
  if (raw.ciphertext.length > maxB64Chars(MAX_V1_FILE_BYTES)) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'Data Envelope ciphertext exceeds the v1 size limit');
  }
  const ciphertext = fromB64(raw.ciphertext, 'ciphertext', DataLockErrorCode.TAMPERED_ENVELOPE);
  if (ciphertext.length > MAX_V1_FILE_BYTES) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'Data Envelope ciphertext exceeds the v1 size limit');
  }
}

export function validatePublicWriteKey(raw, code) {
  if (!raw?.publicWriteKey || typeof raw.publicWriteKey !== 'object') {
    throw new DataLockError(code, 'Document must contain a public Write Key');
  }
  if (raw.publicWriteKey.alg !== 'X25519') {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'publicWriteKey must use X25519');
  }
  if (typeof raw.publicWriteKey.keyId !== 'string') {
    throw new DataLockError(code, 'publicWriteKey.keyId must be a string');
  }
  const publicDer = fromB64(raw.publicWriteKey.spki, 'publicWriteKey.spki', code, { maxLength: X25519_SPKI_MAX_BYTES });
  const expectedKeyId = `x25519:${sha256Base64Url(publicDer).slice(0, 22)}`;
  const actualKeyId = Buffer.from(String(raw.publicWriteKey.keyId));
  const expectedKeyIdBytes = Buffer.from(expectedKeyId);
  if (
    actualKeyId.length !== expectedKeyIdBytes.length ||
    !timingSafeEqual(actualKeyId, expectedKeyIdBytes)
  ) {
    throw new DataLockError(code, 'keyId does not match the Write Key');
  }
  try {
    return createPublicKey({ key: publicDer, format: 'der', type: 'spki' });
  } catch (error) {
    throw new DataLockError(code, 'Invalid public Write Key');
  }
}
