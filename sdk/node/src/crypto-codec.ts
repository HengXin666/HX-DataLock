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

export function fromB64(text, field, code: string = DataLockErrorCode.INVALID_KEYRING, options: any = {}) {
  if (typeof text !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
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
  if (
    raw.alg?.kem !== ENVELOPE_ALG.kem ||
    raw.alg?.kdf !== ENVELOPE_ALG.kdf ||
    raw.alg?.aead !== ENVELOPE_ALG.aead
  ) {
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
