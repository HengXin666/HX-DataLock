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
import { ENVELOPE_ALG, ENVELOPE_SCHEMA, KEY_LENGTH, KEYRING_SCHEMA } from './constants.js';

export function b64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

export function fromB64(text, field, code: string = DataLockErrorCode.INVALID_KEYRING) {
  if (typeof text !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
    throw new DataLockError(code, `Missing or invalid base64 field: ${field}`);
  }
  return Buffer.from(text, 'base64');
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
  if (kdf?.name !== 'scrypt') {
    throw new DataLockError(
      DataLockErrorCode.UNSUPPORTED_ALGORITHM,
      `Unsupported password KDF: ${kdf?.name}`,
    );
  }
  return scryptSync(Buffer.from(password.normalize('NFC'), 'utf8'), fromB64(kdf.salt, 'encryptedReadKey.kdf.salt'), Number(kdf.keyLength || KEY_LENGTH), {
    N: Number(kdf.N),
    r: Number(kdf.r),
    p: Number(kdf.p),
    maxmem: Math.max(512 * 1024 * 1024, 256 * Number(kdf.N) * Number(kdf.r)),
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
  if (!Number.isInteger(value) || value < 2 ** 14 || (value & (value - 1)) !== 0) {
    throw new Error('scrypt_n must be a power of two and at least 16384');
  }
}

export function validatePublicWriteKey(raw, code) {
  if (!raw?.publicWriteKey || typeof raw.publicWriteKey !== 'object') {
    throw new DataLockError(code, 'Document must contain a public Write Key');
  }
  if (raw.publicWriteKey.alg !== 'X25519') {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'publicWriteKey must use X25519');
  }
  const publicDer = fromB64(raw.publicWriteKey.spki, 'publicWriteKey.spki', code);
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
