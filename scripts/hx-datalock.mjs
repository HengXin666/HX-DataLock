#!/usr/bin/env node
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stdin as input, stdout as output } from 'node:process';

export const KEYRING_SCHEMA = 'hxdl.keyring.v1';
export const PUBLIC_KEY_SCHEMA = 'hxdl.publicKey.v1';
export const ENVELOPE_SCHEMA = 'hxdl.envelope.v1';
export const DEFAULT_SCRYPT_N = 2 ** 18;
export const DEFAULT_SCRYPT_R = 8;
export const DEFAULT_SCRYPT_P = 1;
export const KEY_LENGTH = 32;
export const MAX_V1_FILE_BYTES = 25 * 1024 * 1024;
export const ENVELOPE_ALG = {
  kem: 'X25519',
  kdf: 'HKDF-SHA256',
  aead: 'AES-256-GCM',
};

export const DataLockErrorCode = Object.freeze({
  INVALID_KEYRING: 'INVALID_KEYRING',
  INVALID_PUBLIC_KEY_DOCUMENT: 'INVALID_PUBLIC_KEY_DOCUMENT',
  WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING: 'WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING',
  ENVELOPE_RECIPIENT_MISMATCH: 'ENVELOPE_RECIPIENT_MISMATCH',
  TAMPERED_ENVELOPE: 'TAMPERED_ENVELOPE',
  UNSUPPORTED_SCHEMA: 'UNSUPPORTED_SCHEMA',
  OVERSIZED_FILE: 'OVERSIZED_FILE',
  INVALID_UTF8: 'INVALID_UTF8',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
});

export class DataLockError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DataLockError';
    this.code = code;
  }
}

function usage() {
  console.log(`HX-DataLock

Usage:
  node scripts/hx-datalock.mjs init [--keyring keyring.hxdl.json] [--password-env NAME] [--scrypt-n N]
  node scripts/hx-datalock.mjs export-public [--keyring keyring.hxdl.json] [--out public.hxdl.json]
  node scripts/hx-datalock.mjs lock --public public.hxdl.json --in plain.bin --out sealed.hxdl.json
  node scripts/hx-datalock.mjs open --keyring keyring.hxdl.json --in sealed.hxdl.json --out plain.bin [--password-env NAME]
  node scripts/hx-datalock.mjs verify-keyring [--keyring keyring.hxdl.json]
  node scripts/hx-datalock.mjs verify-public --public public.hxdl.json
  node scripts/hx-datalock.mjs bench [--keyring keyring.hxdl.json] [--password-env NAME] [--sizes 1048576,10485760,26214400]
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

function b64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

function fromB64(text, field, code = DataLockErrorCode.INVALID_KEYRING) {
  if (typeof text !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
    throw new DataLockError(code, `Missing or invalid base64 field: ${field}`);
  }
  return Buffer.from(text, 'base64');
}

function sha256Base64Url(buffer) {
  return createHash('sha256').update(buffer).digest('base64url');
}

function utcNow() {
  return new Date().toISOString();
}

function aadForKeyring(keyId) {
  return Buffer.from(`${KEYRING_SCHEMA}:${keyId}:scrypt:AES-256-GCM`, 'utf8');
}

function aadForEnvelope(keyId, alg = ENVELOPE_ALG) {
  return Buffer.from(`${ENVELOPE_SCHEMA}:${keyId}:${alg.kem}:${alg.kdf}:${alg.aead}`, 'utf8');
}

function requireEnvelopeAlg(raw) {
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

function derivePasswordKey(password, kdf) {
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

function encryptAesGcm(key, plaintext, aad) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };
}

function decryptAesGcm(key, sealed, aad, code) {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.tag);
    return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
  } catch (error) {
    throw new DataLockError(code, 'Ciphertext authentication failed');
  }
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function validateScryptN(value) {
  if (!Number.isInteger(value) || value < 2 ** 14 || (value & (value - 1)) !== 0) {
    throw new Error('scrypt_n must be a power of two and at least 16384');
  }
}

function validatePublicWriteKey(raw, code) {
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

export function checkPasswordStrength(masterPassword) {
  const uniqueChars = new Set(masterPassword).size;
  const warnings = [];
  const suggestions = [];
  const common = new Set(['password', '123456', 'qwerty', 'admin', 'letmein']);
  if (masterPassword.length < 12) {
    warnings.push('Master Password is short.');
    suggestions.push('Use a longer passphrase.');
  }
  if (common.has(masterPassword.toLowerCase())) {
    warnings.push('Master Password is a commonly used password.');
    suggestions.push('Avoid common passwords.');
  }
  if (uniqueChars <= 4 && masterPassword.length >= 8) {
    warnings.push('Master Password uses too little character variety.');
    suggestions.push('Use several unrelated words or more varied characters.');
  }
  let level = 'fair';
  if (warnings.length) {
    level = 'weak';
  } else if (masterPassword.length >= 32 && uniqueChars >= 12) {
    level = 'strong';
  } else if (masterPassword.length >= 20 && uniqueChars >= 10) {
    level = 'good';
  }
  return {
    level,
    allowed: true,
    warnings,
    suggestions,
    estimatedEntropyBits: Math.min(128, Math.round((masterPassword.length * 3 + uniqueChars * 1.5) * 10) / 10),
  };
}

export class Keyring {
  constructor(raw) {
    this.raw = raw;
  }
  get keyId() {
    return this.raw.publicWriteKey.keyId;
  }
  get key_id() {
    return this.keyId;
  }
  get publicWriteKey() {
    return validatePublicWriteKey(this.raw, DataLockErrorCode.INVALID_KEYRING);
  }
  verify() {
    if (this.raw?.schema !== KEYRING_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, `Unsupported Keyring schema: ${this.raw?.schema}`);
    }
    if (!this.raw.encryptedReadKey) {
      throw new DataLockError(DataLockErrorCode.INVALID_KEYRING, 'Keyring must contain encrypted Read Key');
    }
    if (this.raw.encryptedReadKey.kdf?.name !== 'scrypt') {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, `Unsupported password KDF: ${this.raw.encryptedReadKey.kdf?.name}`);
    }
    if (this.raw.encryptedReadKey.aead?.name !== 'AES-256-GCM') {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'encryptedReadKey must use AES-256-GCM');
    }
    validatePublicWriteKey(this.raw, DataLockErrorCode.INVALID_KEYRING);
  }
  toJSON() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  write(path) {
    writeJson(path, this.raw);
  }
  unwrapReadKey(masterPassword) {
    this.verify();
    const encrypted = this.raw.encryptedReadKey;
    const wrappingKey = derivePasswordKey(masterPassword, encrypted.kdf);
    const privateDer = decryptAesGcm(
      wrappingKey,
      {
        nonce: fromB64(encrypted.aead.nonce, 'encryptedReadKey.aead.nonce'),
        tag: fromB64(encrypted.aead.tag, 'encryptedReadKey.aead.tag'),
        ciphertext: fromB64(encrypted.ciphertext, 'encryptedReadKey.ciphertext'),
      },
      aadForKeyring(this.keyId),
      DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
    );
    try {
      return createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' });
    } catch (error) {
      throw new DataLockError(DataLockErrorCode.INVALID_KEYRING, 'Unwrapped Read Key is not an X25519 private key');
    }
  }
}

export class PublicKeyDocument {
  constructor(raw) {
    this.raw = raw;
  }
  get keyId() {
    return this.raw.publicWriteKey.keyId;
  }
  get key_id() {
    return this.keyId;
  }
  get publicWriteKey() {
    return validatePublicWriteKey(this.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT);
  }
  verify() {
    if (this.raw?.schema !== PUBLIC_KEY_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, `Unsupported Public Key Document schema: ${this.raw?.schema}`);
    }
    if ('encryptedReadKey' in this.raw) {
      throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Public Key Document must not contain encrypted Read Key material');
    }
    validatePublicWriteKey(this.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT);
  }
  toJSON() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  write(path) {
    writeJson(path, this.raw);
  }
  static read(path) {
    const document = new PublicKeyDocument(readJson(path));
    document.verify();
    return document;
  }
}

export class DataEnvelope {
  constructor(raw) {
    this.raw = raw;
  }
  verify() {
    if (this.raw?.schema !== ENVELOPE_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, `Unsupported Data Envelope schema: ${this.raw?.schema}`);
    }
    requireEnvelopeAlg(this.raw);
  }
  toJSON() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  write(path) {
    writeJson(path, this.raw);
  }
  static read(path) {
    return new DataEnvelope(readJson(path));
  }
}

function lockBytesWithPublicKey(keyId, publicWriteKey, payloadBytes) {
  const ephemeral = generateKeyPairSync('x25519');
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: publicWriteKey,
  });
  const hkdfSalt = randomBytes(32);
  const contentKey = Buffer.from(hkdfSync(
    'sha256',
    sharedSecret,
    hkdfSalt,
    Buffer.from(`${ENVELOPE_SCHEMA}:${keyId}`, 'utf8'),
    KEY_LENGTH,
  ));
  const sealed = encryptAesGcm(contentKey, payloadBytes, aadForEnvelope(keyId));
  return new DataEnvelope({
    schema: ENVELOPE_SCHEMA,
    createdAt: utcNow(),
    recipientKeyId: keyId,
    alg: { ...ENVELOPE_ALG },
    ephemeralPublicKey: b64(ephemeral.publicKey.export({ format: 'der', type: 'spki' })),
    hkdfSalt: b64(hkdfSalt),
    nonce: b64(sealed.nonce),
    tag: b64(sealed.tag),
    ciphertext: b64(sealed.ciphertext),
  });
}

export class SenderDataLock {
  constructor(publicKeyDocument) {
    this.publicKeyDocument = publicKeyDocument;
  }
  lockBytes(payloadBytes) {
    const bytes = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(payloadBytes);
    this.publicKeyDocument.verify();
    return lockBytesWithPublicKey(this.publicKeyDocument.keyId, this.publicKeyDocument.publicWriteKey, bytes);
  }
  lockText(text) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
    }
    return this.lockBytes(Buffer.from(text, 'utf8'));
  }
  lockFile(inputPath, outputPath) {
    if (statSync(inputPath).size > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support local files up to 25 MB');
    }
    const envelope = this.lockBytes(readFileSync(inputPath));
    envelope.write(outputPath);
    return envelope;
  }
}

export class UserDataLock {
  constructor(keyring, readKey) {
    this.keyring = keyring;
    this.readKey = readKey;
  }
  requireOpenReadKey() {
    if (!this.readKey) {
      throw new DataLockError(DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING, 'User DataLock is closed');
    }
    return this.readKey;
  }
  openBytes(envelope) {
    const readKey = this.requireOpenReadKey();
    this.keyring.verify();
    const dataEnvelope = envelope instanceof DataEnvelope ? envelope : new DataEnvelope(envelope);
    dataEnvelope.verify();
    if (dataEnvelope.raw.recipientKeyId !== this.keyring.keyId) {
      throw new DataLockError(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, 'Data Envelope recipient does not match the Keyring');
    }
    let ephemeralPublicKey;
    try {
      ephemeralPublicKey = createPublicKey({
        key: fromB64(dataEnvelope.raw.ephemeralPublicKey, 'ephemeralPublicKey', DataLockErrorCode.TAMPERED_ENVELOPE),
        format: 'der',
        type: 'spki',
      });
    } catch (error) {
      if (error instanceof DataLockError) throw error;
      throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Invalid Data Envelope public key');
    }
    const sharedSecret = diffieHellman({ privateKey: readKey, publicKey: ephemeralPublicKey });
    const contentKey = Buffer.from(hkdfSync(
      'sha256',
      sharedSecret,
      fromB64(dataEnvelope.raw.hkdfSalt, 'hkdfSalt', DataLockErrorCode.TAMPERED_ENVELOPE),
      Buffer.from(`${ENVELOPE_SCHEMA}:${this.keyring.keyId}`, 'utf8'),
      KEY_LENGTH,
    ));
    return decryptAesGcm(
      contentKey,
      {
        nonce: fromB64(dataEnvelope.raw.nonce, 'nonce', DataLockErrorCode.TAMPERED_ENVELOPE),
        tag: fromB64(dataEnvelope.raw.tag, 'tag', DataLockErrorCode.TAMPERED_ENVELOPE),
        ciphertext: fromB64(dataEnvelope.raw.ciphertext, 'ciphertext', DataLockErrorCode.TAMPERED_ENVELOPE),
      },
      aadForEnvelope(this.keyring.keyId, dataEnvelope.raw.alg),
      DataLockErrorCode.TAMPERED_ENVELOPE,
    );
  }
  openText(envelope) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(this.openBytes(envelope));
    } catch (error) {
      if (error instanceof DataLockError) throw error;
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Data Envelope payload is not valid UTF-8');
    }
  }
  openFile(inputPath, outputPath) {
    const plaintext = this.openBytes(DataEnvelope.read(inputPath));
    if (plaintext.length > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support local files up to 25 MB');
    }
    mkdirSync(dirname(resolve(outputPath)), { recursive: true });
    writeFileSync(outputPath, plaintext, { mode: 0o600 });
    return plaintext;
  }
  lockBytes(payloadBytes) {
    this.requireOpenReadKey();
    const bytes = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(payloadBytes);
    this.keyring.verify();
    return lockBytesWithPublicKey(this.keyring.keyId, this.keyring.publicWriteKey, bytes);
  }
  lockText(text) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
    }
    return this.lockBytes(Buffer.from(text, 'utf8'));
  }
  lockFile(inputPath, outputPath) {
    if (statSync(inputPath).size > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support local files up to 25 MB');
    }
    const envelope = this.lockBytes(readFileSync(inputPath));
    envelope.write(outputPath);
    return envelope;
  }
  close() {
    this.readKey = null;
  }
}

export function createKeyring(masterPassword, options = {}) {
  checkPasswordStrength(masterPassword);
  const scryptN = Number(options.scryptN || options.scrypt_n || DEFAULT_SCRYPT_N);
  validateScryptN(scryptN);
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const keyId = `x25519:${sha256Base64Url(publicDer).slice(0, 22)}`;
  const kdf = {
    name: 'scrypt',
    salt: b64(randomBytes(32)),
    N: scryptN,
    r: DEFAULT_SCRYPT_R,
    p: DEFAULT_SCRYPT_P,
    keyLength: KEY_LENGTH,
  };
  const wrappingKey = derivePasswordKey(masterPassword, kdf);
  const sealed = encryptAesGcm(wrappingKey, privateDer, aadForKeyring(keyId));
  const keyring = new Keyring({
    schema: KEYRING_SCHEMA,
    createdAt: utcNow(),
    publicWriteKey: {
      alg: 'X25519',
      keyId,
      spki: b64(publicDer),
    },
    encryptedReadKey: {
      kdf,
      aead: {
        name: 'AES-256-GCM',
        nonce: b64(sealed.nonce),
        tag: b64(sealed.tag),
      },
      ciphertext: b64(sealed.ciphertext),
    },
  });
  keyring.verify();
  return keyring;
}

export const create_keyring = createKeyring;

export function loadKeyring(path) {
  const keyring = new Keyring(readJson(path));
  keyring.verify();
  return keyring;
}

export function exportPublicKeyDocument(keyring) {
  const fullKeyring = keyring instanceof Keyring ? keyring : new Keyring(keyring);
  fullKeyring.verify();
  const document = new PublicKeyDocument({
    schema: PUBLIC_KEY_SCHEMA,
    createdAt: utcNow(),
    publicWriteKey: { ...fullKeyring.raw.publicWriteKey },
  });
  document.verify();
  return document;
}

export function makeSenderDataLock(publicKeyDocument) {
  if (publicKeyDocument instanceof Keyring || publicKeyDocument?.schema === KEYRING_SCHEMA || publicKeyDocument?.raw?.schema === KEYRING_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Sender DataLock requires a Public Key Document, not a full Keyring');
  }
  const document = publicKeyDocument instanceof PublicKeyDocument ? publicKeyDocument : new PublicKeyDocument(publicKeyDocument);
  document.verify();
  return new SenderDataLock(document);
}

export function makeUserDataLock(keyring, options) {
  const fullKeyring = keyring instanceof Keyring ? keyring : new Keyring(keyring);
  if (!options || typeof options.masterPassword !== 'string') {
    throw new DataLockError(DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING, 'User DataLock requires a Master Password');
  }
  return new UserDataLock(fullKeyring, fullKeyring.unwrapReadKey(options.masterPassword));
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
  const rawPublic = readJson(options.public);
  if (rawPublic.schema === KEYRING_SCHEMA) {
    throw new DataLockError(
      DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
      'lock requires a Public Key Document, not a full Keyring',
    );
  }
  makeSenderDataLock(new PublicKeyDocument(rawPublic)).lockFile(options.in, options.out);
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
  const keyring = loadKeyring(options.keyring || 'keyring.hxdl.json');
  console.log(`Valid Keyring: ${keyring.keyId}`);
}

function commandVerifyPublic(options) {
  if (!options.public) {
    throw new Error('verify-public requires --public');
  }
  const document = PublicKeyDocument.read(options.public);
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
