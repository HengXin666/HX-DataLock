import { createPrivateKey } from 'node:crypto';
import { DataLockError, DataLockErrorCode } from './errors.js';
import { ENVELOPE_SCHEMA, KEYRING_SCHEMA, MAX_PUBLIC_KEY_JSON_BYTES, PUBLIC_KEY_SCHEMA } from './constants.js';
import {
  aadForKeyring,
  decryptAesGcm,
  derivePasswordKey,
  fromB64,
  requireEnvelopeAlg,
  validateEnvelopeFields,
  validateKeyringEncryptedReadKey,
  validatePublicWriteKey,
} from './crypto-codec.js';
import { readJson, writeJson } from './json.js';

export class Keyring {
  raw: any;

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
    validateKeyringEncryptedReadKey(this.raw.encryptedReadKey);
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
        nonce: fromB64(encrypted.aead.nonce, 'encryptedReadKey.aead.nonce', DataLockErrorCode.INVALID_KEYRING, { exactLength: 12 }),
        tag: fromB64(encrypted.aead.tag, 'encryptedReadKey.aead.tag', DataLockErrorCode.INVALID_KEYRING, { exactLength: 16 }),
        ciphertext: fromB64(encrypted.ciphertext, 'encryptedReadKey.ciphertext', DataLockErrorCode.INVALID_KEYRING, { maxLength: 4096 }),
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
  raw: any;

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
    const document = new PublicKeyDocument(readJson(path, MAX_PUBLIC_KEY_JSON_BYTES));
    document.verify();
    return document;
  }
}

export class DataEnvelope {
  raw: any;

  constructor(raw) {
    this.raw = raw;
  }
  verify() {
    if (this.raw?.schema !== ENVELOPE_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, `Unsupported Data Envelope schema: ${this.raw?.schema}`);
    }
    requireEnvelopeAlg(this.raw);
    validateEnvelopeFields(this.raw);
  }
  toJSON() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  write(path) {
    writeJson(path, this.raw);
  }
  static read(path) {
    const document = new DataEnvelope(readJson(path));
    document.verify();
    return document;
  }
}
