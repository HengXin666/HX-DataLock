import { createPrivateKey, type KeyObject } from 'node:crypto';
import { DataLockError, DataLockErrorCode } from './errors.js';
import { ENVELOPE_SCHEMA, KEYRING_SCHEMA, MAX_PUBLIC_KEY_JSON_BYTES, PUBLIC_KEY_SCHEMA } from './constants.js';
import {
  aadForKeyring,
  decryptAesGcm,
  derivePasswordKey,
  fromB64,
  requireCreationTime,
  requireEnvelopeAlg,
  validateEnvelopeFields,
  validateKeyringEncryptedReadKey,
  validatePublicWriteKey,
} from './crypto-codec.js';
import { readJson, writeJson } from './json.js';
import type { DecodedEnvelopeFields, EnvelopeInspection, EnvelopeJson, JsonObject, KeyringJson, PublicKeyDocumentJson } from './types.js';

export class Keyring {
  raw: KeyringJson;

  constructor(raw: KeyringJson) {
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
    requireCreationTime(this.raw, DataLockErrorCode.INVALID_KEYRING);
    validateKeyringEncryptedReadKey(this.raw.encryptedReadKey);
    validatePublicWriteKey(this.raw, DataLockErrorCode.INVALID_KEYRING);
  }
  toJSON() {
    return this.raw;
  }
  serialize() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  write(path: string) {
    writeJson(path, this.raw);
  }
  unwrapReadKey(masterPassword: string): KeyObject {
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
  raw: PublicKeyDocumentJson;

  constructor(raw: PublicKeyDocumentJson) {
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
    if ((this.raw.schema as string) === KEYRING_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Public Key Document must not be a full Keyring');
    }
    if (this.raw?.schema !== PUBLIC_KEY_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, `Unsupported Public Key Document schema: ${this.raw?.schema}`);
    }
    if ('encryptedReadKey' in this.raw) {
      throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Public Key Document must not contain encrypted Read Key material');
    }
    requireCreationTime(this.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT);
    validatePublicWriteKey(this.raw, DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT);
  }
  toJSON() {
    return this.raw;
  }
  serialize() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  write(path: string) {
    writeJson(path, this.raw);
  }
  static parse(text: string) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'Public Key Document JSON must be a string');
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (error) {
      throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Public Key Document JSON is not valid');
    }
    const document = new PublicKeyDocument(raw as PublicKeyDocumentJson);
    document.verify();
    return document;
  }
  static read(path: string) {
    const document = new PublicKeyDocument(readJson(path, MAX_PUBLIC_KEY_JSON_BYTES) as unknown as PublicKeyDocumentJson);
    document.verify();
    return document;
  }
}

export class DataEnvelope {
  raw: EnvelopeJson;
  decoded: DecodedEnvelopeFields | null;
  decodedCiphertext: string | undefined;

  constructor(raw: EnvelopeJson) {
    this.raw = raw;
    this.decoded = null;
    this.decodedCiphertext = undefined;
  }
  verify() {
    if (this.decoded && this.decodedCiphertext === this.raw?.ciphertext) return;
    this.decoded = null;
    if (this.raw?.schema !== ENVELOPE_SCHEMA) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, `Unsupported Data Envelope schema: ${this.raw?.schema}`);
    }
    requireEnvelopeAlg(this.raw);
    this.decoded = validateEnvelopeFields(this.raw);
    this.decodedCiphertext = this.raw?.ciphertext;
  }
  /** Object form so JSON.stringify(envelope) encodes the document once. */
  toJSON() {
    return this.raw;
  }
  serialize() {
    return `${JSON.stringify(this.raw, null, 2)}\n`;
  }
  inspect(): EnvelopeInspection {
    this.verify();
    return {
      schema: this.raw.schema,
      recipientKeyId: this.raw.recipientKeyId,
      createdAt: this.raw.createdAt,
      alg: { ...this.raw.alg },
      ciphertextBytes: this.decoded!.ciphertext.length,
    };
  }
  write(path: string) {
    writeJson(path, this.raw);
  }
  static parse(text: string) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'Data Envelope JSON must be a string');
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (error) {
      throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Data Envelope JSON is not valid');
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, 'JSON document must be an object');
    }
    const document = new DataEnvelope(raw as EnvelopeJson);
    document.verify();
    return document;
  }
  static read(path: string) {
    const document = new DataEnvelope(readJson(path) as unknown as EnvelopeJson);
    document.verify();
    return document;
  }
}
