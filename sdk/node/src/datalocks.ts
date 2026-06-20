import { createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DataLockError, DataLockErrorCode } from './errors.js';
import { ENVELOPE_ALG, ENVELOPE_SCHEMA, KEY_LENGTH, MAX_V1_FILE_BYTES } from './constants.js';
import { DataEnvelope } from './documents.js';
import { aadForEnvelope, b64, decryptAesGcm, encryptAesGcm, fromB64, utcNow } from './crypto-codec.js';

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
  publicKeyDocument: any;

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
  keyring: any;
  readKey: any;

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
