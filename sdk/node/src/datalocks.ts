import { createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DataLockError, DataLockErrorCode } from './errors.js';
import { ENVELOPE_ALG, ENVELOPE_SCHEMA, KEY_LENGTH, MAX_V1_FILE_BYTES } from './constants.js';
import { DataEnvelope } from './documents.js';
import { aadForEnvelope, b64, decryptAesGcm, encryptAesGcm, fromB64, utcNow } from './crypto-codec.js';

/**
 * Detect unpaired UTF-16 surrogates.
 *
 * Buffer.from(text, 'utf8') silently replaces them with U+FFFD, so the bytes
 * that get encrypted are not the bytes the caller passed. Python raises
 * INVALID_UTF8 in that case; without this check the two SDKs disagreed about
 * whether the same input is lockable at all.
 */
function hasLoneSurrogate(text) {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function readWithinV1Limit(inputPath) {
  // Check before reading so an oversized file is never pulled into memory.
  if (statSync(inputPath).size > MAX_V1_FILE_BYTES) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support local files up to 25 MB');
  }
  return readFileSync(inputPath);
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
  publicKeyDocument: any;

  constructor(publicKeyDocument) {
    this.publicKeyDocument = publicKeyDocument;
  }
  lockBytes(payloadBytes) {
    const bytes = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(payloadBytes);
    // Enforce the v1 limit here, not only in lockFile. Without it lockBytes can
    // produce a Full Data Envelope that every SDK then refuses to open, so the
    // SDK would emit documents it cannot read back.
    if (bytes.length > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support payloads up to 25 MB');
    }
    this.publicKeyDocument.verify();
    return lockBytesWithPublicKey(this.publicKeyDocument.keyId, this.publicKeyDocument.publicWriteKey, bytes);
  }
  lockText(text) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
    }
    if (hasLoneSurrogate(text)) {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Text is not valid UTF-8');
    }
    return this.lockBytes(Buffer.from(text, 'utf8'));
  }
  lockFile(inputPath, outputPath) {
    const envelope = this.lockBytes(readWithinV1Limit(inputPath));
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
        key: fromB64(dataEnvelope.raw.ephemeralPublicKey, 'ephemeralPublicKey', DataLockErrorCode.TAMPERED_ENVELOPE, { maxLength: 512 }),
        format: 'der',
        type: 'spki',
      });
    } catch (error) {
      if (error instanceof DataLockError) throw error;
      throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Invalid Data Envelope public key');
    }
    let sharedSecret;
    try {
      sharedSecret = diffieHellman({ privateKey: readKey, publicKey: ephemeralPublicKey });
    } catch (error) {
      // A low-order point makes OpenSSL refuse the exchange. Rethrowing a bare
      // ERR_OSSL_* error would bypass the stable error-code contract.
      throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Invalid Data Envelope public key');
    }
    const contentKey = Buffer.from(hkdfSync(
      'sha256',
      sharedSecret,
      fromB64(dataEnvelope.raw.hkdfSalt, 'hkdfSalt', DataLockErrorCode.TAMPERED_ENVELOPE, { exactLength: 32 }),
      Buffer.from(`${ENVELOPE_SCHEMA}:${this.keyring.keyId}`, 'utf8'),
      KEY_LENGTH,
    ));
    return decryptAesGcm(
      contentKey,
      {
        nonce: fromB64(dataEnvelope.raw.nonce, 'nonce', DataLockErrorCode.TAMPERED_ENVELOPE, { exactLength: 12 }),
        tag: fromB64(dataEnvelope.raw.tag, 'tag', DataLockErrorCode.TAMPERED_ENVELOPE, { exactLength: 16 }),
        ciphertext: fromB64(dataEnvelope.raw.ciphertext, 'ciphertext', DataLockErrorCode.TAMPERED_ENVELOPE),
      },
      aadForEnvelope(this.keyring.keyId, dataEnvelope.raw.alg),
      DataLockErrorCode.TAMPERED_ENVELOPE,
    );
  }
  openText(envelope) {
    // Decryption runs first so its failures keep their own error code; only a
    // decoding failure of successfully decrypted bytes is INVALID_UTF8.
    const bytes = this.openBytes(envelope);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Data Envelope payload is not valid UTF-8');
    }
  }
  openFile(inputPath, outputPath) {
    const plaintext = this.openBytes(DataEnvelope.read(inputPath));
    if (plaintext.length > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support local files up to 25 MB');
    }
    mkdirSync(dirname(resolve(outputPath)), { recursive: true });
    // writeFileSync only applies mode when creating, so an existing file with
    // looser permissions would silently stay readable. Converge like the
    // Keyring writer does.
    writeFileSync(outputPath, plaintext, { mode: 0o600 });
    if (process.platform !== 'win32') chmodSync(outputPath, 0o600);
    return plaintext;
  }
  lockBytes(payloadBytes) {
    this.requireOpenReadKey();
    const bytes = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(payloadBytes);
    if (bytes.length > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support payloads up to 25 MB');
    }
    this.keyring.verify();
    return lockBytesWithPublicKey(this.keyring.keyId, this.keyring.publicWriteKey, bytes);
  }
  lockText(text) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
    }
    if (hasLoneSurrogate(text)) {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Text is not valid UTF-8');
    }
    return this.lockBytes(Buffer.from(text, 'utf8'));
  }
  lockFile(inputPath, outputPath) {
    const envelope = this.lockBytes(readWithinV1Limit(inputPath));
    envelope.write(outputPath);
    return envelope;
  }
  close() {
    this.readKey = null;
  }
}
