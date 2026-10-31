import { createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DataLockError, DataLockErrorCode } from './errors.js';
import { ENVELOPE_ALG, ENVELOPE_SCHEMA, KEY_LENGTH, MAX_V1_FILE_BYTES } from './constants.js';
import { DataEnvelope } from './documents.js';
import { aadForEnvelope, b64, decryptAesGcm, encryptAesGcm, utcNow } from './crypto-codec.js';
import { lockStream, openStream } from './stream.js';

/**
 * Detect unpaired UTF-16 surrogates.
 *
 * Buffer.from(text, 'utf8') silently replaces them with U+FFFD, so the bytes
 * that get encrypted are not the bytes the caller passed. Python raises
 * INVALID_UTF8 in that case; without this check the two SDKs disagreed about
 * whether the same input is lockable at all.
 */
function hasLoneSurrogate(text: any) {
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

function asPayloadBytes(payloadBytes: any) {
  if (typeof payloadBytes === 'string') {
    throw new DataLockError(
      DataLockErrorCode.INVALID_ARGUMENT,
      'lockBytes requires Buffer or Uint8Array, not a string; use lockText for text',
    );
  }
  if (Buffer.isBuffer(payloadBytes)) return payloadBytes;
  if (payloadBytes instanceof Uint8Array) return Buffer.from(payloadBytes);
  throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'lockBytes requires Buffer or Uint8Array');
}

function readWithinV1Limit(inputPath: any) {
  // Check before reading so an oversized file is never pulled into memory.
  if (statSync(inputPath).size > MAX_V1_FILE_BYTES) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support local files up to 25 MB');
  }
  return readFileSync(inputPath);
}

function lockBytesWithPublicKey(keyId: any, publicWriteKey: any, payloadBytes: any) {
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

  constructor(publicKeyDocument: any) {
    this.publicKeyDocument = publicKeyDocument;
  }
  lockBytes(payloadBytes: any) {
    const bytes = asPayloadBytes(payloadBytes);
    // Enforce the v1 limit here, not only in lockFile. Without it lockBytes can
    // produce a Full Data Envelope that every SDK then refuses to open, so the
    // SDK would emit documents it cannot read back.
    if (bytes.length > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support payloads up to 25 MB');
    }
    this.publicKeyDocument.verify();
    return lockBytesWithPublicKey(this.publicKeyDocument.keyId, this.publicKeyDocument.publicWriteKey, bytes);
  }
  lockText(text: any) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
    }
    if (hasLoneSurrogate(text)) {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Text is not valid UTF-8');
    }
    return this.lockBytes(Buffer.from(text, 'utf8'));
  }
  lockFile(inputPath: any, outputPath: any) {
    const envelope = this.lockBytes(readWithinV1Limit(inputPath));
    envelope.write(outputPath);
    return envelope;
  }
  lockStream(src: any, dst: any, options: any = {}) {
    this.publicKeyDocument.verify();
    return lockStream({
      keyId: this.publicKeyDocument.keyId,
      publicKey: this.publicKeyDocument.publicWriteKey,
      src,
      dst,
      chunkSize: options.chunkSize,
      fileId: options.fileId,
      chunkIndex: options.chunkIndex,
    });
  }
}

export class UserDataLock {
  keyring: any;
  readKey: any;

  constructor(keyring: any, readKey: any) {
    this.keyring = keyring;
    this.readKey = readKey;
  }
  requireOpenReadKey() {
    if (!this.readKey) {
      throw new DataLockError(DataLockErrorCode.DATALOCK_CLOSED, 'User DataLock is closed');
    }
    return this.readKey;
  }
  openBytes(envelope: any) {
    const readKey = this.requireOpenReadKey();
    this.keyring.verify();
    const dataEnvelope = envelope instanceof DataEnvelope ? envelope : new DataEnvelope(envelope);
    dataEnvelope.verify();
    if (dataEnvelope.raw.recipientKeyId !== this.keyring.keyId) {
      throw new DataLockError(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, 'Data Envelope recipient does not match the Keyring');
    }
    const decoded = dataEnvelope.decoded;
    let ephemeralPublicKey;
    try {
      ephemeralPublicKey = createPublicKey({
        key: decoded.ephemeralPublicKey,
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
      decoded.hkdfSalt,
      Buffer.from(`${ENVELOPE_SCHEMA}:${this.keyring.keyId}`, 'utf8'),
      KEY_LENGTH,
    ));
    return decryptAesGcm(
      contentKey,
      {
        nonce: decoded.nonce,
        tag: decoded.tag,
        ciphertext: decoded.ciphertext,
      },
      aadForEnvelope(this.keyring.keyId, dataEnvelope.raw.alg),
      DataLockErrorCode.TAMPERED_ENVELOPE,
    );
  }
  openText(envelope: any) {
    // Decryption runs first so its failures keep their own error code; only a
    // decoding failure of successfully decrypted bytes is INVALID_UTF8.
    const bytes = this.openBytes(envelope);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Data Envelope payload is not valid UTF-8');
    }
  }
  openFile(inputPath: any, outputPath: any) {
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
  lockBytes(payloadBytes: any) {
    this.requireOpenReadKey();
    const bytes = asPayloadBytes(payloadBytes);
    if (bytes.length > MAX_V1_FILE_BYTES) {
      throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support payloads up to 25 MB');
    }
    this.keyring.verify();
    return lockBytesWithPublicKey(this.keyring.keyId, this.keyring.publicWriteKey, bytes);
  }
  lockText(text: any) {
    if (typeof text !== 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
    }
    if (hasLoneSurrogate(text)) {
      throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Text is not valid UTF-8');
    }
    return this.lockBytes(Buffer.from(text, 'utf8'));
  }
  lockFile(inputPath: any, outputPath: any) {
    const envelope = this.lockBytes(readWithinV1Limit(inputPath));
    envelope.write(outputPath);
    return envelope;
  }
  lockStream(src: any, dst: any, options: any = {}) {
    this.requireOpenReadKey();
    this.keyring.verify();
    return lockStream({
      keyId: this.keyring.keyId,
      publicKey: this.keyring.publicWriteKey,
      src,
      dst,
      chunkSize: options.chunkSize,
      fileId: options.fileId,
      chunkIndex: options.chunkIndex,
    });
  }
  openStream(src: any, dst: any) {
    const readKey = this.requireOpenReadKey();
    this.keyring.verify();
    const recipientSpki = this.keyring.publicWriteKey.export({ format: 'der', type: 'spki' });
    return openStream({
      keyId: this.keyring.keyId,
      readKey,
      recipientSpki,
      src,
      dst,
    });
  }
  close() {
    this.readKey = null;
  }
}
