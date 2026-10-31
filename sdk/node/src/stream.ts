import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import {
  DEFAULT_STREAM_CHUNK_SIZE,
  ENVELOPE_ALG,
  KEY_LENGTH,
  MANIFEST_SCHEMA,
  MAX_STREAM_CHUNK_SIZE,
  MAX_STREAM_HEADER_BYTES,
  MIN_STREAM_CHUNK_SIZE,
  STREAM_SCHEMA,
} from './constants.js';
import { DataLockError, DataLockErrorCode } from './errors.js';
import { b64, fromB64, sha256Base64Url } from './crypto-codec.js';

const STREAM_MAGIC = Buffer.from('HXDL');

function requireChunkSize(chunkSize: any) {
  if (!Number.isInteger(chunkSize) || chunkSize < MIN_STREAM_CHUNK_SIZE || chunkSize > MAX_STREAM_CHUNK_SIZE) {
    throw new DataLockError(
      DataLockErrorCode.INVALID_ARGUMENT,
      `chunk_size must be an integer from ${MIN_STREAM_CHUNK_SIZE} to ${MAX_STREAM_CHUNK_SIZE}`,
    );
  }
  return chunkSize;
}

export function streamNonce(index: any, isLast: any) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(index), 0);
  nonce[11] = isLast ? 1 : 0;
  return nonce;
}

function streamAad(keyId: any, chunkSize: any, index: any, isLast: any, headerSha: any) {
  const flag = isLast ? '1' : '0';
  return Buffer.from(
    `${STREAM_SCHEMA}:${keyId}:X25519:HKDF-SHA256:AES-256-GCM:${chunkSize}:${index}:${flag}:${headerSha}`,
    'utf8',
  );
}

function contentKey(sharedSecret: any, hkdfSalt: any, keyId: any, recipientSpki: any) {
  const info = Buffer.concat([
    Buffer.from(`hxdl.stream.v1:${keyId}:`, 'utf8'),
    createHash('sha256').update(recipientSpki).digest(),
  ]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, hkdfSalt, info, KEY_LENGTH));
}

function sealChunk(key: any, nonce: any, plaintext: any, aad: any) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function openChunk(key: any, nonce: any, body: any, aad: any) {
  const tag = body.subarray(body.length - 16);
  const ciphertext = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function readExact(src: any, size: any, what: any) {
  const data = src.read(size);
  if (!data || data.length !== size) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, `stream ended inside ${what}`);
  }
  return data;
}

export function lockStreamBytes({ keyId, publicKey, plaintext, chunkSize = DEFAULT_STREAM_CHUNK_SIZE, fileId = undefined, chunkIndex = undefined }: any) {
  const src = { offset: 0, read(n: any) {
    const slice = plaintext.subarray(this.offset, this.offset + n);
    this.offset += slice.length;
    return Buffer.from(slice);
  } };
  const parts: Buffer[] = [];
  const info = lockStream({
    keyId,
    publicKey,
    src,
    dst: { write(buf: any) { parts.push(Buffer.from(buf)); } },
    chunkSize,
    fileId,
    chunkIndex,
  });
  return { bytes: Buffer.concat(parts), info };
}

export function lockStream({ keyId, publicKey, src, dst, chunkSize = DEFAULT_STREAM_CHUNK_SIZE, fileId = undefined, chunkIndex = undefined }: any) {
  chunkSize = requireChunkSize(chunkSize);
  const recipientSpki = publicKey.export({ format: 'der', type: 'spki' });
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralSpki = ephemeral.publicKey.export({ format: 'der', type: 'spki' });
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey });
  const hkdfSalt = randomBytes(32);
  const key = contentKey(shared, hkdfSalt, keyId, recipientSpki);
  const header: any = {
    schema: STREAM_SCHEMA,
    recipientKeyId: keyId,
    alg: { ...ENVELOPE_ALG },
    ephemeralPublicKey: b64(ephemeralSpki),
    hkdfSalt: b64(hkdfSalt),
    chunkSize,
  };
  if (fileId !== undefined && fileId !== null) header.fileId = fileId;
  if (chunkIndex !== undefined && chunkIndex !== null) header.chunkIndex = chunkIndex;
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  if (headerBytes.length > MAX_STREAM_HEADER_BYTES) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'stream header is too large');
  }
  const headerSha = sha256Base64Url(headerBytes);
  dst.write(STREAM_MAGIC);
  dst.write(Buffer.from([1]));
  const len = Buffer.alloc(4);
  len.writeUInt32BE(headerBytes.length, 0);
  dst.write(len);
  dst.write(headerBytes);

  let index = 0;
  let total = 0;
  let previous = readChunk(src, chunkSize);
  const writeOne = (plaintext: any, isLast: any) => {
    const body = sealChunk(key, streamNonce(index, isLast), plaintext, streamAad(keyId, chunkSize, index, isLast, headerSha));
    dst.write(Buffer.from([isLast ? 1 : 0]));
    const bodyLen = Buffer.alloc(4);
    bodyLen.writeUInt32BE(body.length, 0);
    dst.write(bodyLen);
    dst.write(body);
    total += plaintext.length;
    index += 1;
  };
  if (previous.length < chunkSize) {
    writeOne(previous, true);
  } else {
    while (true) {
      const next = readChunk(src, chunkSize);
      if (next.length === 0) {
        writeOne(previous, true);
        break;
      }
      writeOne(previous, false);
      previous = next;
      if (previous.length < chunkSize) {
        writeOne(previous, true);
        break;
      }
    }
  }
  return {
    schema: STREAM_SCHEMA,
    recipientKeyId: keyId,
    chunkSize,
    chunkCount: index,
    plaintextLength: total,
    fileId: fileId ?? null,
    chunkIndex: chunkIndex ?? null,
  };
}

function readChunk(src: any, chunkSize: any) {
  const block = src.read(chunkSize);
  if (block == null) return Buffer.alloc(0);
  if (typeof block === 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'stream source must yield bytes');
  }
  return Buffer.from(block);
}

export function openStream({ keyId, readKey, recipientSpki, src, dst }: any) {
  const magic = readExact(src, 4, 'stream magic');
  if (!magic.equals(STREAM_MAGIC)) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream magic does not match hxdl.stream.v1');
  }
  const version = readExact(src, 1, 'stream version');
  if (version[0] !== 1) throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, 'Unsupported stream version');
  const headerLen = readExact(src, 4, 'stream header length').readUInt32BE(0);
  if (headerLen === 0 || headerLen > MAX_STREAM_HEADER_BYTES) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream header length is invalid');
  }
  const headerBytes = readExact(src, headerLen, 'stream header');
  let header;
  try {
    header = JSON.parse(headerBytes.toString('utf8'));
  } catch (error) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream header is not JSON');
  }
  if (header?.schema !== STREAM_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, 'Unsupported stream schema');
  }
  if (header.recipientKeyId !== keyId) {
    throw new DataLockError(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, 'stream recipient does not match the Keyring');
  }
  const alg = header.alg;
  if (!alg || alg.kem !== ENVELOPE_ALG.kem || alg.kdf !== ENVELOPE_ALG.kdf || alg.aead !== ENVELOPE_ALG.aead || Object.keys(alg).length !== 3) {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'stream must use X25519, HKDF-SHA256, and AES-256-GCM');
  }
  const chunkSize = header.chunkSize;
  requireChunkSize(chunkSize);
  const ephemeralSpki = fromB64(header.ephemeralPublicKey, 'ephemeralPublicKey', DataLockErrorCode.TAMPERED_STREAM, { maxLength: 512 });
  const hkdfSalt = fromB64(header.hkdfSalt, 'hkdfSalt', DataLockErrorCode.TAMPERED_STREAM, { exactLength: 32 });
  let ephemeralPublic;
  try {
    ephemeralPublic = createPublicKey({ key: ephemeralSpki, format: 'der', type: 'spki' });
  } catch (error) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'Invalid stream ephemeral public key');
  }
  let shared;
  try {
    shared = diffieHellman({ privateKey: readKey, publicKey: ephemeralPublic });
  } catch (error) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'Invalid stream ephemeral public key');
  }
  const key = contentKey(shared, hkdfSalt, keyId, recipientSpki);
  const headerSha = sha256Base64Url(headerBytes);
  let index = 0;
  let total = 0;
  let sawLast = false;
  while (true) {
    const flagBuf = src.read(1);
    if (!flagBuf || flagBuf.length === 0) break;
    if (sawLast) throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream continues after the last chunk');
    const flag = flagBuf[0];
    if (flag !== 0 && flag !== 1) throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream chunk flag is invalid');
    const isLast = flag === 1;
    const bodyLen = readExact(src, 4, 'chunk length').readUInt32BE(0);
    if (bodyLen < 16 || bodyLen > chunkSize + 16) {
      throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream chunk length is invalid');
    }
    const body = readExact(src, bodyLen, 'chunk body');
    let plaintext;
    try {
      plaintext = openChunk(key, streamNonce(index, isLast), body, streamAad(keyId, chunkSize, index, isLast, headerSha));
    } catch (error) {
      if (error instanceof DataLockError) throw error;
      throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream chunk authentication failed');
    }
    if (!isLast && plaintext.length !== chunkSize) {
      throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'non-final stream chunk has an unexpected length');
    }
    if (isLast && plaintext.length > chunkSize) {
      throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'final stream chunk exceeds chunkSize');
    }
    dst.write(plaintext);
    total += plaintext.length;
    index += 1;
    sawLast = isLast;
  }
  if (!sawLast) throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream ended before the last chunk');
  return {
    schema: STREAM_SCHEMA,
    recipientKeyId: keyId,
    chunkSize,
    chunkCount: index,
    plaintextLength: total,
    fileId: header.fileId ?? null,
    chunkIndex: header.chunkIndex ?? null,
  };
}

export function changedChunkIndexes(previous: any, current: any) {
  validateManifest(previous);
  validateManifest(current);
  if (previous.fileId !== current.fileId) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifests belong to different files');
  }
  const previousPlain = new Map(previous.chunks.map((entry: any) => [entry.index, entry.plaintextSha256]));
  return current.chunks
    .filter((entry: any) => previousPlain.get(entry.index) !== entry.plaintextSha256)
    .map((entry: any) => entry.index);
}

function validateManifest(manifest: any) {
  if (!manifest || manifest.schema !== MANIFEST_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest schema must be hxdl.manifest.v1');
  }
  if (typeof manifest.fileId !== 'string' || !manifest.fileId) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest fileId is missing');
  }
  if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest must list at least one chunk');
  }
  manifest.chunks.forEach((entry: any, expected: any) => {
    if (!entry || entry.index !== expected) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest chunk indexes must be contiguous from 0');
    }
  });
}
