import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
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
import type { ByteCursor, ByteSink, ChunkManifest, ManifestChunk, StreamInfo } from './types.js';

const STREAM_MAGIC = Buffer.from('HXDL');

function requireChunkSize(chunkSize: number | undefined): number {
  if (chunkSize === undefined || !Number.isInteger(chunkSize) || chunkSize < MIN_STREAM_CHUNK_SIZE || chunkSize > MAX_STREAM_CHUNK_SIZE) {
    throw new DataLockError(
      DataLockErrorCode.INVALID_ARGUMENT,
      `chunk_size must be an integer from ${MIN_STREAM_CHUNK_SIZE} to ${MAX_STREAM_CHUNK_SIZE}`,
    );
  }
  return chunkSize;
}

export function streamNonce(index: number, isLast: boolean) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(index), 0);
  nonce[11] = isLast ? 1 : 0;
  return nonce;
}

function streamAad(keyId: string, chunkSize: number, index: number, isLast: boolean, headerSha: string) {
  const flag = isLast ? '1' : '0';
  return Buffer.from(
    `${STREAM_SCHEMA}:${keyId}:X25519:HKDF-SHA256:AES-256-GCM:${chunkSize}:${index}:${flag}:${headerSha}`,
    'utf8',
  );
}

function contentKey(sharedSecret: Buffer, hkdfSalt: Buffer, keyId: string, recipientSpki: Buffer) {
  const info = Buffer.concat([
    Buffer.from(`hxdl.stream.v1:${keyId}:`, 'utf8'),
    createHash('sha256').update(recipientSpki).digest(),
  ]);
  return Buffer.from(hkdfSync('sha256', sharedSecret, hkdfSalt, info, KEY_LENGTH));
}

function sealChunk(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function openChunk(key: Buffer, nonce: Buffer, body: Buffer, aad: Buffer) {
  const tag = body.subarray(body.length - 16);
  const ciphertext = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function asBuffer(block: Buffer | Uint8Array): Buffer {
  return Buffer.isBuffer(block) ? block : Buffer.from(block);
}

function readUpTo(src: ByteCursor, size: number, what: string): { data: Buffer; eof: boolean } {
  const parts: Buffer[] = [];
  let got = 0;
  while (got < size) {
    const block = src.read(size - got);
    if (block == null) {
      throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, `${what} returned null before EOF; use an empty buffer at EOF`);
    }
    if (typeof block === 'string') {
      throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'stream source must yield bytes');
    }
    const buf = asBuffer(block);
    if (buf.length === 0) return { data: Buffer.concat(parts), eof: true };
    const slice = buf.length > size - got ? buf.subarray(0, size - got) : buf;
    parts.push(slice);
    got += slice.length;
  }
  return { data: Buffer.concat(parts), eof: false };
}

function readExact(src: ByteCursor, size: number, what: string) {
  const { data, eof } = readUpTo(src, size, what);
  if (eof || data.length !== size) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, `stream ended inside ${what}`);
  }
  return data;
}

export function lockStreamBytes({
  keyId,
  publicKey,
  plaintext,
  chunkSize = DEFAULT_STREAM_CHUNK_SIZE,
  fileId = undefined,
  chunkIndex = undefined,
}: {
  keyId: string;
  publicKey: KeyObject;
  plaintext: Buffer;
  chunkSize?: number;
  fileId?: string;
  chunkIndex?: number;
}) {
  const cursor = { offset: 0, read(n: number) {
    const slice = plaintext.subarray(this.offset, this.offset + n);
    this.offset += slice.length;
    return Buffer.from(slice);
  } };
  const parts: Buffer[] = [];
  const info = lockStream({
    keyId,
    publicKey,
    src: cursor,
    dst: { write(buf: Buffer | Uint8Array) { parts.push(Buffer.from(buf)); } },
    chunkSize,
    fileId,
    chunkIndex,
  });
  return { bytes: Buffer.concat(parts), info };
}

export function lockStream({
  keyId,
  publicKey,
  src,
  dst,
  chunkSize = DEFAULT_STREAM_CHUNK_SIZE,
  fileId = undefined,
  chunkIndex = undefined,
}: {
  keyId: string;
  publicKey: KeyObject;
  src: ByteCursor;
  dst: ByteSink;
  chunkSize?: number;
  fileId?: string | null;
  chunkIndex?: number | null;
}): StreamInfo {
  chunkSize = requireChunkSize(chunkSize);
  if (fileId !== undefined && fileId !== null && (typeof fileId !== 'string' || fileId.length === 0 || fileId.includes('\n'))) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'fileId must be a single-line string');
  }
  if (chunkIndex !== undefined && chunkIndex !== null && (!Number.isInteger(chunkIndex) || chunkIndex < 0)) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'chunkIndex must be a non-negative integer');
  }
  const recipientSpki = publicKey.export({ format: 'der', type: 'spki' });
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralSpki = ephemeral.publicKey.export({ format: 'der', type: 'spki' });
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey });
  const hkdfSalt = randomBytes(32);
  const key = contentKey(shared, hkdfSalt, keyId, recipientSpki);
  const header: {
    schema: string;
    recipientKeyId: string;
    alg: typeof ENVELOPE_ALG;
    ephemeralPublicKey: string;
    hkdfSalt: string;
    chunkSize: number;
    fileId?: string;
    chunkIndex?: number;
  } = {
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
  const writeOne = (plaintext: Buffer, isLast: boolean) => {
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

function readChunk(src: ByteCursor, chunkSize: number) {
  return readUpTo(src, chunkSize, 'stream source').data;
}

export function openStream({
  keyId,
  readKey,
  recipientSpki,
  src,
  dst,
}: {
  keyId: string;
  readKey: KeyObject;
  recipientSpki: Buffer;
  src: ByteCursor;
  dst: ByteSink;
}): StreamInfo {
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
  let header: {
    schema?: string;
    recipientKeyId?: string;
    alg?: { kem?: string; kdf?: string; aead?: string };
    chunkSize?: number;
    ephemeralPublicKey?: string;
    hkdfSalt?: string;
    fileId?: string;
    chunkIndex?: number;
  };
  try {
    const parsed: unknown = JSON.parse(headerBytes.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, 'stream header is not JSON');
    }
    header = parsed as typeof header;
  } catch (error) {
    if (error instanceof DataLockError) throw error;
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
  const chunkSize = requireChunkSize(header.chunkSize);
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
    const flagRead = readUpTo(src, 1, 'stream chunk flag');
    if (flagRead.eof && flagRead.data.length === 0) break;
    const flagBuf = flagRead.data;
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

export function changedChunkIndexes(previous: ChunkManifest, current: ChunkManifest) {
  validateManifest(previous);
  validateManifest(current);
  if (previous.fileId !== current.fileId) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifests belong to different files');
  }
  const previousPlain = new Map(previous.chunks.map((entry) => [entry.index, entry.plaintextSha256]));
  return current.chunks
    .filter((entry) => previousPlain.get(entry.index) !== entry.plaintextSha256)
    .map((entry) => entry.index);
}

export function sealChunked({
  keyId,
  publicKey,
  src,
  chunkSize = DEFAULT_STREAM_CHUNK_SIZE,
  fileId,
  version = 1,
  previousManifest = null,
  previousSealed = null,
}: {
  keyId: string;
  publicKey: KeyObject;
  src: ByteCursor;
  chunkSize?: number;
  fileId: string;
  version?: number;
  previousManifest?: ChunkManifest | null;
  previousSealed?: Array<Buffer | Uint8Array> | null;
}): { manifest: ChunkManifest; chunks: Buffer[] } {
  if (typeof fileId !== 'string' || fileId.length === 0) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'fileId is required');
  }
  if (!Number.isInteger(version) || version < 1) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'manifest version must be a positive integer');
  }
  const size = requireChunkSize(chunkSize);
  if ((previousManifest == null) !== (previousSealed == null)) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'previousManifest and previousSealed must be passed together');
  }
  const previousByIndex = new Map<number, { entry: ManifestChunk; sealed: Buffer }>();
  if (previousManifest && previousSealed) {
    validateManifest(previousManifest);
    if (previousManifest.fileId !== fileId) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'previous manifest belongs to a different file');
    }
    if (previousSealed.length !== previousManifest.chunks.length) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'previous sealed chunk count does not match the manifest');
    }
    previousManifest.chunks.forEach((entry, index) => {
      const sealed = asBuffer(previousSealed[index]);
      if (sha256Base64Url(sealed) !== entry.sealedSha256) {
        throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'previous sealed hash does not match the manifest');
      }
      previousByIndex.set(entry.index, { entry, sealed });
    });
  }
  const chunks: Buffer[] = [];
  const entries: ManifestChunk[] = [];
  let total = 0;
  let index = 0;
  while (true) {
    const { data: block, eof } = readUpTo(src, size, 'plaintext source');
    if (eof && block.length === 0 && index > 0) break;
    const digest = sha256Base64Url(block);
    const reused = previousByIndex.get(index);
    const sealed = reused && reused.entry.plaintextSha256 === digest && reused.entry.plaintextLength === block.length
      ? reused.sealed
      : lockStreamBytes({
        keyId,
        publicKey,
        plaintext: block,
        chunkSize: size,
        fileId,
        chunkIndex: index,
      }).bytes;
    entries.push({
      index,
      plaintextLength: block.length,
      plaintextSha256: digest,
      sealedSha256: sha256Base64Url(sealed),
    });
    chunks.push(sealed);
    total += block.length;
    index += 1;
    if (eof || block.length < size) break;
  }
  return {
    manifest: {
      schema: MANIFEST_SCHEMA,
      fileId,
      version,
      chunkSize: size,
      totalPlaintextLength: total,
      chunks: entries,
    },
    chunks,
  };
}

export function openChunked({
  keyId,
  readKey,
  recipientSpki,
  manifest,
  sealedChunks,
  dst,
}: {
  keyId: string;
  readKey: KeyObject;
  recipientSpki: Buffer;
  manifest: ChunkManifest;
  sealedChunks: Array<Buffer | Uint8Array>;
  dst: ByteSink;
}): { schema: string; fileId: string; version: number; plaintextLength: number; chunkCount: number } {
  validateManifest(manifest);
  if (sealedChunks.length !== manifest.chunks.length) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'sealed chunk count does not match the manifest');
  }
  let total = 0;
  manifest.chunks.forEach((entry, index) => {
    const sealed = asBuffer(sealedChunks[index]);
    if (sha256Base64Url(sealed) !== entry.sealedSha256) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, `sealed hash mismatch for chunk ${entry.index}`);
    }
    const parts: Buffer[] = [];
    const info = openStream({
      keyId,
      readKey,
      recipientSpki,
      src: bufferCursor(sealed),
      dst: { write(buf) { parts.push(Buffer.from(buf)); } },
    });
    const plaintext = Buffer.concat(parts);
    if (info.fileId !== manifest.fileId || info.chunkIndex !== entry.index) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, `chunk ${entry.index} is bound to a different file`);
    }
    if (plaintext.length !== entry.plaintextLength || sha256Base64Url(plaintext) !== entry.plaintextSha256) {
      throw new DataLockError(DataLockErrorCode.TAMPERED_STREAM, `plaintext hash mismatch for chunk ${entry.index}`);
    }
    dst.write(plaintext);
    total += plaintext.length;
  });
  if (total !== manifest.totalPlaintextLength) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest total length does not match the chunks');
  }
  return {
    schema: MANIFEST_SCHEMA,
    fileId: manifest.fileId,
    version: manifest.version,
    plaintextLength: total,
    chunkCount: manifest.chunks.length,
  };
}

function bufferCursor(plaintext: Buffer): ByteCursor {
  const cursor = { offset: 0, read(n: number) {
    const slice = plaintext.subarray(this.offset, this.offset + n);
    this.offset += slice.length;
    return Buffer.from(slice);
  } };
  return cursor;
}

function validateManifest(manifest: ChunkManifest) {
  if (!manifest || manifest.schema !== MANIFEST_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest schema must be hxdl.manifest.v1');
  }
  if (typeof manifest.fileId !== 'string' || !manifest.fileId) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest fileId is missing');
  }
  if (!Number.isInteger(manifest.version) || manifest.version < 1) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest version is invalid');
  }
  if (!Number.isInteger(manifest.chunkSize)) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest chunkSize is invalid');
  }
  requireChunkSize(manifest.chunkSize);
  if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
    throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest must list at least one chunk');
  }
  manifest.chunks.forEach((entry, expected) => {
    if (!entry || entry.index !== expected) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest chunk indexes must be contiguous from 0');
    }
    if (!Number.isInteger(entry.plaintextLength) || typeof entry.plaintextSha256 !== 'string' || !entry.plaintextSha256 || typeof entry.sealedSha256 !== 'string' || !entry.sealedSha256) {
      throw new DataLockError(DataLockErrorCode.INVALID_MANIFEST, 'manifest chunk is missing a hash or length');
    }
  });
}
