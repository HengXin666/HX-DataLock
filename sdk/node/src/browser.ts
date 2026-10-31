/**
 * Browser and Worker entry. No node:crypto, node:fs, or Buffer.
 *
 * X25519, HKDF, AES-GCM, and Ed25519 use WebCrypto. scrypt uses
 * @noble/hashes scryptAsync so the main thread can yield. Call this module
 * from a Worker when unlocking a Keyring on a page.
 */
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { base64ToBytes, bytesToBase64, sha256Base64Url } from './base64-pure.js';
import { checkPasswordStrength } from './password-strength.js';
import {
  ATTESTATION_SCHEMA,
  DEFAULT_SCRYPT_N,
  DEFAULT_SCRYPT_P,
  DEFAULT_SCRYPT_R,
  DEFAULT_STREAM_CHUNK_SIZE,
  ENVELOPE_ALG,
  ENVELOPE_SCHEMA,
  KEY_LENGTH,
  KEYRING_SCHEMA,
  MAX_V1_FILE_BYTES,
  PUBLIC_KEY_SCHEMA,
  STREAM_SCHEMA,
} from './constants.js';
import { DataLockError, DataLockErrorCode } from './errors.js';

export { checkPasswordStrength, DataLockError, DataLockErrorCode };
export type { PasswordStrengthReport } from './password-strength.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

function subtle(): SubtleCrypto {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.subtle) {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'WebCrypto is not available in this environment');
  }
  return cryptoApi.subtle;
}

function randomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await subtle().digest('SHA-256', data as BufferSource);
  return new Uint8Array(digest);
}

function utcNow(): string {
  return new Date().toISOString();
}

function enforcePassword(masterPassword: string, options: Record<string, unknown> = {}) {
  if (typeof masterPassword !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'Master Password must be a string');
  }
  const report = checkPasswordStrength(masterPassword);
  const onReport = options.onPasswordReport;
  if (typeof onReport === 'function') onReport(report);
  const allowWeak = Boolean(options.allowWeak);
  const publicKeyring = Boolean(options.publicKeyring);
  if (publicKeyring && !report.allowedForPublicKeyring) {
    throw new DataLockError(
      DataLockErrorCode.WEAK_MASTER_PASSWORD,
      'A public Keyring requires a Master Password of at least 80 estimated bits',
    );
  }
  if (!publicKeyring && !report.allowed && !allowWeak) {
    throw new DataLockError(
      DataLockErrorCode.WEAK_MASTER_PASSWORD,
      'Master Password is too weak to create a Keyring; pass allowWeak to override',
    );
  }
  return report;
}

async function importX25519Public(spki: Uint8Array, usages: KeyUsage[] = []) {
  return subtle().importKey('spki', spki as BufferSource, { name: 'X25519' }, true, usages);
}

async function importX25519Private(pkcs8: Uint8Array) {
  return subtle().importKey('pkcs8', pkcs8 as BufferSource, { name: 'X25519' }, true, ['deriveBits']);
}

async function sharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  try {
    const bits = await subtle().deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256);
    return new Uint8Array(bits);
  } catch (error) {
    throw new DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, 'Invalid Data Envelope public key');
  }
}

async function hkdf(secret: Uint8Array, salt: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  const base = await subtle().importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
    base,
    256,
  );
  return new Uint8Array(bits);
}

async function aesGcmEncrypt(keyBytes: Uint8Array, plaintext: Uint8Array, aad: Uint8Array) {
  const nonce = randomBytes(12);
  const key = await subtle().importKey('raw', keyBytes as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const sealed = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
      key,
      plaintext as BufferSource,
    ),
  );
  return {
    nonce,
    ciphertext: sealed.subarray(0, sealed.length - 16),
    tag: sealed.subarray(sealed.length - 16),
  };
}

async function aesGcmDecrypt(keyBytes: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad: Uint8Array, code: string) {
  const key = await subtle().importKey('raw', keyBytes as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
      key,
      concat([ciphertext, tag]) as BufferSource,
    );
    return new Uint8Array(plain);
  } catch (error) {
    throw new DataLockError(code, 'Ciphertext authentication failed');
  }
}

async function scrypt(password: string, salt: Uint8Array, n: number, r: number, p: number): Promise<Uint8Array> {
  const derived = await scryptAsync(textEncoder.encode(password.normalize('NFC')), salt, {
    N: n,
    r,
    p,
    dkLen: KEY_LENGTH,
    asyncTick: 10,
  });
  return new Uint8Array(derived);
}

function keyIdForSpki(spki: Uint8Array, prefix: string): Promise<string> {
  return sha256(spki).then((digest) => `${prefix}:${sha256Base64Url(digest).slice(0, 22)}`);
}

export async function createKeyring(masterPassword: string, options: Record<string, any> = {}) {
  enforcePassword(masterPassword, options);
  const scryptN = Number(options.scryptN || DEFAULT_SCRYPT_N);
  const pair = (await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const publicSpki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey));
  const privatePkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
  const keyId = await keyIdForSpki(publicSpki, 'x25519');
  const salt = randomBytes(32);
  const wrapping = await scrypt(masterPassword, salt, scryptN, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P);
  const aad = textEncoder.encode(`${KEYRING_SCHEMA}:${keyId}:scrypt:AES-256-GCM`);
  const sealed = await aesGcmEncrypt(wrapping, privatePkcs8, aad);
  return {
    schema: KEYRING_SCHEMA,
    createdAt: utcNow(),
    publicWriteKey: { alg: 'X25519', keyId, spki: bytesToBase64(publicSpki) },
    encryptedReadKey: {
      kdf: { name: 'scrypt', salt: bytesToBase64(salt), N: scryptN, r: DEFAULT_SCRYPT_R, p: DEFAULT_SCRYPT_P, keyLength: KEY_LENGTH },
      aead: { name: 'AES-256-GCM', nonce: bytesToBase64(sealed.nonce), tag: bytesToBase64(sealed.tag) },
      ciphertext: bytesToBase64(sealed.ciphertext),
    },
  };
}

export function exportPublicKeyDocument(keyring: any) {
  return {
    schema: PUBLIC_KEY_SCHEMA,
    createdAt: utcNow(),
    publicWriteKey: { ...keyring.publicWriteKey },
  };
}

function asBytes(payload: Uint8Array | ArrayBuffer): Uint8Array {
  if (typeof payload === 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'lockBytes requires Uint8Array, not a string; use lockText');
  }
  if (payload instanceof Uint8Array) return payload;
  if (payload instanceof ArrayBuffer) return new Uint8Array(payload);
  throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'lockBytes requires Uint8Array');
}

export async function lockBytes(publicKeyDocument: any, payload: Uint8Array) {
  const bytes = asBytes(payload);
  if (bytes.length > MAX_V1_FILE_BYTES) {
    throw new DataLockError(DataLockErrorCode.OVERSIZED_FILE, 'V1 Full Data Envelopes support payloads up to 25 MB');
  }
  if (publicKeyDocument?.schema === KEYRING_SCHEMA || publicKeyDocument?.encryptedReadKey) {
    throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Sender DataLock requires a Public Key Document, not a full Keyring');
  }
  const write = publicKeyDocument.publicWriteKey ?? publicKeyDocument.raw?.publicWriteKey;
  const recipient = await importX25519Public(base64ToBytes(write.spki));
  const ephemeral = (await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const ephemeralSpki = new Uint8Array(await subtle().exportKey('spki', ephemeral.publicKey));
  const shared = await sharedSecret(ephemeral.privateKey, recipient);
  const hkdfSalt = randomBytes(32);
  const info = textEncoder.encode(`${ENVELOPE_SCHEMA}:${write.keyId}`);
  const contentKey = await hkdf(shared, hkdfSalt, info);
  const aad = textEncoder.encode(`${ENVELOPE_SCHEMA}:${write.keyId}:${ENVELOPE_ALG.kem}:${ENVELOPE_ALG.kdf}:${ENVELOPE_ALG.aead}`);
  const sealed = await aesGcmEncrypt(contentKey, bytes, aad);
  return {
    schema: ENVELOPE_SCHEMA,
    createdAt: utcNow(),
    recipientKeyId: write.keyId,
    alg: { ...ENVELOPE_ALG },
    ephemeralPublicKey: bytesToBase64(ephemeralSpki),
    hkdfSalt: bytesToBase64(hkdfSalt),
    nonce: bytesToBase64(sealed.nonce),
    tag: bytesToBase64(sealed.tag),
    ciphertext: bytesToBase64(sealed.ciphertext),
  };
}

export async function lockText(publicKeyDocument: any, text: string) {
  if (typeof text !== 'string') throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'lockText requires text input');
  return lockBytes(publicKeyDocument, textEncoder.encode(text));
}

async function unwrapReadKey(keyring: any, masterPassword: string) {
  const encrypted = keyring.encryptedReadKey;
  const kdf = encrypted.kdf;
  const wrapping = await scrypt(masterPassword, base64ToBytes(kdf.salt), kdf.N, kdf.r, kdf.p);
  const aad = textEncoder.encode(`${KEYRING_SCHEMA}:${keyring.publicWriteKey.keyId}:scrypt:AES-256-GCM`);
  try {
    return await aesGcmDecrypt(
      wrapping,
      base64ToBytes(encrypted.aead.nonce),
      base64ToBytes(encrypted.ciphertext),
      base64ToBytes(encrypted.aead.tag),
      aad,
      DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
    );
  } catch (error) {
    if (error instanceof DataLockError) throw error;
    throw new DataLockError(DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING, 'Wrong master password or tampered Keyring');
  }
}

export async function openBytes(keyring: any, masterPassword: string, envelope: any) {
  if (typeof masterPassword !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'masterPassword must be a string');
  }
  const privatePkcs8 = await unwrapReadKey(keyring, masterPassword);
  const readKey = await importX25519Private(privatePkcs8);
  if (envelope.recipientKeyId !== keyring.publicWriteKey.keyId) {
    throw new DataLockError(DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH, 'Data Envelope recipient does not match the Keyring');
  }
  const ephemeral = await importX25519Public(base64ToBytes(envelope.ephemeralPublicKey));
  const shared = await sharedSecret(readKey, ephemeral);
  const info = textEncoder.encode(`${ENVELOPE_SCHEMA}:${keyring.publicWriteKey.keyId}`);
  const contentKey = await hkdf(shared, base64ToBytes(envelope.hkdfSalt), info);
  const alg = envelope.alg;
  const aad = textEncoder.encode(`${ENVELOPE_SCHEMA}:${keyring.publicWriteKey.keyId}:${alg.kem}:${alg.kdf}:${alg.aead}`);
  return aesGcmDecrypt(
    contentKey,
    base64ToBytes(envelope.nonce),
    base64ToBytes(envelope.ciphertext),
    base64ToBytes(envelope.tag),
    aad,
    DataLockErrorCode.TAMPERED_ENVELOPE,
  );
}

export async function openText(keyring: any, masterPassword: string, envelope: any) {
  try {
    return textDecoder.decode(await openBytes(keyring, masterPassword, envelope));
  } catch (error) {
    if (error instanceof DataLockError) throw error;
    throw new DataLockError(DataLockErrorCode.INVALID_UTF8, 'Data Envelope payload is not valid UTF-8');
  }
}

export function parseEnvelope(text: string) {
  if (typeof text !== 'string') throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'Data Envelope JSON must be a string');
  const raw = JSON.parse(text);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || raw.schema !== ENVELOPE_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, 'Unsupported Data Envelope schema');
  }
  return raw;
}

export function inspectEnvelope(envelope: any) {
  return {
    schema: envelope.schema,
    recipientKeyId: envelope.recipientKeyId,
    createdAt: envelope.createdAt,
    alg: { ...envelope.alg },
    ciphertextBytes: base64ToBytes(envelope.ciphertext).length,
  };
}

export function serializeDocument(raw: any): string {
  return `${JSON.stringify(raw, null, 2)}\n`;
}

export async function lockStream(publicKeyDocument: any, source: ReadableStream<Uint8Array>, options: { chunkSize?: number } = {}) {
  const chunkSize = options.chunkSize ?? DEFAULT_STREAM_CHUNK_SIZE;
  const write = publicKeyDocument.publicWriteKey;
  const recipientSpki = base64ToBytes(write.spki);
  const recipient = await importX25519Public(recipientSpki);
  const ephemeral = (await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const ephemeralSpki = new Uint8Array(await subtle().exportKey('spki', ephemeral.publicKey));
  const shared = await sharedSecret(ephemeral.privateKey, recipient);
  const hkdfSalt = randomBytes(32);
  const info = concat([textEncoder.encode(`hxdl.stream.v1:${write.keyId}:`), await sha256(recipientSpki)]);
  const contentKeyBytes = await hkdf(shared, hkdfSalt, info);
  const header = {
    schema: STREAM_SCHEMA,
    recipientKeyId: write.keyId,
    alg: { ...ENVELOPE_ALG },
    ephemeralPublicKey: bytesToBase64(ephemeralSpki),
    hkdfSalt: bytesToBase64(hkdfSalt),
    chunkSize,
  };
  const headerBytes = textEncoder.encode(JSON.stringify(header));
  const headerSha = sha256Base64Url(await sha256(headerBytes));
  const aesKey = await subtle().importKey('raw', contentKeyBytes as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const reader = source.getReader();
  let stash: Uint8Array = new Uint8Array(0);

  async function readUpTo(n: number): Promise<{ bytes: Uint8Array; eof: boolean }> {
    while (stash.length < n) {
      const next = await reader.read();
      if (next.done) {
        const bytes = stash;
        stash = new Uint8Array(0);
        return { bytes, eof: true };
      }
      stash = concat([stash, next.value]);
    }
    const bytes = stash.slice(0, n);
    stash = stash.slice(n);
    return { bytes, eof: false };
  }

  async function emit(controller: ReadableStreamDefaultController<Uint8Array>, plaintext: Uint8Array, isLast: boolean, index: number) {
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setUint32(4, index);
    nonce[11] = isLast ? 1 : 0;
    const aad = textEncoder.encode(
      `${STREAM_SCHEMA}:${write.keyId}:X25519:HKDF-SHA256:AES-256-GCM:${chunkSize}:${index}:${isLast ? 1 : 0}:${headerSha}`,
    );
    const body = new Uint8Array(
      await subtle().encrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
        aesKey,
        plaintext as BufferSource,
      ),
    );
    const frameLen = new Uint8Array(4);
    new DataView(frameLen.buffer).setUint32(0, body.length);
    controller.enqueue(new Uint8Array([isLast ? 1 : 0]));
    controller.enqueue(frameLen);
    controller.enqueue(body);
  }

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      controller.enqueue(new Uint8Array([0x48, 0x58, 0x44, 0x4c, 1]));
      const len = new Uint8Array(4);
      new DataView(len.buffer).setUint32(0, headerBytes.length);
      controller.enqueue(len);
      controller.enqueue(headerBytes);
      let index = 0;
      let previous = await readUpTo(chunkSize);
      if (previous.eof) {
        await emit(controller, previous.bytes, true, index);
        controller.close();
        return;
      }
      while (true) {
        const next = await readUpTo(chunkSize);
        if (next.eof && next.bytes.length === 0) {
          await emit(controller, previous.bytes, true, index);
          break;
        }
        await emit(controller, previous.bytes, false, index);
        index += 1;
        if (next.eof) {
          await emit(controller, next.bytes, true, index);
          break;
        }
        previous = next;
      }
      controller.close();
    },
  });
}

export async function signEnvelopeWithKey(privateKey: CryptoKey, publicKey: CryptoKey, envelope: any, context = '') {
  const digest = sha256Base64Url(await sha256(textEncoder.encode(serializeDocument(envelope))));
  const message = textEncoder.encode(`${ATTESTATION_SCHEMA}\n${digest}\n${envelope.recipientKeyId}\n${context}\n`);
  const signature = new Uint8Array(await subtle().sign({ name: 'Ed25519' }, privateKey, message as BufferSource));
  const publicSpki = new Uint8Array(await subtle().exportKey('spki', publicKey));
  return {
    schema: ATTESTATION_SCHEMA,
    createdAt: utcNow(),
    envelopeSha256: digest,
    context,
    recipientKeyId: envelope.recipientKeyId,
    signer: {
      alg: 'Ed25519',
      keyId: `ed25519:${sha256Base64Url(await sha256(publicSpki)).slice(0, 22)}`,
      publicKey: bytesToBase64(publicSpki),
    },
    signature: bytesToBase64(signature),
  };
}

export async function generateAttestationKey() {
  return subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
}
