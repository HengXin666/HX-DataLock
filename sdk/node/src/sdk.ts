import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { DataLockError, DataLockErrorCode } from './errors.js';
import {
  DEFAULT_SCRYPT_N,
  DEFAULT_SCRYPT_P,
  DEFAULT_SCRYPT_R,
  KEY_LENGTH,
  KEYRING_SCHEMA,
  MAX_KEYRING_JSON_BYTES,
  PUBLIC_KEY_SCHEMA,
} from './constants.js';
import { Keyring, PublicKeyDocument } from './documents.js';
import { SenderDataLock, UserDataLock } from './datalocks.js';
import {
  aadForKeyring,
  b64,
  derivePasswordKey,
  encryptAesGcm,
  sha256Base64Url,
  utcNow,
  validateScryptN,
} from './crypto-codec.js';
import { readJson } from './json.js';
import { isStableJson } from './json.js';
import { checkPasswordStrength } from './password-strength.js';

export function createKeyring(masterPassword, options: any = {}) {
  if (typeof masterPassword !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'Master Password must be a string');
  }
  const report = checkPasswordStrength(masterPassword);
  const onReport = options.onPasswordReport ?? options.on_password_report;
  if (typeof onReport === 'function') onReport(report);
  const publicKeyring = Boolean(options.publicKeyring ?? options.public_keyring);
  const allowWeak = Boolean(options.allowWeak ?? options.allow_weak);
  if (publicKeyring) {
    console.warn(
      'DANGER: creating a Keyring for public storage. Anyone who can read it can guess the Master Password offline. Publish a Public Key Document instead unless this is deliberate.',
    );
    if (!report.allowedForPublicKeyring) {
      throw new DataLockError(
        DataLockErrorCode.WEAK_MASTER_PASSWORD,
        'A public Keyring requires a Master Password of at least 80 estimated bits',
      );
    }
  } else if (!report.allowed && !allowWeak) {
    throw new DataLockError(
      DataLockErrorCode.WEAK_MASTER_PASSWORD,
      'Master Password is too weak to create a Keyring; pass allowWeak to override',
    );
  }
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

export function initKeyring(path, masterPassword, options: any = {}) {
  const keyring = createKeyring(masterPassword, options);
  keyring.write(path);
  return keyring;
}

export const init_keyring = initKeyring;

export function loadKeyring(path) {
  const keyring = new Keyring(readJson(path, MAX_KEYRING_JSON_BYTES));
  keyring.verify();
  return keyring;
}

export function verifyKeyringFile(path, options: any = {}) {
  const keyring = loadKeyring(path);
  if (options.requireStableJson && !isStableJson(path, keyring.raw)) {
    throw new DataLockError(DataLockErrorCode.INVALID_KEYRING, 'Keyring does not use stable v1 JSON');
  }
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

export function verifyPublicKeyDocumentFile(path, options: any = {}) {
  const document = PublicKeyDocument.read(path);
  if (options.requireStableJson && !isStableJson(path, document.raw)) {
    throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Public Key Document does not use stable v1 JSON');
  }
  return document;
}

export function verifyPublicKeyDocumentKeyId(publicKeyDocument, expectedKeyId) {
  const document = publicKeyDocument instanceof PublicKeyDocument ? publicKeyDocument : new PublicKeyDocument(publicKeyDocument);
  document.verify();
  if (document.keyId !== expectedKeyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Public Key Document keyId does not match the expected keyId');
  }
  return document;
}

export function makeSenderDataLock(publicKeyDocument, options: any = {}) {
  if (publicKeyDocument instanceof Keyring || publicKeyDocument?.schema === KEYRING_SCHEMA || publicKeyDocument?.raw?.schema === KEYRING_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT, 'Sender DataLock requires a Public Key Document, not a full Keyring');
  }
  const document = publicKeyDocument instanceof PublicKeyDocument ? publicKeyDocument : new PublicKeyDocument(publicKeyDocument);
  document.verify();
  const expectedKeyId = options.expectedKeyId || options.expected_key_id;
  const requireExpectedKeyId = Boolean(options.requireExpectedKeyId ?? options.require_expected_key_id);
  if (expectedKeyId) {
    verifyPublicKeyDocumentKeyId(document, expectedKeyId);
  } else if (requireExpectedKeyId) {
    throw new DataLockError(
      DataLockErrorCode.UNPINNED_PUBLIC_KEY,
      'Sender DataLock requires expectedKeyId so a replaced Public Key Document is rejected',
    );
  } else {
    console.warn(
      'Sender DataLock has no expectedKeyId. A replaced Public Key Document encrypts new data to the replacement key. Pass expectedKeyId.',
    );
  }
  return new SenderDataLock(document);
}

export function makeUserDataLock(keyring, options) {
  const fullKeyring = keyring instanceof Keyring ? keyring : new Keyring(keyring);
  const masterPassword = masterPasswordFromOptions(options);
  return new UserDataLock(fullKeyring, fullKeyring.unwrapReadKey(masterPassword));
}

function masterPasswordFromOptions(options) {
  if (typeof options === 'string') return options;
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new DataLockError(
      DataLockErrorCode.INVALID_ARGUMENT,
      'User DataLock requires a Master Password string or {masterPassword: string}',
    );
  }
  if (!Object.prototype.hasOwnProperty.call(options, 'masterPassword')) {
    throw new DataLockError(
      DataLockErrorCode.INVALID_ARGUMENT,
      'User DataLock options require masterPassword; other key names are not accepted',
    );
  }
  const unknown = Object.keys(options).filter((key) => key !== 'masterPassword');
  if (unknown.length) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, `Unknown User DataLock option: ${unknown.join(', ')}`);
  }
  if (typeof options.masterPassword !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'masterPassword must be a string');
  }
  return options.masterPassword;
}

export function rewrapKeyring(keyring, currentPassword, newPassword, options: any = {}) {
  const fullKeyring = keyring instanceof Keyring ? keyring : new Keyring(keyring);
  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'Passwords must be strings');
  }
  const report = checkPasswordStrength(newPassword);
  const onReport = options.onPasswordReport ?? options.on_password_report;
  if (typeof onReport === 'function') onReport(report);
  const publicKeyring = Boolean(options.publicKeyring ?? options.public_keyring);
  const allowWeak = Boolean(options.allowWeak ?? options.allow_weak);
  if (publicKeyring && !report.allowedForPublicKeyring) {
    throw new DataLockError(
      DataLockErrorCode.WEAK_MASTER_PASSWORD,
      'A public Keyring requires a Master Password of at least 80 estimated bits',
    );
  }
  if (!report.allowed && !allowWeak) {
    throw new DataLockError(
      DataLockErrorCode.WEAK_MASTER_PASSWORD,
      'Master Password is too weak to rewrap a Keyring; pass allowWeak to override',
    );
  }
  const readKey = fullKeyring.unwrapReadKey(currentPassword);
  const privateDer = readKey.export({ format: 'der', type: 'pkcs8' });
  const previous = fullKeyring.raw.encryptedReadKey.kdf;
  const kdf = {
    name: 'scrypt',
    salt: b64(randomBytes(32)),
    N: previous.N,
    r: previous.r,
    p: previous.p,
    keyLength: previous.keyLength,
  };
  const wrappingKey = derivePasswordKey(newPassword, kdf);
  const sealed = encryptAesGcm(wrappingKey, privateDer, aadForKeyring(fullKeyring.keyId));
  const rewrapped = new Keyring({
    schema: fullKeyring.raw.schema,
    createdAt: fullKeyring.raw.createdAt,
    publicWriteKey: { ...fullKeyring.raw.publicWriteKey },
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
  rewrapped.verify();
  return rewrapped;
}
