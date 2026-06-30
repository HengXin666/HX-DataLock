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
import { checkPasswordStrength } from './password-strength.js';

export function createKeyring(masterPassword, options: any = {}) {
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
  const keyring = new Keyring(readJson(path, MAX_KEYRING_JSON_BYTES));
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
