export const KEYRING_SCHEMA = 'hxdl.keyring.v1';
export const PUBLIC_KEY_SCHEMA = 'hxdl.publicKey.v1';
export const ENVELOPE_SCHEMA = 'hxdl.envelope.v1';
export const DEFAULT_SCRYPT_N = 2 ** 18;
export const DEFAULT_SCRYPT_R = 8;
export const DEFAULT_SCRYPT_P = 1;
export const KEY_LENGTH = 32;
export const MIN_SCRYPT_N = 2 ** 14;
export const MAX_SCRYPT_N = 2 ** 20;
export const MAX_SCRYPT_R = 16;
export const MAX_SCRYPT_P = 4;
export const MAX_V1_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_KEYRING_JSON_BYTES = 1024 * 1024;
export const MAX_PUBLIC_KEY_JSON_BYTES = 64 * 1024;
export const MAX_ENVELOPE_JSON_BYTES = 40 * 1024 * 1024;
export const ENVELOPE_ALG = {
  kem: 'X25519',
  kdf: 'HKDF-SHA256',
  aead: 'AES-256-GCM',
};
