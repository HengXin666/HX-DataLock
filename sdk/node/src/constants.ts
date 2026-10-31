export const KEYRING_SCHEMA = 'hxdl.keyring.v1' as const;
export const PUBLIC_KEY_SCHEMA = 'hxdl.publicKey.v1' as const;
export const ENVELOPE_SCHEMA = 'hxdl.envelope.v1' as const;
export const STREAM_SCHEMA = 'hxdl.stream.v1' as const;
export const MANIFEST_SCHEMA = 'hxdl.manifest.v1' as const;
export const ATTESTATION_SCHEMA = 'hxdl.attestation.v1' as const;
export const SIGNED_MANIFEST_V2_SCHEMA = 'hxdl.signedManifest.v2' as const;
export const STREAM_MAGIC = new Uint8Array([0x48, 0x58, 0x44, 0x4c]);
export const DEFAULT_STREAM_CHUNK_SIZE = 1024 * 1024;
export const MIN_STREAM_CHUNK_SIZE = 1;
export const MAX_STREAM_CHUNK_SIZE = 8 * 1024 * 1024;
export const MAX_STREAM_HEADER_BYTES = 64 * 1024;
export const DEFAULT_SCRYPT_N = 2 ** 18;
export const DEFAULT_SCRYPT_R = 8;
export const DEFAULT_SCRYPT_P = 1;
export const KEY_LENGTH = 32;
// Readers still accept Keyrings created at the historical floor. New Keyrings
// must use MIN_CREATE_SCRYPT_N unless the caller opts into a lower N.
export const MIN_SCRYPT_N = 2 ** 14;
export const MIN_CREATE_SCRYPT_N = 2 ** 17;
export const RECOMMENDED_MIN_SCRYPT_N = MIN_CREATE_SCRYPT_N;
export const PRIVATE_MIN_GUESSES_LOG10 = 14;
export const PUBLIC_MIN_GUESSES_LOG10 = 24.082399653118497;
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
} as const;
