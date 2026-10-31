/**
 * Public document shapes. Field names and schemas match the Python SDK.
 * Creation Time is an ISO-8601 UTC string with millisecond precision.
 */

import type { PasswordStrengthReport } from './password-strength.js';

export type { PasswordStrengthReport };

export interface ScryptKdf {
  name: 'scrypt';
  salt: string;
  N: number;
  r: number;
  p: number;
  keyLength: number;
}

export interface PublicWriteKeyJson {
  alg: 'X25519';
  keyId: string;
  spki: string;
}

export interface EncryptedReadKeyJson {
  kdf: ScryptKdf;
  aead: {
    name: 'AES-256-GCM';
    nonce: string;
    tag: string;
  };
  ciphertext: string;
}

export interface KeyringJson {
  schema: 'hxdl.keyring.v1';
  createdAt: string;
  publicWriteKey: PublicWriteKeyJson;
  encryptedReadKey: EncryptedReadKeyJson;
}

export interface PublicKeyDocumentJson {
  schema: 'hxdl.publicKey.v1';
  createdAt: string;
  publicWriteKey: PublicWriteKeyJson;
}

export interface EnvelopeAlgJson {
  kem: 'X25519';
  kdf: 'HKDF-SHA256';
  aead: 'AES-256-GCM';
}

export interface EnvelopeJson {
  schema: 'hxdl.envelope.v1';
  createdAt: string;
  recipientKeyId: string;
  alg: EnvelopeAlgJson;
  ephemeralPublicKey: string;
  hkdfSalt: string;
  nonce: string;
  tag: string;
  ciphertext: string;
}

export interface DecodedEnvelopeFields {
  ephemeralPublicKey: Buffer;
  hkdfSalt: Buffer;
  nonce: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

export interface EnvelopeInspection {
  schema: string;
  recipientKeyId: string;
  createdAt: string;
  alg: EnvelopeAlgJson;
  ciphertextBytes: number;
}

export interface ManifestChunk {
  index: number;
  plaintextLength: number;
  plaintextSha256: string;
  sealedSha256: string;
}

export interface ChunkManifest {
  schema: 'hxdl.manifest.v1';
  fileId: string;
  version: number;
  chunkSize: number;
  totalPlaintextLength: number;
  chunks: ManifestChunk[];
}

export interface StreamInfo {
  schema: 'hxdl.stream.v1';
  recipientKeyId: string;
  chunkSize: number;
  chunkCount: number;
  plaintextLength: number;
  fileId: string | null;
  chunkIndex: number | null;
}

export interface AttestationSignerJson {
  alg: 'Ed25519';
  keyId: string;
  publicKey: string;
}

export interface AttestationJson {
  schema: 'hxdl.attestation.v1';
  createdAt: string;
  envelopeSha256: string;
  context: string;
  recipientKeyId: string;
  signer: AttestationSignerJson;
  signature: string;
}

export interface SignedManifestJson {
  schema: 'hxdl.signedManifest.v2';
  signedAt: string;
  issuer: string;
  signer: AttestationSignerJson;
  payload: JsonObject;
  signature: string;
}

export interface CreateKeyringOptions {
  scryptN?: number;
  scrypt_n?: number;
  allowWeakPassword?: boolean;
  allow_weak_password?: boolean;
  allowWeak?: boolean;
  allow_weak?: boolean;
  allowLowScryptN?: boolean;
  allow_low_scrypt_n?: boolean;
  publicKeyring?: boolean;
  public_keyring?: boolean;
  onPasswordReport?: (report: PasswordStrengthReport) => void;
  on_password_report?: (report: PasswordStrengthReport) => void;
}

export interface SenderOptions {
  expectedKeyId?: string;
  expected_key_id?: string;
  allowUnpinnedPublicKey?: boolean;
  allow_unpinned_public_key?: boolean;
}

export interface UserDataLockOptions {
  masterPassword: string;
}

export interface StreamLockOptions {
  chunkSize?: number;
  fileId?: string;
  chunkIndex?: number;
}

export interface SealChunkedOptions extends StreamLockOptions {
  fileId: string;
  version?: number;
  previousManifest?: ChunkManifest | null;
  previousSealed?: Uint8Array[] | null;
}

export interface VerifyFileOptions {
  requireStableJson?: boolean;
}

export interface AttestationVerifyOptions {
  context?: string;
  expectedSignerKeyId?: string;
}

export interface SignedManifestVerifyOptions {
  expectedSignerKeyId?: string;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;

export interface JsonObject {
  [key: string]: JsonValue;
}

/** A reader that may return fewer bytes than requested. Empty means EOF. */
export interface ByteCursor {
  read(size: number): Buffer | Uint8Array | null | undefined;
}

export interface ByteSink {
  write(chunk: Buffer | Uint8Array): void;
}

export interface Base64DecodeOptions {
  exactLength?: number;
  maxLength?: number;
}

export interface AesGcmSealed {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}
