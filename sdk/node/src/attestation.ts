import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { ATTESTATION_SCHEMA, SIGNED_MANIFEST_V2_SCHEMA } from './constants.js';
import { b64, fromB64, sha256Base64Url, utcNow } from './crypto-codec.js';
import { DataLockError, DataLockErrorCode } from './errors.js';
import type { AttestationJson, AttestationVerifyOptions, JsonValue, SignedManifestJson, SignedManifestVerifyOptions } from './types.js';

export function generateAttestationKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey,
    publicSpki: publicKey.export({ format: 'der', type: 'spki' }),
  };
}

export function attestationKeyId(publicSpki: Buffer | Uint8Array) {
  return `ed25519:${sha256Base64Url(publicSpki).slice(0, 22)}`;
}

export function attestationMessage(envelopeSha256: string, recipientKeyId: string, context: string) {
  if ([envelopeSha256, recipientKeyId, context].some((value) => String(value).includes('\n'))) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'attestation fields must not contain newlines');
  }
  return Buffer.from(`${ATTESTATION_SCHEMA}\n${envelopeSha256}\n${recipientKeyId}\n${context}\n`, 'utf8');
}

export function envelopeSha256(envelope: { serialize(): string; verify(): void }) {
  return sha256Base64Url(Buffer.from(envelope.serialize(), 'utf8'));
}

export function signEnvelope(privateKey: KeyObject, envelope: { verify(): void; serialize(): string; raw: { recipientKeyId: string } }, context = ''): AttestationJson {
  if (privateKey?.asymmetricKeyType !== 'ed25519') {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'attestation signer must use Ed25519');
  }
  if (typeof context !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'attestation context must be a string');
  }
  envelope.verify();
  const publicSpki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const digest = envelopeSha256(envelope);
  const recipient = envelope.raw.recipientKeyId;
  const signature = sign(null, attestationMessage(digest, recipient, context), privateKey);
  return {
    schema: ATTESTATION_SCHEMA,
    createdAt: utcNow(),
    envelopeSha256: digest,
    context,
    recipientKeyId: recipient,
    signer: {
      alg: 'Ed25519',
      keyId: attestationKeyId(publicSpki),
      publicKey: b64(publicSpki),
    },
    signature: b64(signature),
  };
}

export function verifyAttestation(attestation: AttestationJson, envelope: { verify(): void; serialize(): string; raw: { recipientKeyId: string } }, options: AttestationVerifyOptions = {}) {
  if (!attestation || attestation.schema !== ATTESTATION_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation schema must be hxdl.attestation.v1');
  }
  envelope.verify();
  const digest = envelopeSha256(envelope);
  if (attestation.envelopeSha256 !== digest) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation does not match this Data Envelope');
  }
  if (attestation.recipientKeyId !== envelope.raw.recipientKeyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation recipient does not match the Data Envelope');
  }
  if (typeof attestation.context !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation context must be a string');
  }
  if (options.context !== undefined && attestation.context !== options.context) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation context does not match');
  }
  const signer = attestation.signer;
  if (!signer || signer.alg !== 'Ed25519') {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'attestation signer must use Ed25519');
  }
  const publicSpki = fromB64(signer.publicKey, 'signer.publicKey', DataLockErrorCode.INVALID_ATTESTATION, { maxLength: 128 });
  const keyId = attestationKeyId(publicSpki);
  if (signer.keyId !== keyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation signer keyId does not match the public key');
  }
  if (options.expectedSignerKeyId && keyId !== options.expectedSignerKeyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation signer is not the expected key');
  }
  const signature = fromB64(attestation.signature, 'signature', DataLockErrorCode.INVALID_ATTESTATION, { exactLength: 64 });
  const publicKey = createPublicKey({ key: publicSpki, format: 'der', type: 'spki' });
  const ok = verify(null, attestationMessage(digest, envelope.raw.recipientKeyId, attestation.context), publicKey, signature);
  if (!ok) throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'attestation signature is invalid');
}

export function signManifest(privateKey: KeyObject, payload: { [key: string]: JsonValue }, issuer: string): SignedManifestJson {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'manifest payload must be an object');
  }
  if (privateKey?.asymmetricKeyType !== 'ed25519') {
    throw new DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, 'attestation signer must use Ed25519');
  }
  const publicSpki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const stable = signedManifestBytes(issuer, payload);
  const signature = sign(null, stable, privateKey);
  return {
    schema: SIGNED_MANIFEST_V2_SCHEMA,
    signedAt: utcNow(),
    issuer,
    signer: {
      alg: 'Ed25519',
      keyId: attestationKeyId(publicSpki),
      publicKey: b64(publicSpki),
    },
    payload,
    signature: b64(signature),
  };
}

export function verifySignedManifest(document: SignedManifestJson, options: SignedManifestVerifyOptions = {}) {
  if (!document || document.schema !== SIGNED_MANIFEST_V2_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest schema must be hxdl.signedManifest.v2');
  }
  const publicSpki = fromB64(document.signer?.publicKey, 'signer.publicKey', DataLockErrorCode.INVALID_ATTESTATION, { maxLength: 128 });
  const keyId = attestationKeyId(publicSpki);
  if (document.signer?.keyId !== keyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest signer keyId does not match the public key');
  }
  if (!options.expectedSignerKeyId) {
    console.warn('verifySignedManifest has no expectedSignerKeyId. Any matching Ed25519 key will be accepted.');
  } else if (keyId !== options.expectedSignerKeyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest signer is not the expected key');
  }
  const signature = fromB64(document.signature, 'signature', DataLockErrorCode.INVALID_ATTESTATION, { exactLength: 64 });
  const stable = signedManifestBytes(String(document.issuer ?? ''), document.payload);
  const ok = verify(
    null,
    stable,
    createPublicKey({ key: publicSpki, format: 'der', type: 'spki' }),
    signature,
  );
  if (!ok) throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest signature is invalid');
  return document.payload;
}

function canonicalJson(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map((item) => canonicalJson(item)).join(',\n')}\n]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) return '{}';
    const lines = keys.map((key) => `${JSON.stringify(key)}: ${canonicalJson(value[key])}`);
    return `{\n${lines.join(',\n')}\n}`;
  }
  throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest is not canonical JSON');
}

function indentCanonical(value: JsonValue, indent: number): string {
  const pad = ' '.repeat(indent);
  const inner = ' '.repeat(indent + 2);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map((item) => `${inner}${indentCanonical(item, indent + 2)}`).join(',\n')}\n${pad}]`;
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) return '{}';
    return `{\n${keys.map((key) => `${inner}${JSON.stringify(key)}: ${indentCanonical(value[key], indent + 2)}`).join(',\n')}\n${pad}}`;
  }
  return canonicalJson(value);
}

export function signedManifestBytes(issuer: string, payload: JsonValue) {
  return Buffer.from(`${indentCanonical({ issuer, payload }, 0)}\n`, 'utf8');
}

export function loadAttestationPrivateKey(pkcs8: Buffer | Uint8Array) {
  return createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
}
