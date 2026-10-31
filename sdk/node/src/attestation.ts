import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { ATTESTATION_SCHEMA, SIGNED_MANIFEST_V2_SCHEMA } from './constants.js';
import { b64, fromB64, sha256Base64Url, utcNow } from './crypto-codec.js';
import { DataLockError, DataLockErrorCode } from './errors.js';

export function generateAttestationKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey,
    publicSpki: publicKey.export({ format: 'der', type: 'spki' }),
  };
}

export function attestationKeyId(publicSpki) {
  return `ed25519:${sha256Base64Url(publicSpki).slice(0, 22)}`;
}

export function attestationMessage(envelopeSha256, recipientKeyId, context) {
  if ([envelopeSha256, recipientKeyId, context].some((value) => String(value).includes('\n'))) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'attestation fields must not contain newlines');
  }
  return Buffer.from(`${ATTESTATION_SCHEMA}\n${envelopeSha256}\n${recipientKeyId}\n${context}\n`, 'utf8');
}

export function envelopeSha256(envelope) {
  return sha256Base64Url(Buffer.from(envelope.serialize(), 'utf8'));
}

export function signEnvelope(privateKey, envelope, context = '') {
  if (typeof context !== 'string') {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'attestation context must be a string');
  }
  envelope.verify();
  const publicSpki = (privateKey.type === 'private' ? createPublicKey(privateKey) : privateKey).export
    ? createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
    : privateKey.export({ format: 'der', type: 'spki' });
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

export function verifyAttestation(attestation, envelope, options: any = {}) {
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

export function signManifest(privateKey, payload, issuer) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new DataLockError(DataLockErrorCode.INVALID_ARGUMENT, 'manifest payload must be an object');
  }
  const publicSpki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const stable = `${JSON.stringify(payload, null, 2)}\n`;
  const signature = sign(null, Buffer.from(stable, 'utf8'), privateKey);
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

export function verifySignedManifest(document, options: any = {}) {
  if (!document || document.schema !== SIGNED_MANIFEST_V2_SCHEMA) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest schema must be hxdl.signedManifest.v2');
  }
  const publicSpki = fromB64(document.signer?.publicKey, 'signer.publicKey', DataLockErrorCode.INVALID_ATTESTATION, { maxLength: 128 });
  const keyId = attestationKeyId(publicSpki);
  if (document.signer?.keyId !== keyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest signer keyId does not match the public key');
  }
  if (options.expectedSignerKeyId && keyId !== options.expectedSignerKeyId) {
    throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest signer is not the expected key');
  }
  const signature = fromB64(document.signature, 'signature', DataLockErrorCode.INVALID_ATTESTATION, { exactLength: 64 });
  const stable = `${JSON.stringify(document.payload, null, 2)}\n`;
  const ok = verify(
    null,
    Buffer.from(stable, 'utf8'),
    createPublicKey({ key: publicSpki, format: 'der', type: 'spki' }),
    signature,
  );
  if (!ok) throw new DataLockError(DataLockErrorCode.INVALID_ATTESTATION, 'signed manifest signature is invalid');
  return document.payload;
}

export function loadAttestationPrivateKey(pkcs8) {
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}
