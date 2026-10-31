export { DataLockError, DataLockErrorCode } from './errors.js';
export {
  createKeyring,
  create_keyring,
  initKeyring,
  init_keyring,
  exportPublicKeyDocument,
  loadKeyring,
  makeSenderDataLock,
  makeUserDataLock,
  verifyKeyringFile,
  verifyPublicKeyDocumentFile,
  rewrapKeyring,
  verifyPublicKeyDocumentKeyId,
} from './sdk.js';
// Document classes and the data locks are part of the public surface: the
// functions above already return them, so callers need the types to annotate
// and to construct a document from parsed JSON.
export { DataEnvelope, Keyring, PublicKeyDocument } from './documents.js';
export { SenderDataLock, UserDataLock } from './datalocks.js';
export { checkPasswordStrength } from './password-strength.js';
export {
  generateAttestationKey,
  signEnvelope,
  signManifest,
  verifyAttestation,
  verifySignedManifest,
} from './attestation.js';
export { changedChunkIndexes, lockStream, openStream } from './stream.js';
