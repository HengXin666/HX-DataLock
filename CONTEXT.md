# HX-DataLock

HX-DataLock is a general-purpose encryption context for separating data writing from data reading. It treats public storage as hostile and GitHub-hosted key material as non-secret unless it is protected by the user's master password.

## Language

**Master Password**:
A strict Unicode secret memorized by the user and used locally to unwrap the Read Key. It is normalized with NFC and then encoded as UTF-8 before key derivation; it may contain non-English text such as Chinese or Japanese.
_Avoid_: Login password, account password

**Password Strength Policy**:
A local check that warns about weak Master Passwords before a Keyring is created while still allowing the user to continue. It exists because length alone does not describe offline attack resistance for user-chosen passwords.
_Avoid_: Password rule, length check

**Password Strength Report**:
A structured result from the Password Strength Policy containing a strength level, warnings, and suggestions. It informs the user but does not block Keyring creation in v1.
_Avoid_: Password valid flag, password score only

**Secret Residency Policy**:
A safety boundary for how long sensitive material remains reachable in memory. HX-DataLock minimizes Master Password residency, does not cache it, and treats memory clearing as best-effort in managed runtimes.
_Avoid_: Memory encryption, secure memory guarantee

**Write Key**:
The public recipient key that can encrypt new Data Envelopes but cannot decrypt existing data.
_Avoid_: Public key, send key

**Write-only Sender**:
A trusted service or automation environment that can create new Data Envelopes with the Write Key but never receives the Master Password or Read Key.
_Avoid_: Sender, backend decryptor

**Sender DataLock**:
An SDK object for a Write-only Sender. It can lock data with the Write Key and must not expose any operation that unwraps or uses the Read Key.
_Avoid_: Send client, generic client

**User DataLock**:
An SDK object for a local user environment that has unlocked the Read Key with the Master Password. It can open Data Envelopes and may also lock new data.
_Avoid_: Read client, decrypt client

**Crypto Codec**:
The library boundary for HX-DataLock: it converts Payload Bytes to and from Data Envelopes, like a secure codec. It does not perform network I/O, database access, cache management, synchronization, or business object serialization.
_Avoid_: Storage SDK, sync client

**Lock**:
The public SDK operation that converts Payload Bytes into a Data Envelope. It names encryption without implying network I/O.
_Avoid_: Send, upload

**Open**:
The public SDK operation that converts a Data Envelope back into Payload Bytes. It names decryption without implying storage access.
_Avoid_: Receive, download

**Payload Bytes**:
The plaintext byte sequence accepted by the Crypto Codec. Business formats such as JSON are encoded and decoded by the application before locking or after opening.
_Avoid_: JSON object, business object

**Local File Helper**:
A convenience SDK operation that reads or writes local files while still producing or consuming Data Envelopes. It is not a storage integration and must enforce the v1 25 MB file limit.
_Avoid_: Storage adapter, file sync

**DataLock Error Code**:
A stable cross-language error identifier exposed by SDK failures. It lets applications handle expected failure cases without parsing localized or implementation-specific messages.
_Avoid_: Exception message, stack trace

**Read Key**:
The private recipient key that can decrypt Data Envelopes after it is unwrapped with the Master Password.
_Avoid_: Private key, decrypt key

**Keyring**:
A GitHub-stored document containing the Write Key and the Read Key encrypted under a key derived from the Master Password.
_Avoid_: Key file, secret file

**Public Key Document**:
A document containing only the Write Key and non-secret metadata. It is the only supported input for Write-only Senders because it omits all Master Password-related material, including the encrypted Read Key.
_Avoid_: Public key file, sender keyring

**Data Envelope**:
A portable encrypted payload stored in public storage. It contains ciphertext plus the non-secret metadata needed by a holder of the Read Key to decrypt it.
_Avoid_: Blob, encrypted file

**Recipient Key ID**:
A non-secret identifier derived from the Write Key and stored in each Data Envelope so clients can match envelopes to the correct Keyring. It does not encode storage location, GitHub repository, user identity, or other business identity.
_Avoid_: User ID, repo ID

**Creation Time**:
Non-security metadata showing when a Keyring, Public Key Document, or Data Envelope was produced. It is useful for display and debugging but is not authenticated as a business timestamp and does not drive conflict resolution.
_Avoid_: Version, sync timestamp

**Data Migration**:
A business-owned process that opens existing Data Envelopes and locks the resulting Payload Bytes under a new Keyring. HX-DataLock does not provide key rotation as a v1 library operation.
_Avoid_: Key rotation, password change

**Full Data Envelope**:
A Data Envelope that encrypts one complete byte sequence as a single authenticated payload. It is the default shape for business-defined payload bytes and v1 single files up to 25 MB.
_Avoid_: Whole blob, single-shot blob

**Oversized File**:
A file larger than 25 MB, which v1 rejects instead of encrypting as a Full Data Envelope. Oversized files belong to the deferred Chunked File Envelope design.
_Avoid_: Large file, stream file

**Chunked File Envelope**:
A deferred Data Envelope family for large files where the file is split into independently encrypted chunks plus authenticated file-level metadata. It is not part of the first supported SDK surface because chunk boundaries and parallel decrypt semantics need a stable compatibility design.
_Avoid_: Big envelope, streamed blob

**Public Storage**:
Any storage location that is assumed to be fully visible to attackers, such as cloud drives or Cloudflare D1.
_Avoid_: Safe storage, external storage

**Offline Guessing Attack**:
An attack where a leaked Keyring lets an attacker test candidate Master Passwords without interacting with the user or a server.
_Avoid_: Brute force
