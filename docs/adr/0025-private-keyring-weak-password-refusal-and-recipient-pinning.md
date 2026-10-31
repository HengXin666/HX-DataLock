# Private Keyring, Weak-Password Refusal, and Recipient Pinning

The threat model is public storage readable, writers cannot read, and the user decrypts locally. A Keyring that is public turns Master Password strength into the only defense against an Offline Guessing Attack. A Public Key Document that is not pinned can be replaced before a sender locks new data.

## Decision

1. Keyring creation refuses a weak Master Password unless the caller opts in (`allow_weak_password` / `--allow-weak-password`). The Password Strength Report still reaches the caller before that refusal. `allowed` is false when the level is weak. Opening an existing Keyring does not apply this check, so Keyrings created before the change still open. The stable code is `WEAK_MASTER_PASSWORD`. This supersedes the "v1 does not block a weak Master Password" consequence in ADR 0023 and the matching sentence in ADR 0021.

2. A Keyring is private local storage. It must not be committed to a public GitHub repository or copied into other public storage. Automation receives a Public Key Document only. This supersedes the "GitHub-stored Keyring" wording in ADR 0001. CI fails when a tracked Keyring document is present and the repository is public.

3. Sender DataLock requires `expected_key_id` / `expectedKeyId` / `--expect-key-id` unless the caller opts out (`allow_unpinned_public_key` / `--allow-unpinned-public-key`). Missing a pin raises `UNPINNED_PUBLIC_KEY`. A pin that does not match the document still raises `INVALID_PUBLIC_KEY_DOCUMENT`.

4. New Keyrings must use scrypt `N >= 2^17` unless the caller opts in (`allow_low_scrypt_n` / `--allow-low-scrypt-n`). Readers still accept `N` from `2^14` through `2^20`, so older Keyrings open unchanged. Creating below the floor raises `INSECURE_SCRYPT_PARAMETERS`. The opt-in cannot go below the reader minimum.

## Alternatives considered

Leaving weak passwords as a warning was rejected because a public or leaked Keyring plus a common password is the residual risk the format cannot remove after the fact. Silently raising the reader minimum to `2^17` was rejected because it would make existing Keyrings fail to open. Making recipient pinning optional was rejected because the unsafe path was the default. Blocking every committed Keyring, including in a private repository, was rejected because a private repository is not public storage; the check warns there and fails closed when visibility is public or unknown.

## Consequences

Callers that created Keyrings with weak passwords or `N = 2^14` keep the ability to open them. Callers that create new Keyrings must choose a stronger Master Password or pass the weak-password opt-in, and must pass a create-time scrypt `N` of at least `2^17` or pass the low-scrypt opt-in. Sender call sites must pass the recipient key id they already trust, or pass the unpinned opt-out. CLI help, the glossary, and ADR 0001 describe the Keyring as private local storage.
