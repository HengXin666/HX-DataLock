# Password-wrapped X25519 Keyring

A Keyring is a private local document. It exposes an X25519 Write Key and stores the matching Read Key encrypted by a key derived from the user's Master Password. Public GitHub repositories, GitHub Actions, and other public or automation storage receive a Public Key Document only. They never receive the Keyring or the Master Password. Local machines remain the only place where the Read Key is unwrapped.

ADR 0025 supersedes the earlier wording that stored the Keyring itself on GitHub. That layout made an Offline Guessing Attack possible for anyone who could read the repository.

## Considered Options

- Symmetric-only encryption was rejected because anyone who can encrypt would also be able to decrypt.
- GitHub Actions password input was rejected because it expands the trust boundary to GitHub runners and workflow logs.
- Publishing the password-wrapped Keyring was rejected because a public Keyring leaves Master Password strength as the only defense against an Offline Guessing Attack.

## Consequences

Security still depends on the Master Password if a Keyring leaks. A weak Master Password cannot be made safe by the storage layout alone, so creation refuses a weak Master Password unless the caller opts in. Keeping the Keyring off public storage is what keeps that guessing attack from starting.
