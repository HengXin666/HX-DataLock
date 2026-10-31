# Password-wrapped X25519 Keyring

Status: the X25519 wrapping decision stands. The "GitHub-stored Keyring" sentence is superseded by ADR 0025. A Keyring is private. GitHub may see a Public Key Document, not the Keyring.

We use an X25519 Write Key and store the matching Read Key encrypted by a key derived from the user's Master Password. This deliberately avoids sending the Master Password to GitHub Actions: local machines remain the only place where the Read Key is unwrapped.

## Considered Options

- Symmetric-only encryption was rejected because anyone who can encrypt would also be able to decrypt.
- GitHub Actions password input was rejected because it expands the trust boundary to GitHub runners and workflow logs.

## Consequences

Security depends on the Master Password resisting offline guessing after Keyring leakage. A weak Master Password cannot be made safe by the storage layout alone.
