Status: 待办

# Explain Write Key and Read Key binding in plain language

## What happened

The v1 docs say HX-DataLock uses a Write/Read X25519 key pair, but they do not plainly explain how the GitHub-visible Write Key is bound to the locally unwrapped Read Key, or why the Write Key cannot be used to recover the Read Key.

## What I expected

Users should be able to understand that the Write Key is the public half of an X25519 key pair, the Read Key is the matching private half encrypted in the Keyring, and the one-way property of X25519 prevents deriving the Read Key from the Write Key.

## Steps to reproduce

1. Read the README and v1 specification sections about Keyring, Public Key Document, Write Key, Read Key, Lock, and Open.
2. Try to explain how a Write-only Sender can lock Data Envelopes while being unable to open them.
3. Notice that the docs describe the algorithm but do not provide a plain-language security explanation or proof sketch.

## Additional context

This is a documentation issue around the Crypto Codec threat model. The explanation should use project terms: Keyring, Public Key Document, Write Key, Read Key, Data Envelope, Write-only Sender, User DataLock, Master Password, and Offline Guessing Attack.
