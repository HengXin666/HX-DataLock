Status: 已完成

# Harden Keyring file permissions on write

## Risk

Keyrings do not contain plaintext Read Keys, but they do contain encrypted Read Key material. If copied, an attacker can perform offline Master Password guessing.

Node writes JSON documents with `0600`, but Python and Kotlin currently rely on platform defaults for `Path.write_text(...)` / `Files.writeString(...)`. A permissive umask or platform default can make newly written Keyrings readable by other local users.

## What to build

Make Keyring writes owner-only where the platform supports it, and document fallback behavior where it does not.

## Acceptance criteria

- [x] Python Keyring writes create or converge the file to owner read/write permissions on POSIX platforms.
- [x] Kotlin Keyring writes set owner read/write permissions on POSIX-capable JVM platforms.
- [x] Public Key Document and Data Envelope writes remain usable as public documents, but do not weaken Keyring write behavior.
- [x] Tests cover Python Keyring file permission behavior on POSIX.
- [x] Kotlin tests cover permission behavior where Gradle/JVM platform support is available, or document why it is skipped.
- [x] README or SDK docs note that Keyrings should be stored as private local files.

## Notes

Do not promise secure deletion or memory erasure. This issue is only about reducing accidental local file exposure.

## Comments

- Implemented Python `Keyring.write` through a private JSON writer that uses `0600` on creation and converges existing POSIX files to owner read/write permissions.
- Implemented Kotlin `Keyring.write` through a POSIX-capable private JSON writer; Public Key Document and Data Envelope writes still use normal document writes.
- Added POSIX permission regression tests for Python and Kotlin, and documented private Keyring storage expectations in the Python and Kotlin SDK READMEs.
- Verification: `uv run pytest -q` passed with 45 passed and 3 skipped. `uv run pytest tests/kotlin/test_kotlin_sdk.py -q` skipped because this environment does not have `gradle`, matching the existing test guard.
