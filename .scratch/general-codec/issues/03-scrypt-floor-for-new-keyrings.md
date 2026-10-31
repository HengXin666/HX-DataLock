# Raise the scrypt floor for new Keyrings

Status: 交给代理

Readers still accept scrypt `N` from `2^14` through `2^20` so historical Keyrings open. The CLI warns below `2^17`. New Keyrings can still be created at the old floor, which is cheap for an offline guess if that Keyring leaks.

## Acceptance

- Keyring creation below `2^17` fails with `INVALID_SCRYPT_PARAMS` unless a named test override is set.
- Existing Keyrings at `2^14` still unwrap.
- Python, TypeScript, and Kotlin use the same code.
