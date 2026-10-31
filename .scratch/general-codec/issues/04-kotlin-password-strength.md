# Kotlin password strength

Status: 交给代理

Python and TypeScript reject weak Master Passwords with a zxcvbn-style report. Kotlin `createKeyring` does not. A Kotlin caller can still create a Keyring with `password`.

## Acceptance

- Kotlin returns the same report fields and rejects weak passwords unless an explicit allow-weak flag is set.
- The public-Keyring 80-bit floor matches ADR 0025.
