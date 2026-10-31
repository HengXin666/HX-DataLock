# Reject Weak Master Passwords

Status: accepted. Supersedes the "does not block" consequence in ADR 0012, ADR 0021, and ADR 0023.

Keyring creation and rewrap use a zxcvbn-style estimator. The report still reaches the caller first. Creation then rejects the password unless the score is at least 3 and the guess estimate is at least about 46 bits. `allow_weak` is an explicit override for tests and migration. It does not apply to the public-Keyring floor in ADR 0025.

Scores do not have to match bit-for-bit across languages. The shared contract is the report shape and the reject/allow decision for obvious weak passwords and for long passphrases. Kotlin creation does not yet run this estimator; the Python and TypeScript SDKs and both CLIs do. Kotlin callers that create Keyrings should use one of those checks or reject on their own until that gap closes.

Rewrap changes only the scrypt wrapping of the same Read Key. Existing v1 Data Envelopes stay readable. A leaked copy of the old Keyring is not revoked.
