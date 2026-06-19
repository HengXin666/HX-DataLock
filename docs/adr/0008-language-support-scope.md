# Language Support Scope

V1 treats TypeScript and Python as full SDKs with Sender DataLock and User DataLock support, while Kotlin is an Android-first modern client SDK with User DataLock support and a minimum target of Android API 26+. Kotlin does not provide Sender DataLock in v1, but its User DataLock must support both `openBytes` and local `lockBytes` using the Write Key already present in the full Keyring. Cross-language compatibility is part of the product contract: envelopes and keyrings produced by one full SDK must be readable by the others within their supported roles.
