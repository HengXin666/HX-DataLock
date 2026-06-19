# No Platform Keychain in Core SDK

V1 does not integrate OS Keychain, Android Keystore, iOS Keychain, or similar platform secret stores in the core SDK. Storing full Keyrings, caching unlocked state, and using platform-specific secure storage are application integration concerns outside the Crypto Codec boundary.
