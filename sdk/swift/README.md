# HX-DataLock Swift package

`sdk/swift` is a Swift Package for the v1 codec, `hxdl.stream.v1`, `hxdl.manifest.v1`, Ed25519 attestation, and zxcvbn password checks. X25519, HKDF-SHA256, AES-256-GCM, and scrypt come from [swift-crypto](https://github.com/apple/swift-crypto). Password strength uses a vendored pure-Swift zxcvbn with the same 46-bit and 80-bit floors as the other SDKs. The package does not link OpenSSL.

This repository was tested on Linux with Swift 6.2. BoringSSL inside swift-crypto is C++, so the Linux link step needs `libstdc++` on the library path:

```sh
export PATH="$HOME/swift/usr/bin:$PATH"
export CPLUS_INCLUDE_PATH="/usr/include/c++/13:/usr/include/x86_64-linux-gnu/c++/13"
export LIBRARY_PATH="/usr/lib/gcc/x86_64-linux-gnu/13:${LIBRARY_PATH:-}"
cd sdk/swift && swift test && swift build
```

The `hxdl-swift` executable speaks the same `lock` / `open` flags as the Node CLI for envelope interoperability tests.

## What this package does not do

- It does not build an iOS or macOS app. There is no Xcode project and this environment has no iOS simulator. The same sources are the package an Apple target would depend on; that build was not run here.
- swift-crypto supplies the primitives. On Apple platforms some of those primitives can go through CryptoKit inside swift-crypto. scrypt is swift-crypto's own implementation, not a CryptoKit API (CryptoKit has no scrypt).
- An iOS or macOS build was not run here. There is no Xcode toolchain in this environment. CryptoKit still has no scrypt, so Apple targets use the same swift-crypto dependency.
