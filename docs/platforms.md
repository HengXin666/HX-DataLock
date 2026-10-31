# Platforms

## Web

`@hx/datalock/browser` is an ES module with no `node:crypto`, `node:fs`, or `Buffer` dependency. X25519, HKDF, AES-GCM, and Ed25519 use WebCrypto (Chromium 133+, Firefox 133+, Safari 17.4+, and current Node). scrypt uses `@noble/hashes` `scryptAsync`, which yields during the derivation so a Worker can unlock a Keyring without a synchronous stall of the same length as `scryptSync`.

The Node entry stays synchronous and uses `node:crypto`, including native scrypt. Both entries produce `hxdl.keyring.v1` and `hxdl.envelope.v1` documents the other SDKs open.

Build the browser bundle with `npm run build` in `sdk/node`. The file is `sdk/node/dist/browser.bundle.js`. `examples/browser/index.html` loads it.

## Android

`sdk/kotlin` is still the JVM module used by tests and desktop. `sdk/kotlin/android` is an Android library (min SDK 26, compile SDK 34) that compiles the same Kotlin sources into an AAR:

```sh
export ANDROID_HOME=/path/to/android-sdk
gradle -p sdk/kotlin :android:assembleRelease
```

The release archive is `sdk/kotlin/android/build/outputs/aar/android-release.aar`. It contains `classes.jar` with Sender, User, stream, and password-strength types. The AAR depends on BouncyCastle (`bcprov-jdk18on`), kotlinx-serialization, and `com.nulab-inc:zxcvbn`. Android's own conscrypt/BouncyCastle can clash with a bundled `bcprov`; an app that already ships a provider should exclude one of them. File IO uses `Files.readAllBytes` / `Files.write`, which the Android 34 stubs provide, instead of `readString` / `writeString`.

scrypt with the default `N=2^18` asks for about 256 MiB. Phones may fail that allocation. Callers can create a Keyring with a lower `N` inside the accepted window; the CLI warns below `2^17`. Readers still accept historical Keyrings down to `2^14`.

## iOS

There is no Swift SDK in this repository. This environment has no Swift toolchain, so a native CryptoKit port was not added and nothing here pretends to compile as one. A WKWebView or React Native app can use the browser module where WebCrypto X25519 exists (iOS 17.4+). A native port would use CryptoKit for X25519, HKDF, and AES-GCM, plus a separate scrypt implementation, checked against the same vectors as the other SDKs.

## Kotlin streaming

Python, Node, the browser module, and Kotlin implement `hxdl.stream.v1`. Kotlin exposes `lockStream` / `openStream` on `InputStream` and `OutputStream` for both Sender and User. `hxdl.manifest.v1` diffing is `Stream.changedChunkIndexes` inside the module; a public manifest builder matching Python's `seal_chunked` is not wrapped as its own top-level API yet.
