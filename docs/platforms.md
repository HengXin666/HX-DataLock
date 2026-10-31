# Platforms

## Web

`@hx/datalock/browser` is an ES module with no `node:crypto`, `node:fs`, or `Buffer` dependency. X25519, HKDF, and AES-GCM use WebCrypto (Chromium 133+, Firefox 133+, Safari 17.4+, and current Node). Ed25519 in WebCrypto needs Chromium 137+, Firefox 130+, or Safari 17.4+. scrypt uses `@noble/hashes` `scryptAsync`, which yields during the derivation so a Worker can unlock a Keyring without a synchronous stall of the same length as `scryptSync`. The package `browser` export is the esbuild bundle, which inlines those dependencies.

The Node entry stays synchronous and uses `node:crypto`, including native scrypt. Both entries produce `hxdl.keyring.v1` and `hxdl.envelope.v1` documents the other SDKs open.

Build the browser bundle with `npm run build` in `sdk/node`. The file is `sdk/node/dist/browser.bundle.js`. `examples/browser/index.html` loads it.

## Android

`sdk/kotlin` is still the JVM module used by tests and desktop. `sdk/kotlin/android` is an Android library (min SDK 26, compile SDK 34) that compiles the same Kotlin sources into an AAR:

```sh
export ANDROID_HOME=/path/to/android-sdk
gradle -p sdk/kotlin :android:assembleRelease
```

The release archive is `sdk/kotlin/android/build/outputs/aar/android-release.aar`. It contains `classes.jar` with Sender, User, stream, manifest sealing, and password-strength types. The AAR depends on BouncyCastle `bcprov-jdk18on` (not `bcprov-jdk15on` or SpongyCastle), kotlinx-serialization, and `com.nulab-inc:zxcvbn`. The Android library strips BouncyCastle signature files (`META-INF/*.SF`, `*.DSA`, `*.RSA`) and `META-INF/versions/9/OSGI-INF/MANIFEST.MF`, which `bcprov` and `bcpkix` both ship and which otherwise collide when the instrumented test APK is packaged. Conscrypt stays the platform TLS provider; HX-DataLock asks BouncyCastle only for X25519 and scrypt. If the app already depends on another `org.bouncycastle:bcprov-*` artifact, exclude that one and keep `bcprov-jdk18on:1.81`:

```kotlin
configurations.configureEach {
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    exclude(group = "com.madgag.spongycastle", module = "core")
}
```

`connectedDebugAndroidTest` covers a device round trip. The workflow is `.github/workflows/android-instrumented.yml`. File IO uses `Files.readAllBytes` / `Files.write`, which the Android 34 stubs provide.

scrypt with the default `N=2^18` asks for about 256 MiB. Phones may fail that allocation. Callers can create a Keyring with a lower `N` inside the accepted window; the CLI warns below `2^17`. Readers still accept historical Keyrings down to `2^14`.

## Swift

`sdk/swift` is a Swift Package. It creates Keyrings and locks and opens `hxdl.envelope.v1` with swift-crypto (X25519, HKDF, AES-GCM, and scrypt). The `hxdl-swift` executable is covered by the cross-SDK envelope test when `sdk/swift/.build/debug/hxdl-swift` exists. See `sdk/swift/README.md` for the Linux link flags.

This package was built and tested on Linux. An iOS or macOS app target was not compiled here: there is no Xcode toolchain in this environment. CryptoKit does not implement scrypt, so the package uses swift-crypto on every platform, including Apple targets. Streaming, manifests, attestation, and zxcvbn are not in the Swift package.

## Kotlin streaming

Python, Node, and Kotlin implement `hxdl.stream.v1` and `hxdl.manifest.v1`. Sender `sealChunked` and User `openChunked` match Python `seal_chunked` / `open_chunked`, including reuse of an unchanged chunk's previous sealed bytes. `HxDataLock.changedChunkIndexes` compares plaintext hashes. The browser module still seals a single stream; it does not build a manifest.
