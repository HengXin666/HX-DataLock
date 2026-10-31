# Platforms

## Web

`@hx/datalock/browser` is an ES module with no `node:crypto`, `node:fs`, or `Buffer` dependency. X25519, HKDF, AES-GCM, and Ed25519 use WebCrypto (Chromium 133+, Firefox 133+, Safari 17.4+, and current Node). scrypt uses `@noble/hashes` `scryptAsync`, which yields during the derivation so a Worker can unlock a Keyring without a synchronous stall of the same length as `scryptSync`.

The Node entry stays synchronous and uses `node:crypto`, including native scrypt. Both entries produce `hxdl.keyring.v1` and `hxdl.envelope.v1` documents the other SDKs open.

Build the browser bundle with `npm run build` in `sdk/node`. The file is `sdk/node/dist/browser.bundle.js`. `examples/browser/index.html` loads it.

## Android

The Kotlin module is a JVM jar (`kotlin("jvm")`) that Android apps can depend on. It now includes Sender DataLock, `DataEnvelope.parse(String)`, and strict UTF-8 for `lockText`. There is no AAR module in this repository: the Android Gradle plugin and an instrumented test device are not part of the current build. Shipping an AAR also has to decide how to avoid clashing with Android's trimmed BouncyCastle. That is tracked as a follow-up, not claimed here.

scrypt with the default `N=2^18` asks for about 256 MiB. Phones may fail that allocation. Callers can create a Keyring with a lower `N` inside the accepted window; the CLI warns below `2^17`. Readers still accept historical Keyrings down to `2^14`.

## iOS

There is no Swift SDK. A WKWebView or React Native app can use the browser module where WebCrypto X25519 exists (iOS 17.4+). A native CryptoKit port is future work. Nothing in this tree pretends to be that port.

## Kotlin streaming

Python, Node, and the browser module implement `hxdl.stream.v1`. The Kotlin module does not yet. JVM callers with multi-megabyte payloads should use the Python or TypeScript stream API, or split under the 25 MB v1 envelope limit, until the Kotlin port lands.
