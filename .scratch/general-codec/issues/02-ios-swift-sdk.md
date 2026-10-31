# iOS Swift SDK

Status: 交给人工

There is no Swift implementation. A WKWebView can use the browser module on iOS 17.4+ where WebCrypto X25519 exists. A native port would use CryptoKit for X25519, HKDF, and AES-GCM, plus a scrypt implementation that is not CommonCrypto, and the same test vectors as the other SDKs.

Do not add a stub Swift package that only throws.
