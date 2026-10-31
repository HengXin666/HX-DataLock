# iOS Swift SDK

Status: 部分落地

`sdk/swift` 是 Swift Package。Linux 上用 Swift 6.2 和 swift-crypto（X25519、HKDF、AES-GCM、scrypt）跑通了 Keyring 创建和 `hxdl.envelope.v1` 往返，`hxdl-swift` 已进入四端信封互通测试。

仍未完成，也不能假装完成：

- 本环境没有 Xcode，没有编过 iOS 或 macOS 目标。
- CryptoKit 没有 scrypt。Apple 目标也应依赖 swift-crypto，而不是把 scrypt 换成 CryptoKit。
- 流、清单、Ed25519 证明和 zxcvbn 不在这个包里。
