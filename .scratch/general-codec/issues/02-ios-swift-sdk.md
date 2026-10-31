# iOS Swift SDK

Status: 部分落地

`sdk/swift` 在 Linux 上覆盖 Keyring 创建和 rewrap、`hxdl.envelope.v1`、`hxdl.stream.v1`、`hxdl.manifest.v1`、Ed25519 attestation / signed manifest，以及与另外三端相同的 46/80 bit 口令门槛。zxcvbn 是纯 Swift 移植，修了 Linux 上 JSON null 强制转换会中止进程的问题。

仍未完成：

- 本环境没有 Xcode，没有编过 iOS 或 macOS 目标。
- CryptoKit 没有 scrypt。Apple 目标继续用 swift-crypto。
