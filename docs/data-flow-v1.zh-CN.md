# HX-DataLock v1 加密与解密数据流

本文总结当前代码中从 Master Password 开始，到 Keyring 创建、Public Key Document 导出、Payload Bytes 加密成 Data Envelope、再解密回 Payload Bytes 的完整数据流。本文描述的是当前 v1 实现事实；规范性字段和算法仍以 [v1 spec](spec/v1.md) 为准。

## 边界

HX-DataLock 是 Crypto Codec，不是网站、数据库或同步 SDK。它只负责：

- 把应用传入的 Payload Bytes 加密成 Data Envelope。
- 把 Data Envelope 解密回 Payload Bytes。
- 维护 Keyring、Public Key Document、Data Envelope 这三类 JSON 文档格式。

业务对象、网站表单、JSON 序列化、数据库读写、Cloudflare D1、GitHub、缓存、冲突处理都在库外。应用如果要加密“网站数据”，必须先把该数据序列化成字节；Open 后再由应用把字节反序列化回业务对象。

## 运行时角色

- Master Password：用户记住的 Unicode 密码，只在本地用于解包 Read Key。
- Write Key：X25519 公钥，可加密新 Data Envelope，不能解密旧数据。
- Read Key：X25519 私钥，被 Master Password 派生出的 wrapping key 加密后存入 Keyring；解包后才能打开 Data Envelope。
- Keyring：完整用户文档，包含 Write Key 和 encrypted Read Key。
- Public Key Document：只包含 Write Key，给 Write-only Sender 使用。
- Sender DataLock：只持有 Public Key Document，只能 Lock。
- User DataLock：持有 Keyring，并用 Master Password 解包出 Read Key；可以 Open，也可以 Lock。
- Data Envelope：加密后的 payload 文档，可放在 Public Storage。

## 总览

```text
Keyring 创建:
Master Password
  -> NFC normalize + UTF-8
  -> scrypt(salt, N, r, p, keyLength=32)
  -> wrapping key
  -> AES-256-GCM 包裹 X25519 Read Key
  -> Keyring(JSON)

加密 Lock:
Payload Bytes + Write Key
  -> 生成一次性 X25519 ephemeral key pair
  -> X25519(ephemeral private, recipient Write Key)
  -> HKDF-SHA256(shared secret, hkdfSalt, info)
  -> content key
  -> AES-256-GCM 加密 Payload Bytes
  -> Data Envelope(JSON)

解密 Open:
Master Password + Keyring
  -> NFC normalize + UTF-8
  -> scrypt 使用 Keyring 内记录的 kdf 参数
  -> wrapping key
  -> AES-256-GCM 解包 Read Key
  -> X25519(Read Key, envelope ephemeral public key)
  -> HKDF-SHA256(shared secret, envelope hkdfSalt, info)
  -> content key
  -> AES-256-GCM 打开 Data Envelope
  -> Payload Bytes
```

## 1. Master Password 到 Keyring

入口：

- Python: `create_keyring(master_password, scrypt_n=...)`
- Node: `createKeyring(masterPassword, { scryptN })`
- Kotlin: `HxDataLock.createKeyring(masterPassword, CreateKeyringOptions(...))`

流程：

1. Python/Node full SDK 先运行 Password Strength Policy。v1 只产生 Password Strength Report，不阻止弱密码继续创建 Keyring。Kotlin v1 不暴露 Password Strength Report。
2. 校验 `scryptN`：必须是 2 的幂且不小于 `16384`。默认值是 `2^18 = 262144`。
3. 生成一对 X25519 密钥：
   - 公钥是 Write Key。
   - 私钥是 Read Key。
4. 将 Write Key 编码成 DER SPKI。
5. 计算 Recipient Key ID：

```text
x25519:<first 22 chars of base64url(sha256(publicWriteKey.spki DER)) without padding>
```

6. 构造 KDF 参数：

```json
{
  "name": "scrypt",
  "salt": "<base64 32 bytes>",
  "N": 262144,
  "r": 8,
  "p": 1,
  "keyLength": 32
}
```

7. Master Password 先做 Unicode NFC 规范化，再 UTF-8 编码。
8. 用 scrypt 派生 32 字节 wrapping key。
9. 将 Read Key 编码为 DER PKCS8。
10. 使用 AES-256-GCM 加密 DER PKCS8 Read Key：
    - key: 第 8 步得到的 wrapping key。
    - nonce: 随机 12 字节。
    - tag: 16 字节认证标签。
    - AAD:

```text
hxdl.keyring.v1:<keyId>:scrypt:AES-256-GCM
```

11. 产出 Keyring。

Keyring 结构：

```json
{
  "schema": "hxdl.keyring.v1",
  "createdAt": "<UTC timestamp>",
  "publicWriteKey": {
    "alg": "X25519",
    "keyId": "x25519:<hash>",
    "spki": "<base64 DER SPKI>"
  },
  "encryptedReadKey": {
    "kdf": {
      "name": "scrypt",
      "salt": "<base64 32 bytes>",
      "N": 262144,
      "r": 8,
      "p": 1,
      "keyLength": 32
    },
    "aead": {
      "name": "AES-256-GCM",
      "nonce": "<base64 12 bytes>",
      "tag": "<base64 16 bytes>"
    },
    "ciphertext": "<base64 encrypted DER PKCS8 Read Key>"
  }
}
```

重要细节：

- Master Password 不写入 Keyring、Public Key Document、Data Envelope。
- Keyring 应作为私有本地文件保存和备份。如果完整 Keyring 被复制，攻击者可以离线猜 Master Password 来尝试解封 encrypted Read Key。
- 适合放入 GitHub Actions、对象存储或其他公共/自动化环境的是 Public Key Document，不是完整 Keyring。
- Write Key 是 X25519 公钥；Read Key 是匹配私钥，被 Master Password 加密后存在 Keyring 中。Write-only Sender 能用 Write Key Lock 新 Data Envelope，但不能从 Write Key 推导出 Read Key，也不能 Open 已有密文。
- `createdAt` 是展示和调试元数据，不参与 AAD，不是业务时间戳。
- SDK 不缓存 Master Password。User DataLock 会缓存解包后的 Read Key，直到 `close()` 或对象释放。

## 2. Keyring 到 Public Key Document

入口：

- Python: `export_public_key_document(keyring)`
- Node: `exportPublicKeyDocument(keyring)`
- Kotlin: `HxDataLock.exportPublicKeyDocument(keyring)`

流程：

1. 校验 Keyring。
2. 复制 `publicWriteKey`。
3. 生成 Public Key Document。
4. 确认文档不包含 `encryptedReadKey`。

Public Key Document 结构：

```json
{
  "schema": "hxdl.publicKey.v1",
  "createdAt": "<UTC timestamp>",
  "publicWriteKey": {
    "alg": "X25519",
    "keyId": "x25519:<hash>",
    "spki": "<base64 DER SPKI>"
  }
}
```

流向含义：

- Write-only Sender 只能拿 Public Key Document。
- Write-only Sender 不需要、也不能拿 Master Password。
- Write-only Sender 不需要、也不能拿 full Keyring 或 encrypted Read Key。
- Public Key Document 泄漏不会让攻击者解密已有 Data Envelope，但任何拿到它的人都可以为该 Recipient Key ID 创建新的 Data Envelope。

## 3. Lock：Payload Bytes 到 Data Envelope

入口：

- Sender DataLock:
  - Python/Node: `makeSenderDataLock(publicKeyDocument).lockBytes(payloadBytes)`
- User DataLock:
  - Python/Node/Kotlin: `makeUserDataLock(...).lockBytes(payloadBytes)` 或等价 Kotlin API。
- 兼容/便捷 API:
  - Python: `encrypt_message(keyring, plaintext)`、`send_file(...)`

核心流程：

1. 应用将网站数据序列化成 Payload Bytes。Crypto Codec 不理解业务对象。
2. SDK 校验 Public Key Document 或 Keyring 中的 Write Key：
   - `publicWriteKey.alg` 必须是 `X25519`。
   - `publicWriteKey.spki` 必须是可解析的 DER SPKI X25519 公钥。
   - `publicWriteKey.keyId` 必须等于 SPKI 派生出的 key ID。
3. 生成一次性 X25519 ephemeral key pair。
4. 用 ephemeral private key 和 recipient Write Key 做 X25519 key agreement，得到 shared secret。
5. 生成随机 32 字节 `hkdfSalt`。
6. 用 HKDF-SHA256 派生 32 字节 content key：

```text
input key material = shared secret
salt = hkdfSalt
info = "hxdl.envelope.v1:<recipientKeyId>"
length = 32
```

7. 生成随机 12 字节 AES-GCM nonce。
8. 使用 AES-256-GCM 加密 Payload Bytes：
   - key: content key。
   - nonce: 第 7 步 nonce。
   - plaintext: Payload Bytes。
   - tag: 16 字节认证标签。
   - AAD:

```text
hxdl.envelope.v1:<recipientKeyId>:X25519:HKDF-SHA256:AES-256-GCM
```

9. 将 ephemeral public key 编码成 DER SPKI。
10. 产出 Data Envelope。

Data Envelope 结构：

```json
{
  "schema": "hxdl.envelope.v1",
  "createdAt": "<UTC timestamp>",
  "recipientKeyId": "x25519:<hash>",
  "alg": {
    "kem": "X25519",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM"
  },
  "ephemeralPublicKey": "<base64 DER SPKI>",
  "hkdfSalt": "<base64 32 bytes>",
  "nonce": "<base64 12 bytes>",
  "tag": "<base64 16 bytes>",
  "ciphertext": "<base64 encrypted payload bytes>"
}
```

重要细节：

- Lock 不使用 Master Password。
- Lock 不使用 Read Key。
- Sender DataLock 没有 Open API。
- User DataLock 的 `lockBytes` 目前要求 User DataLock 仍处于打开状态，但实际加密仍只使用 Keyring 里的 Write Key。
- 每次 Lock 都生成新的 ephemeral key、HKDF salt 和 AES-GCM nonce。
- v1 是 Full Data Envelope：一次加密完整 Payload Bytes，不做分块。
- 文件 helper 读取整个文件；超过 25 MB 拒绝。
- v1 不压缩，不填充长度。Public Storage 观察者可看到 Data Envelope 大小、Creation Time、Recipient Key ID 和算法字段。

## 4. Open：Master Password 和 Data Envelope 到 Payload Bytes

入口：

- Python/Node: `makeUserDataLock(keyring, { masterPassword }).openBytes(envelope)`
- Kotlin: `HxDataLock.makeUserDataLock(keyring, masterPassword).openBytes(envelope)`
- 兼容/便捷 API:
  - Python: `decrypt_message(keyring, master_password, envelope)`、`open_file(...)`

解包 Read Key：

1. 校验 Keyring schema、encrypted Read Key、KDF、AEAD 和 Write Key。
2. Master Password 做 Unicode NFC 规范化，再 UTF-8 编码。
3. 使用 Keyring 中记录的 `encryptedReadKey.kdf` 参数运行 scrypt，派生 wrapping key。
4. 用 AES-256-GCM 打开 `encryptedReadKey.ciphertext`：
   - key: wrapping key。
   - nonce: `encryptedReadKey.aead.nonce`。
   - ciphertext: `encryptedReadKey.ciphertext`。
   - tag: `encryptedReadKey.aead.tag`。
   - AAD:

```text
hxdl.keyring.v1:<keyId>:scrypt:AES-256-GCM
```

5. 解密成功后得到 DER PKCS8 Read Key，并解析为 X25519 private key。
6. 如果 Master Password 错误，或 Keyring 被篡改，AES-GCM 认证失败，抛出 `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`。
7. User DataLock 缓存 Read Key，不缓存 Master Password。

打开 Data Envelope：

1. 校验 Data Envelope schema 和算法：

```json
{
  "kem": "X25519",
  "kdf": "HKDF-SHA256",
  "aead": "AES-256-GCM"
}
```

2. 检查 `recipientKeyId` 必须等于 Keyring 的 `keyId`，否则抛出 `ENVELOPE_RECIPIENT_MISMATCH`。
3. 解析 `ephemeralPublicKey` 为 X25519 公钥。
4. 用 Read Key 和 envelope ephemeral public key 做 X25519 key agreement，得到 shared secret。
5. 使用 envelope 内的 `hkdfSalt` 和同样的 HKDF info 派生 content key：

```text
input key material = shared secret
salt = envelope.hkdfSalt
info = "hxdl.envelope.v1:<recipientKeyId>"
length = 32
```

6. 用 AES-256-GCM 打开 payload：
   - key: content key。
   - nonce: `envelope.nonce`。
   - ciphertext: `envelope.ciphertext`。
   - tag: `envelope.tag`。
   - AAD:

```text
hxdl.envelope.v1:<recipientKeyId>:X25519:HKDF-SHA256:AES-256-GCM
```

7. 解密成功后返回 Payload Bytes。
8. 如果 envelope 任何认证相关字段被篡改，或 ciphertext/tag/nonce 不匹配，抛出 `TAMPERED_ENVELOPE`。

重要细节：

- Open 必须发生在 User DataLock 中。
- Open 需要 Master Password 的目的只是解包 Read Key；payload 本身不是直接用 Master Password 加密。
- `createdAt` 不参与认证，不能当作安全时间戳或冲突版本。
- Text helper 在 Open 后严格按 UTF-8 解码；无效 UTF-8 抛出 `INVALID_UTF8`。
- `close()` 会丢弃 User DataLock 对 Read Key 的引用；托管运行时内存清零只能是 best effort。

## 5. 存储可见与不可见数据

可放入 Public Storage 的内容：

- Public Key Document。
- Data Envelope。

应作为私有本地文件保存和备份的内容：

- Keyring。

Public Storage 可见内容：

- schema。
- createdAt。
- Recipient Key ID / Write Key ID。
- 算法标识。
- Write Key 公钥。
- Data Envelope 的 ephemeral public key、HKDF salt、AES-GCM nonce/tag、ciphertext。
- Data Envelope 大小和近似 payload 大小。

如果完整 Keyring 被复制，攻击者还会看到 encrypted Read Key 的 KDF 参数、salt、AEAD nonce/tag 和 ciphertext，并可以离线猜 Master Password。

Public Storage 不应得到：

- Master Password。
- 解包后的 Read Key。
- wrapping key。
- content key。
- plaintext Payload Bytes。
- 业务对象的明文 JSON。

## 6. 字段认证边界

Keyring encrypted Read Key 的 AAD 绑定：

- Keyring schema。
- Write Key ID。
- wrapping KDF 名称。
- wrapping AEAD 名称。

Data Envelope 的 AAD 绑定：

- Envelope schema。
- Recipient Key ID。
- KEM 名称。
- KDF 名称。
- AEAD 名称。

不在 AAD 中的字段：

- `createdAt`。
- JSON 格式化、缩进和字段顺序。

因此，安全相关的 schema、key ID、算法字段变动会导致认证失败或验证失败；展示型元数据变动不应破坏解密兼容性。

## 7. 代码位置

Python:

- `sdk/py/src/hx_datalock/sdk.py`: Keyring 创建、Public Key Document 导出、User/Sender DataLock 构造、便捷 API。
- `sdk/py/src/hx_datalock/crypto_codec.py`: scrypt、X25519、HKDF-SHA256、AES-256-GCM、AAD、base64。
- `sdk/py/src/hx_datalock/datalocks.py`: `lockBytes`、`openBytes`、文件 helper、`close()`。
- `sdk/py/src/hx_datalock/documents.py`: Keyring、Public Key Document、Data Envelope 校验。

Node:

- `sdk/node/src/sdk.ts`
- `sdk/node/src/crypto-codec.ts`
- `sdk/node/src/datalocks.ts`
- `sdk/node/src/documents.ts`

Kotlin:

- `sdk/kotlin/src/main/kotlin/com/hxdatalock/HxDataLock.kt`
- `sdk/kotlin/src/main/kotlin/com/hxdatalock/CryptoCodec.kt`
- `sdk/kotlin/src/main/kotlin/com/hxdatalock/Documents.kt`

相关文档：

- [v1 specification](spec/v1.md)
- [ADR 0001: Password-wrapped X25519 Keyring](adr/0001-password-wrapped-x25519-keyring.md)
- [ADR 0002: NFC-normalized Master Passwords](adr/0002-nfc-normalized-master-passwords.md)
- [ADR 0004: Separate Sender and User DataLock APIs](adr/0004-separate-sender-and-user-datalock-apis.md)
- [ADR 0005: Minimize Master Password Residency](adr/0005-minimize-master-password-residency.md)
- [ADR 0006: Crypto Codec Boundary](adr/0006-crypto-codec-boundary.md)
- [ADR 0009: Public Key Document for Senders](adr/0009-public-key-document-for-senders.md)
- [ADR 0015: AAD Binds Schema, Key, and Algorithm](adr/0015-aad-binds-schema-key-and-algorithm.md)
