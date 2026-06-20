# HX-DataLock kotlin 用户侧 SDK

`sdk/kotlin` 是 HX-DataLock v1 的 Kotlin/JVM 用户侧 SDK。它对应规范里的 Android Kotlin User DataLock 范围：本地用户持有完整 Keyring 和 Master Password，可以打开 Data Envelope，也可以使用 Keyring 内的 Write Key 本地加密新 Payload Bytes。

> 目录名保留为 `kotlin`，以匹配当前仓库任务路径；包名使用 `com.hxdatalock`。

## 支持范围

- 创建 v1 Keyring。
- 从完整 Keyring 和 Master Password 创建 User DataLock。
- `openBytes` / `openText` / `openFile`。
- 本地 `lockBytes` / `lockText` / `lockFile`。
- NFC 规范化 Master Password。
- 读取 Python 和 Node/TypeScript SDK 生成的 v1 JSON 文档，按字段解析，不依赖字段顺序。
- 暴露稳定 `DataLockErrorCode`。

v1 不提供 Sender DataLock、Public Key Document 加密、CLI、分块文件、流式接口或平台 Keystore 集成。

## 快速示例

```kotlin
import com.hxdatalock.CreateKeyringOptions
import com.hxdatalock.HxDataLock

val password = "correct horse battery staple for hx datalock"
val keyring = HxDataLock.createKeyring(password, CreateKeyringOptions(scryptN = 16384))

HxDataLock.makeUserDataLock(keyring, password).use { user ->
    val envelope = user.lockText("你好，HX-DataLock")
    val plaintext = user.openText(envelope)
    check(plaintext == "你好，HX-DataLock")
}
```

生产默认 `scryptN` 为 `262144`。测试可以显式传入 `16384` 以缩短运行时间，生成的 Keyring 会记录实际参数。

## 运行测试

```bash
cd sdk/kotlin
gradle test
```

跨语言示例由仓库根目录的 pytest 测试驱动：

```bash
uv run pytest tests/kotlin/test_kotlin_sdk.py -q
```

## 示例

`examples/kotlin/OpenEnvelope.kt` 使用 Kotlin 打开 Python/Node 生成的 Data Envelope：

```bash
cd sdk/kotlin
gradle runOpenExample --quiet -PexampleArgs="/path/keyring.json|/path/envelope.json|/path/out.bin|master-password"
```

`examples/kotlin/LockEnvelope.kt` 使用 Kotlin 本地加密 Payload Bytes：

```bash
cd sdk/kotlin
gradle runLockExample --quiet -PexampleArgs="/path/keyring.json|/path/plain.bin|/path/envelope.json|master-password"
```
