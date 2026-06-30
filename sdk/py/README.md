# HX-DataLock Python SDK

HX-DataLock Python SDK 提供 v1 Keyring、Public Key Document 和 Data Envelope 的 Python API。它适合两类场景:

- 发送方: 只拿 Public Key Document 加密数据, 不能解密历史数据。
- 用户本地: 使用 Keyring 和主密码打开或再次加密数据。

Python SDK 和 Node SDK 使用同一种 JSON 文件格式, 可以跨语言生成、加密和解密。

## 安装

### 安装 uv

本仓库推荐使用 `uv` 管理 Python 环境和命令运行。

macOS / Linux:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

安装后确认:

```sh
uv --version
```

### 本仓库开发安装

在仓库根目录运行:

```sh
uv sync --dev
```

这会安装 Python SDK、CLI 入口 `hxdl` 和测试依赖。

本地验证:

```sh
uv run pytest -q
```

### 在外部项目使用本地 SDK

当前包位于仓库内的 `sdk/py`。在另一个 Python 项目中, 可以从仓库路径安装:

```sh
uv add /path/to/HX-DataLock
```

如果只想临时运行仓库内 CLI, 不需要进入虚拟环境:

```sh
uv run hxdl --help
```

运行环境要求 Python 3.10 或更高版本。

## 快速开始

```python
from hx_datalock import (
    create_keyring,
    export_public_key_document,
    makeSenderDataLock,
    makeUserDataLock,
)

master_password = "use-a-long-high-entropy-password"

keyring = create_keyring(master_password)
keyring.write("keyring.hxdl.json")

public_key = export_public_key_document(keyring)
public_key.write("public.hxdl.json")

sender = makeSenderDataLock(public_key)
envelope = sender.lockText("hello from python")
envelope.write("message.hxdl.json")

user = makeUserDataLock(keyring, {"masterPassword": master_password})
plaintext = user.openText(envelope)
user.close()

print(plaintext)
```

## 文件加密

发送方只需要 Public Key Document:

```python
from hx_datalock import (
    export_public_key_document,
    load_keyring,
    makeSenderDataLock,
)

keyring = load_keyring("keyring.hxdl.json")
public_key = export_public_key_document(keyring)
public_key.write("public.hxdl.json")

sender = makeSenderDataLock(public_key)
sender.lockFile("plain.txt", "plain.txt.hxdl.json")
```

用户本地解密需要 Keyring 和主密码:

```python
import os

from hx_datalock import load_keyring, makeUserDataLock

keyring = load_keyring("keyring.hxdl.json")
user = makeUserDataLock(
    keyring,
    {"masterPassword": os.environ["HXDL_MASTER_PASSWORD"]},
)

user.openFile("plain.txt.hxdl.json", "plain.opened.txt")
user.close()
```

也可以使用简单文件级 API。发送方文件助手必须传入 `Public Key Document`, 不能传入完整 `Keyring`:

```python
from hx_datalock import open_file, send_file_with_public_doc

send_file_with_public_doc("public.hxdl.json", "plain.txt", "plain.txt.hxdl.json")
open_file("keyring.hxdl.json", "plain.txt.hxdl.json", "plain.opened.txt", "master password")
```

## CLI

本地源码运行:

```sh
uv run hxdl init --keyring keyring.hxdl.json --password-env HXDL_MASTER_PASSWORD
uv run hxdl export-public --keyring keyring.hxdl.json --out public.hxdl.json
uv run hxdl lock --public public.hxdl.json --in plain.txt --out plain.txt.hxdl.json
uv run hxdl open --keyring keyring.hxdl.json --in plain.txt.hxdl.json --out plain.opened.txt --password-env HXDL_MASTER_PASSWORD
```

安装包后运行同一个入口:

```sh
hxdl init --keyring keyring.hxdl.json --password-env HXDL_MASTER_PASSWORD
hxdl export-public --keyring keyring.hxdl.json --out public.hxdl.json
hxdl lock --public public.hxdl.json --in plain.txt --out plain.txt.hxdl.json
hxdl open --keyring keyring.hxdl.json --in plain.txt.hxdl.json --out plain.opened.txt --password-env HXDL_MASTER_PASSWORD
```

SDK 不读取环境变量。只有 CLI 会在传入 `--password-env` 时读取指定环境变量。

## API

### `create_keyring(master_password, *, scrypt_n=DEFAULT_SCRYPT_N)`

生成新的 Keyring。返回对象可调用 `write(path)` 写入 JSON 文件。

可选参数:

- `scrypt_n`: scrypt N 参数, 默认使用 SDK 内部 v1 默认值。

### `load_keyring(path)`

从 JSON 文件读取并校验 Keyring。

### `export_public_key_document(keyring)`

从 Keyring 导出 Public Key Document。这个文档不包含 Read Key 材料, 可以交给只负责写入的发送方。

### `makeSenderDataLock(publicKeyDocument)`

创建发送方 DataLock。输入必须是 Public Key Document, 不能是完整 Keyring。

返回对象:

- `lockBytes(payload_bytes)`: 加密 `bytes`。
- `lockText(text)`: 加密 UTF-8 文本。
- `lockFile(input_path, output_path)`: 加密本地文件并写出 Data Envelope。

### `makeUserDataLock(keyring, {"masterPassword": master_password})`

创建用户本地 DataLock。它会用主密码解封 Read Key。

返回对象:

- `openBytes(envelope)`: 解密 Data Envelope, 返回 `bytes`。
- `openText(envelope)`: 解密 UTF-8 文本。
- `openFile(input_path, output_path)`: 解密文件。
- `lockBytes(payload_bytes)`: 使用自己的 Write Key 加密字节。
- `lockText(text)`: 使用自己的 Write Key 加密文本。
- `lockFile(input_path, output_path)`: 使用自己的 Write Key 加密文件。
- `close()`: 清除当前对象持有的解封 Read Key。

### `send_file_with_public_doc(public_key_document_path, input_path, output_path)`

使用 Public Key Document 加密本地文件并写出 Data Envelope。推荐发送方环境使用这个 helper, 避免把完整 Keyring 传入写入环境。

### `send_file(keyring_path, input_path, output_path)`

兼容 v1 早期代码的本地文件 helper。它会从完整 Keyring 读取 Write Key 加密文件, 仅适合已经持有完整 Keyring 的本地用户环境。

### `check_password_strength(master_password)`

返回 Password Strength Report。弱主密码会产生 warnings 和 suggestions, 但 v1 不阻止创建 Keyring。

### `DataLockError` 和 `DataLockErrorCode`

SDK 失败时会尽量抛出 `DataLockError`, 可通过 `error.code` 判断错误类型。

```python
from hx_datalock import DataLockError

try:
    user.openFile("message.hxdl.json", "message.txt")
except DataLockError as error:
    print(error.code, str(error))
```

## 公开导出

`hx_datalock` 顶层入口只导出应用开发需要的 v1 SDK surface:

- `create_keyring`
- `init_keyring`
- `load_keyring`
- `export_public_key_document`
- `makeSenderDataLock`
- `makeUserDataLock`
- `check_password_strength`
- `DataLockError`
- `DataLockErrorCode`
- `Keyring`
- `PublicKeyDocument`
- `DataEnvelope`
- `SenderDataLock`
- `UserDataLock`
- `verify_keyring_file`
- `verify_public_key_document_file`
- `encrypt_message`
- `encrypt_message_for_sender`
- `decrypt_message`
- `send_file`
- `send_file_with_public_doc`
- `open_file`
- `make_v1_compatibility_manifest`

内部模块、常量、底层密码学 codec 和 CLI `main` 不作为包的公开 API。需要命令行能力时使用 `hxdl`。

## 内部模块布局

- `errors.py`: 稳定的 `DataLockError` 和 `DataLockErrorCode`。
- `constants.py`: v1 schema、算法标识、KDF 默认值和文件上限。
- `json.py`: 稳定 JSON 输出和字段解析输入。
- `crypto_codec.py`: base64、AAD、密钥派生、Write Key 校验、Keyring 解封和 Data Envelope lock/open primitives。
- `documents.py`: `Keyring`、`PublicKeyDocument` 和 `DataEnvelope`。
- `datalocks.py`: `SenderDataLock` 和 `UserDataLock`。
- `password_strength.py`: Password Strength Report 和本地强度策略。
- `compatibility.py`: v1 跨语言兼容 manifest。
- `sdk.py`: public orchestration functions 和兼容 helper。
- `__init__.py`: package-level exports。

## 限制

- v1 文件助手只支持 25 MB 以内的完整文件 Envelope。
- 不支持流式加密、分片 Envelope 或超大文件加密。
- 主密码不会被 SDK 保存。请使用高熵长口令, 最好由密码管理器生成。
