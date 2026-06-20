# HX-DataLock

HX-DataLock 是一个"可写不可读"的通用加解密项目骨架。

它把信任边界拆成三层:

- GitHub 私有仓库: 存储 `Keyring`。里面有可公开的 `Write Key`, 以及被主密码加密包裹的 `Read Key`。
- 公共存储: 网盘、Cloudflare D1 等, 只存储 `Data Envelope` 密文。
- 用户本地: 用户输入主密码, 解封 `Read Key`, 再解密公共存储中的密文。

最重要的一点: 主密码只在本地输入。GitHub Actions 只验证文件格式和跑互通测试, 不接触真实主密码。

## 安全模型

本项目目标是做到:

- 泄露公共存储, 不泄露明文。
- 泄露 GitHub 中的 `keyring.hxdl.json`, 攻击者只能拿到加密能力, 不能直接解密历史数据。
- 拥有 `Write Key` 的发送方可以生成新密文, 但不能解密已有密文。
- 用户本地拥有主密码时, 才能解封 `Read Key` 并读取数据。

这不是"绝对安全"。如果主密码很弱, 攻击者拿到 `keyring.hxdl.json` 后可以离线猜密码。要保护高价值数据, 主密码必须是高熵长口令, 最好由密码管理器生成。

## 密码学结构

- `Write Key` / `Read Key`: X25519
- 内容密钥派生: HKDF-SHA256
- 内容加密: AES-256-GCM
- 主密码派生: scrypt
- `Read Key` 包裹: AES-256-GCM

## 安装 Python SDK

```powershell
uv sync --dev
```

## 仓库布局

- `sdk/py/`: Python SDK 和 CLI 包源码。
- `sdk/node/`: Node TypeScript SDK / CLI 源码。`src/index.ts` 是简洁 SDK 入口, `hx-datalock.mjs` 保留为兼容 CLI / ESM 入口。
- `examples/py/`: Python 使用示例。
- `tests/py/`: Python SDK / CLI 测试。
- `tests/compat/`: Python 与 Node 的跨 SDK 兼容测试。
- `tests/workflows/`: GitHub Actions workflow 契约测试。

TypeScript SDK 和 Android Kotlin SDK 还没有真实源码；对应缺口记录在 `.scratch/v1-spec/issues/11-implementation-gap-typescript-android-v1.md`。

## 1. 本地生成 GitHub 存储的 Keyring

```powershell
uv run hxdl init --keyring keyring.hxdl.json
```

也可以使用本地交互脚本:

```sh
sh scripts/hxdl-local.sh
```

这个脚本适合 macOS、Linux、Git Bash 或 WSL。Windows PowerShell 下可以直接使用上面的 `uv run hxdl ...` 命令。

把生成的 `keyring.hxdl.json` 提交到 GitHub 私有仓库。这个文件包含 `Write Key` 和被主密码包裹的 `Read Key`:

- 用户本地可以用它和主密码打开 `Data Envelope`。
- 写入方不要使用完整 `Keyring`。先导出 `Public Key Document`, 再把该公开文档交给写入方。

```powershell
uv run hxdl export-public --keyring keyring.hxdl.json --out public.hxdl.json
```

## 2. 发送方加密消息

发送方只需要 `public.hxdl.json`, 不需要主密码:

```powershell
uv run hxdl lock --public public.hxdl.json --in message.txt --out message.hxdl.json
```

输出的 `message.hxdl.json` 是 `Data Envelope`, 可以放到网盘、Cloudflare D1 或其他公共存储。

业务代码也只需要调用文件级 API:

```python
from hx_datalock import send_file

send_file("keyring.hxdl.json", "message.txt", "message.hxdl.json")
```

## 3. 用户本地解密消息

解密方需要 `keyring.hxdl.json` 和主密码:

```powershell
uv run hxdl open --keyring keyring.hxdl.json --in message.hxdl.json --out message.txt
```

也可以通过环境变量传入主密码, 适合本地自动化:

```powershell
$env:HXDL_MASTER_PASSWORD="你的高熵主密码"
uv run hxdl open --keyring keyring.hxdl.json --in message.hxdl.json --out message.txt --password-env HXDL_MASTER_PASSWORD
```

业务代码调用方式:

```python
from hx_datalock import open_file

open_file("keyring.hxdl.json", "message.hxdl.json", "message.txt", "你的高熵主密码")
```

## Node v1 CLI / SDK 互通

Node CLI 和 Python SDK 使用同一种 `Keyring` / `Data Envelope` 格式, 因此可以交叉使用:

```powershell
node sdk/node/hx-datalock.mjs export-public --keyring keyring.hxdl.json --out public.hxdl.json
node sdk/node/hx-datalock.mjs lock --public public.hxdl.json --in message.txt --out message.hxdl.json
uv run hxdl open --keyring keyring.hxdl.json --in message.hxdl.json --out message.txt
```

```powershell
uv run hxdl export-public --keyring keyring.hxdl.json --out public.hxdl.json
uv run hxdl lock --public public.hxdl.json --in message.txt --out message.hxdl.json
node sdk/node/hx-datalock.mjs open --keyring keyring.hxdl.json --in message.hxdl.json --out message.txt --password-env HXDL_MASTER_PASSWORD
```

Node 模块只导出应用开发需要的 v1 SDK surface: `createKeyring`, `loadKeyring`, `exportPublicKeyDocument`, `checkPasswordStrength`, `makeSenderDataLock`, `makeUserDataLock`, `DataLockError` 和 `DataLockErrorCode`。源码入口是 `sdk/node/src/index.ts`, 兼容运行入口仍然是 `sdk/node/hx-datalock.mjs`; 详细 API 文档见 `sdk/node/README.md`。

旧命令 `public-key`, `encrypt`, `decrypt` 不是 v1 CLI, 当前入口会提示改用 `export-public`, `lock`, `open`。

## 性能与文件上限

v1 只支持单个完整 `Full Data Envelope`, 本地文件助手拒绝超过 25 MB 的文件并返回 `OVERSIZED_FILE`。不支持 `Chunked File Envelope`, 流式 API, 100 MB, 1 GB 或 10 GB 性能承诺。

本地复现基准:

```powershell
uv run hxdl bench --keyring keyring.hxdl.json --password-env HXDL_MASTER_PASSWORD
node sdk/node/hx-datalock.mjs bench --keyring keyring.hxdl.json --password-env HXDL_MASTER_PASSWORD
```

基准输出为 JSON lines, 覆盖 `unlockKeyring`, `lockBytes`, `openBytes`, `lockFile`, `openFile`, 默认测量 1 MB, 10 MB 和 25 MB。输出用于本机观察, 不是硬性性能保证。

## GitHub Workflow

`.github/workflows/keyring-check.yml` 会做两件事:

- 验证提交的 `keyring.hxdl.json` 格式正确。
- 检查没有明显提交裸私钥。

`.github/workflows/sdk-tests.yml` 专门运行 SDK 测试:

- Python SDK / CLI 测试: `tests/py/`
- Node SDK surface 测试
- Python 与 Node 的跨 SDK 兼容测试: `tests/compat/`

Workflow 使用测试密码生成临时测试 Keyring, 不会接触你的真实主密码。

本地验证:

```powershell
uv run pytest -q
```
