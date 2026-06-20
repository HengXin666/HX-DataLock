# HX-DataLock Node SDK

HX-DataLock Node SDK 提供 v1 Keyring、Public Key Document 和 Data Envelope 的 Node.js API。它适合两类场景:

- 发送方: 只拿 Public Key Document 加密数据, 不能解密历史数据。
- 用户本地: 使用 Keyring 和主密码打开或再次加密数据。

Node SDK 和 Python SDK 使用同一种 JSON 文件格式, 可以跨语言生成、加密和解密。

## 安装

当前包位于仓库内的 `sdk/node`:

```sh
cd sdk/node
npm install
npm run build
```

在本仓库外使用本地包时, 可以从仓库路径安装:

```sh
npm install /path/to/HX-DataLock/sdk/node
```

发布到 npm 后, 使用包名安装:

```sh
npm install @hx/datalock
```

运行环境要求 Node.js 20 或更高版本。包是 ESM-only, 请使用 `import`。

## 快速开始

```js
import {
  createKeyring,
  exportPublicKeyDocument,
  makeSenderDataLock,
  makeUserDataLock,
} from '@hx/datalock';

const masterPassword = 'use-a-long-high-entropy-password';

const keyring = createKeyring(masterPassword);
keyring.write('keyring.hxdl.json');

const publicKey = exportPublicKeyDocument(keyring);
publicKey.write('public.hxdl.json');

const sender = makeSenderDataLock(publicKey);
const envelope = sender.lockText('hello from node');
envelope.write('message.hxdl.json');

const user = makeUserDataLock(keyring, { masterPassword });
const plaintext = user.openText(envelope);

console.log(plaintext);
```

## 文件加密

发送方只需要 Public Key Document:

```js
import {
  exportPublicKeyDocument,
  loadKeyring,
  makeSenderDataLock,
} from '@hx/datalock';

const keyring = loadKeyring('keyring.hxdl.json');
const publicKey = exportPublicKeyDocument(keyring);
publicKey.write('public.hxdl.json');

const sender = makeSenderDataLock(publicKey);
sender.lockFile('plain.txt', 'plain.txt.hxdl.json');
```

用户本地解密需要 Keyring 和主密码:

```js
import { loadKeyring, makeUserDataLock } from '@hx/datalock';

const keyring = loadKeyring('keyring.hxdl.json');
const user = makeUserDataLock(keyring, {
  masterPassword: process.env.HXDL_MASTER_PASSWORD,
});

user.openFile('plain.txt.hxdl.json', 'plain.opened.txt');
user.close();
```

## CLI

本地源码运行:

```sh
node sdk/node/hx-datalock.mjs init --keyring keyring.hxdl.json --password-env HXDL_MASTER_PASSWORD
node sdk/node/hx-datalock.mjs export-public --keyring keyring.hxdl.json --out public.hxdl.json
node sdk/node/hx-datalock.mjs lock --public public.hxdl.json --in plain.txt --out plain.txt.hxdl.json
node sdk/node/hx-datalock.mjs open --keyring keyring.hxdl.json --in plain.txt.hxdl.json --out plain.opened.txt --password-env HXDL_MASTER_PASSWORD
```

安装包后运行:

```sh
hxdl-node init --keyring keyring.hxdl.json --password-env HXDL_MASTER_PASSWORD
hxdl-node export-public --keyring keyring.hxdl.json --out public.hxdl.json
hxdl-node lock --public public.hxdl.json --in plain.txt --out plain.txt.hxdl.json
hxdl-node open --keyring keyring.hxdl.json --in plain.txt.hxdl.json --out plain.opened.txt --password-env HXDL_MASTER_PASSWORD
```

## API

### `createKeyring(masterPassword, options?)`

生成新的 Keyring。返回对象可调用 `write(path)` 写入 JSON 文件。

可选参数:

- `scryptN`: scrypt N 参数, 默认使用 SDK 内部 v1 默认值。

### `loadKeyring(path)`

从 JSON 文件读取并校验 Keyring。

### `exportPublicKeyDocument(keyring)`

从 Keyring 导出 Public Key Document。这个文档不包含 Read Key 材料, 可以交给只负责写入的发送方。

### `makeSenderDataLock(publicKeyDocument)`

创建发送方 DataLock。输入必须是 Public Key Document, 不能是完整 Keyring。

返回对象:

- `lockBytes(payloadBytes)`: 加密 `Buffer`、`Uint8Array` 或可转为 Buffer 的数据。
- `lockText(text)`: 加密 UTF-8 文本。
- `lockFile(inputPath, outputPath)`: 加密本地文件并写出 Data Envelope。

### `makeUserDataLock(keyring, { masterPassword })`

创建用户本地 DataLock。它会用主密码解封 Read Key。

返回对象:

- `openBytes(envelope)`: 解密 Data Envelope, 返回 `Buffer`。
- `openText(envelope)`: 解密 UTF-8 文本。
- `openFile(inputPath, outputPath)`: 解密文件。
- `lockBytes(payloadBytes)`: 使用自己的 Write Key 加密字节。
- `lockText(text)`: 使用自己的 Write Key 加密文本。
- `lockFile(inputPath, outputPath)`: 使用自己的 Write Key 加密文件。
- `close()`: 清除当前对象持有的解封 Read Key。

### `checkPasswordStrength(masterPassword)`

校验主密码强度。不满足要求时抛出 `DataLockError`。

### `DataLockError` 和 `DataLockErrorCode`

SDK 失败时会尽量抛出 `DataLockError`, 可通过 `error.code` 判断错误类型。

```js
import { DataLockError } from '@hx/datalock';

try {
  user.openFile('message.hxdl.json', 'message.txt');
} catch (error) {
  if (error instanceof DataLockError) {
    console.error(error.code, error.message);
  } else {
    throw error;
  }
}
```

## 公开导出

`@hx/datalock` 顶层入口只导出应用开发需要的 API:

- `createKeyring`
- `create_keyring`
- `loadKeyring`
- `exportPublicKeyDocument`
- `makeSenderDataLock`
- `makeUserDataLock`
- `checkPasswordStrength`
- `DataLockError`
- `DataLockErrorCode`

内部模块、常量、文档类、底层密码学 codec 和 CLI `main` 不作为包的公开 API。需要命令行能力时使用 `hxdl-node`。

## 限制

- v1 文件助手只支持 25 MB 以内的完整文件 Envelope。
- 不支持流式加密、分片 Envelope 或超大文件加密。
- 主密码不会被 SDK 保存。请使用高熵长口令, 最好由密码管理器生成。
