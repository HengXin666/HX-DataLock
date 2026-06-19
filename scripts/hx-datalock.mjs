#!/usr/bin/env node
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { mkdirSync } from 'node:fs';
import { stdin as input, stdout as output } from 'node:process';

const KEYRING_SCHEMA = 'hxdl.keyring.v1';
const ENVELOPE_SCHEMA = 'hxdl.envelope.v1';
const DEFAULT_KEYRING = 'keyring.hxdl.json';
const DEFAULT_SCRYPT_N = 2 ** 18;
const DEFAULT_SCRYPT_R = 8;
const DEFAULT_SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 32;

function usage() {
  console.log(`HX-DataLock

Usage:
  node scripts/hx-datalock.mjs init [--out keyring.hxdl.json] [--password-env NAME] [--scrypt-n N]
  node scripts/hx-datalock.mjs verify-keyring [--keyring keyring.hxdl.json]
  node scripts/hx-datalock.mjs public-key [--keyring keyring.hxdl.json] [--out public-key.hxdl.json]
  node scripts/hx-datalock.mjs encrypt --in plain.bin --out sealed.hxdl.json [--keyring keyring.hxdl.json]
  node scripts/hx-datalock.mjs decrypt --in sealed.hxdl.json --out plain.bin [--keyring keyring.hxdl.json] [--password-env NAME]

Security notes:
  - Run init and decrypt only on a trusted local machine.
  - GitHub should store the Keyring, but should never receive the Master Password.
  - A weak Master Password is vulnerable to offline guessing if the Keyring leaks.
`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i];
    if (!token.startsWith('--')) {
      throw new Error(`Unexpected argument: ${token}`);
    }
    const key = token.slice(2);
    const next = rest[i + 1];
    if (!next || next.startsWith('--')) {
      options[key] = true;
    } else {
      options[key] = next;
      i += 1;
    }
  }
  return { command, options };
}

async function readPassword(options, prompt = 'Master password: ') {
  if (options['password-env']) {
    const value = process.env[options['password-env']];
    if (!value) {
      throw new Error(`Environment variable ${options['password-env']} is empty or missing`);
    }
    return value;
  }

  if (!input.isTTY || !output.isTTY) {
    throw new Error('Interactive password input requires a TTY; use --password-env for automation');
  }

  output.write(prompt);
  input.setRawMode(true);
  input.resume();
  input.setEncoding('utf8');

  return await new Promise((resolvePassword, rejectPassword) => {
    let password = '';

    function cleanup() {
      input.setRawMode(false);
      input.pause();
      input.off('data', onData);
      output.write('\n');
    }

    function onData(chunk) {
      if (chunk === '\u0003') {
        cleanup();
        rejectPassword(new Error('Password input cancelled'));
        return;
      }
      if (chunk === '\r' || chunk === '\n' || chunk === '\r\n') {
        cleanup();
        resolvePassword(password);
        return;
      }
      if (chunk === '\b' || chunk === '\u007f') {
        password = password.slice(0, -1);
        return;
      }
      password += chunk;
    }

    input.on('data', onData);
  });
}

function b64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

function fromB64(text, field) {
  if (typeof text !== 'string') {
    throw new Error(`Missing base64 field: ${field}`);
  }
  return Buffer.from(text, 'base64');
}

function sha256Base64Url(buffer) {
  return createHash('sha256').update(buffer).digest('base64url');
}

function aadForKeyring(keyId) {
  return Buffer.from(`${KEYRING_SCHEMA}:${keyId}:scrypt:AES-256-GCM`, 'utf8');
}

function aadForEnvelope(keyId) {
  return Buffer.from(`${ENVELOPE_SCHEMA}:${keyId}:X25519:HKDF-SHA256:AES-256-GCM`, 'utf8');
}

function derivePasswordKey(password, kdf) {
  if (kdf.name !== 'scrypt') {
    throw new Error(`Unsupported password KDF: ${kdf.name}`);
  }
  return scryptSync(password, fromB64(kdf.salt, 'kdf.salt'), kdf.keyLength, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: Math.max(512 * 1024 * 1024, 256 * kdf.N * kdf.r),
  });
}

function encryptAesGcm(key, plaintext, aad) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

function decryptAesGcm(key, sealed, aad) {
  const decipher = createDecipheriv('aes-256-gcm', key, sealed.nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.tag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function getKeyringPath(options) {
  return options.keyring || options.out || DEFAULT_KEYRING;
}

function assertKeyring(keyring) {
  if (keyring.schema !== KEYRING_SCHEMA) {
    throw new Error(`Unsupported keyring schema: ${keyring.schema}`);
  }
  if (keyring.publicWriteKey?.alg !== 'X25519') {
    throw new Error('Keyring publicWriteKey must be X25519');
  }
  if (keyring.encryptedReadKey?.aead?.name !== 'AES-256-GCM') {
    throw new Error('Keyring encryptedReadKey must use AES-256-GCM');
  }

  const publicDer = fromB64(keyring.publicWriteKey.spki, 'publicWriteKey.spki');
  const expectedKeyId = `x25519:${sha256Base64Url(publicDer).slice(0, 22)}`;
  if (!timingSafeEqual(Buffer.from(keyring.publicWriteKey.keyId), Buffer.from(expectedKeyId))) {
    throw new Error('Keyring keyId does not match the Write Key');
  }

  createPublicKey({ key: publicDer, format: 'der', type: 'spki' });
}

async function commandInit(options) {
  const password = await readPassword(options);
  if (password.length < 16) {
    throw new Error('Master Password must be at least 16 characters; use a long passphrase');
  }

  const scryptN = Number(options['scrypt-n'] || DEFAULT_SCRYPT_N);
  if (!Number.isInteger(scryptN) || scryptN < 2 ** 14 || (scryptN & (scryptN - 1)) !== 0) {
    throw new Error('--scrypt-n must be a power of two and at least 16384');
  }

  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const keyId = `x25519:${sha256Base64Url(publicDer).slice(0, 22)}`;
  const kdf = {
    name: 'scrypt',
    salt: b64(randomBytes(32)),
    N: scryptN,
    r: DEFAULT_SCRYPT_R,
    p: DEFAULT_SCRYPT_P,
    keyLength: SCRYPT_KEY_LENGTH,
  };
  const wrappingKey = derivePasswordKey(password, kdf);
  const sealed = encryptAesGcm(wrappingKey, privateDer, aadForKeyring(keyId));
  const keyring = {
    schema: KEYRING_SCHEMA,
    createdAt: new Date().toISOString(),
    publicWriteKey: {
      alg: 'X25519',
      keyId,
      spki: b64(publicDer),
    },
    encryptedReadKey: {
      kdf,
      aead: {
        name: 'AES-256-GCM',
        nonce: b64(sealed.nonce),
        tag: b64(sealed.tag),
      },
      ciphertext: b64(sealed.ciphertext),
    },
  };

  const outPath = options.out || DEFAULT_KEYRING;
  writeJson(outPath, keyring);
  console.log(`Wrote Keyring: ${outPath}`);
  console.log(`Write Key ID: ${keyId}`);
}

function commandVerifyKeyring(options) {
  const keyring = readJson(getKeyringPath(options));
  assertKeyring(keyring);
  console.log(`Valid Keyring: ${keyring.publicWriteKey.keyId}`);
}

function commandPublicKey(options) {
  const keyring = readJson(getKeyringPath(options));
  assertKeyring(keyring);
  const document = {
    schema: 'hxdl.publicKey.v1',
    createdAt: new Date().toISOString(),
    publicWriteKey: keyring.publicWriteKey,
  };
  if (options.out) {
    writeJson(options.out, document);
    console.log(`Wrote Public Key Document: ${options.out}`);
  }
  console.log(`Write Key ID: ${keyring.publicWriteKey.keyId}`);
}

function loadPublicKey(keyring) {
  return createPublicKey({
    key: fromB64(keyring.publicWriteKey.spki, 'publicWriteKey.spki'),
    format: 'der',
    type: 'spki',
  });
}

function commandEncrypt(options) {
  if (!options.in || !options.out) {
    throw new Error('encrypt requires --in and --out');
  }
  const keyring = readJson(getKeyringPath(options));
  assertKeyring(keyring);

  const recipientPublicKey = loadPublicKey(keyring);
  const ephemeral = generateKeyPairSync('x25519');
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: recipientPublicKey,
  });
  const hkdfSalt = randomBytes(32);
  const contentKey = Buffer.from(hkdfSync(
    'sha256',
    sharedSecret,
    hkdfSalt,
    Buffer.from(`${ENVELOPE_SCHEMA}:${keyring.publicWriteKey.keyId}`, 'utf8'),
    32,
  ));
  const plaintext = readFileSync(options.in);
  const sealed = encryptAesGcm(contentKey, plaintext, aadForEnvelope(keyring.publicWriteKey.keyId));
  const envelope = {
    schema: ENVELOPE_SCHEMA,
    createdAt: new Date().toISOString(),
    recipientKeyId: keyring.publicWriteKey.keyId,
    alg: {
      kem: 'X25519',
      kdf: 'HKDF-SHA256',
      aead: 'AES-256-GCM',
    },
    ephemeralPublicKey: b64(ephemeral.publicKey.export({ format: 'der', type: 'spki' })),
    hkdfSalt: b64(hkdfSalt),
    nonce: b64(sealed.nonce),
    tag: b64(sealed.tag),
    ciphertext: b64(sealed.ciphertext),
  };
  writeJson(options.out, envelope);
  console.log(`Wrote Data Envelope: ${options.out}`);
}

async function unwrapReadKey(keyring, options) {
  const password = await readPassword(options);
  const encrypted = keyring.encryptedReadKey;
  const wrappingKey = derivePasswordKey(password, encrypted.kdf);
  const privateDer = decryptAesGcm(wrappingKey, {
    nonce: fromB64(encrypted.aead.nonce, 'encryptedReadKey.aead.nonce'),
    tag: fromB64(encrypted.aead.tag, 'encryptedReadKey.aead.tag'),
    ciphertext: fromB64(encrypted.ciphertext, 'encryptedReadKey.ciphertext'),
  }, aadForKeyring(keyring.publicWriteKey.keyId));
  return createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' });
}

async function commandDecrypt(options) {
  if (!options.in || !options.out) {
    throw new Error('decrypt requires --in and --out');
  }
  const keyring = readJson(getKeyringPath(options));
  assertKeyring(keyring);
  const envelope = readJson(options.in);
  if (envelope.schema !== ENVELOPE_SCHEMA) {
    throw new Error(`Unsupported envelope schema: ${envelope.schema}`);
  }
  if (envelope.recipientKeyId !== keyring.publicWriteKey.keyId) {
    throw new Error('Envelope recipient does not match Keyring Write Key');
  }

  const readKey = await unwrapReadKey(keyring, options);
  const ephemeralPublicKey = createPublicKey({
    key: fromB64(envelope.ephemeralPublicKey, 'ephemeralPublicKey'),
    format: 'der',
    type: 'spki',
  });
  const sharedSecret = diffieHellman({
    privateKey: readKey,
    publicKey: ephemeralPublicKey,
  });
  const contentKey = Buffer.from(hkdfSync(
    'sha256',
    sharedSecret,
    fromB64(envelope.hkdfSalt, 'hkdfSalt'),
    Buffer.from(`${ENVELOPE_SCHEMA}:${keyring.publicWriteKey.keyId}`, 'utf8'),
    32,
  ));
  const plaintext = decryptAesGcm(contentKey, {
    nonce: fromB64(envelope.nonce, 'nonce'),
    tag: fromB64(envelope.tag, 'tag'),
    ciphertext: fromB64(envelope.ciphertext, 'ciphertext'),
  }, aadForEnvelope(keyring.publicWriteKey.keyId));

  mkdirSync(dirname(resolve(options.out)), { recursive: true });
  writeFileSync(options.out, plaintext, { mode: 0o600 });
  console.log(`Wrote plaintext: ${options.out}`);
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));
  switch (command) {
    case 'init':
      await commandInit(options);
      break;
    case 'verify-keyring':
      commandVerifyKeyring(options);
      break;
    case 'public-key':
      commandPublicKey(options);
      break;
    case 'encrypt':
      commandEncrypt(options);
      break;
    case 'decrypt':
      await commandDecrypt(options);
      break;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      usage();
      break;
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
});
