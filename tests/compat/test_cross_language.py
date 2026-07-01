import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hx_datalock import (
    DataEnvelope,
    DataLockErrorCode,
    decrypt_message,
    encrypt_message,
    export_public_key_document,
    init_keyring,
    load_keyring,
    open_file,
    send_file,
)

PASSWORD = "correct horse battery staple for hx datalock"


def _python_cli() -> list[str]:
    return [sys.executable, "-m", "hx_datalock.cli"]


def _node_cli() -> list[str]:
    return ["node", "sdk/node/hx-datalock.mjs"]


def _kotlin_example(task: str, keyring_path: Path, input_path: Path, output_path: Path) -> list[str]:
    return [
        "gradle",
        task,
        "--quiet",
        f"-PexampleArgs={keyring_path}|{input_path}|{output_path}|{PASSWORD}",
    ]


def test_each_sdk_can_open_envelopes_locked_by_every_sdk(tmp_path: Path) -> None:
    if shutil.which("gradle") is None:
        pytest.skip("gradle is required to prove Kotlin interoperability")

    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    env = os.environ | {"HXDL_TEST_PASSWORD": PASSWORD}

    subprocess.run(
        [
            *_python_cli(),
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )
    subprocess.run(
        [*_python_cli(), "export-public", "--keyring", str(keyring_path), "--out", str(public_path)],
        check=True,
    )

    lock_commands = {
        "python": lambda plain_path, envelope_path: subprocess.run(
            [
                *_python_cli(),
                "lock",
                "--public",
                str(public_path),
                "--in",
                str(plain_path),
                "--out",
                str(envelope_path),
            ],
            check=True,
        ),
        "node": lambda plain_path, envelope_path: subprocess.run(
            [
                *_node_cli(),
                "lock",
                "--public",
                str(public_path),
                "--in",
                str(plain_path),
                "--out",
                str(envelope_path),
            ],
            check=True,
        ),
        "kotlin": lambda plain_path, envelope_path: subprocess.run(
            _kotlin_example("runLockExample", keyring_path, plain_path, envelope_path),
            cwd=Path("sdk/kotlin"),
            check=True,
        ),
    }
    open_commands = {
        "python": lambda envelope_path, opened_path: subprocess.run(
            [
                *_python_cli(),
                "open",
                "--keyring",
                str(keyring_path),
                "--in",
                str(envelope_path),
                "--out",
                str(opened_path),
                "--password-env",
                "HXDL_TEST_PASSWORD",
            ],
            check=True,
            env=env,
        ),
        "node": lambda envelope_path, opened_path: subprocess.run(
            [
                *_node_cli(),
                "open",
                "--keyring",
                str(keyring_path),
                "--in",
                str(envelope_path),
                "--out",
                str(opened_path),
                "--password-env",
                "HXDL_TEST_PASSWORD",
            ],
            check=True,
            env=env,
        ),
        "kotlin": lambda envelope_path, opened_path: subprocess.run(
            _kotlin_example("runOpenExample", keyring_path, envelope_path, opened_path),
            cwd=Path("sdk/kotlin"),
            check=True,
        ),
    }

    for locker_name, lock in lock_commands.items():
        plain_path = tmp_path / f"{locker_name}.txt"
        envelope_path = tmp_path / f"{locker_name}.hxdl.json"
        payload = f"{locker_name} SDK 加密, 所有 SDK 解密".encode("utf-8")
        plain_path.write_bytes(payload)

        lock(plain_path, envelope_path)

        for opener_name, open_ in open_commands.items():
            opened_path = tmp_path / f"{locker_name}-to-{opener_name}.txt"

            open_(envelope_path, opened_path)

            assert opened_path.read_bytes() == payload


def test_python_encrypts_and_node_decrypts(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    decrypted_path = tmp_path / "decrypted.txt"

    env = os.environ | {"HXDL_TEST_PASSWORD": password}
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )

    keyring = load_keyring(keyring_path)
    plain_path.write_bytes(b"python sender, node receiver")
    encrypt_message(keyring, plain_path.read_bytes()).write(envelope_path)

    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(decrypted_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        check=True,
        env=env,
    )
    assert decrypted_path.read_bytes() == plain_path.read_bytes()


def test_node_locks_with_public_document_and_python_opens(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"

    env = os.environ | {"HXDL_TEST_PASSWORD": password}
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "export-public",
            "--keyring",
            str(keyring_path),
            "--out",
            str(public_path),
        ],
        check=True,
    )
    plain_path.write_bytes(b"node sender, python receiver")
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "lock",
            "--public",
            str(public_path),
            "--in",
            str(plain_path),
            "--out",
            str(envelope_path),
        ],
        check=True,
    )

    keyring = load_keyring(keyring_path)
    plaintext = decrypt_message(keyring, password, DataEnvelope.read(envelope_path))
    assert plaintext == plain_path.read_bytes()


def test_python_public_document_works_with_node_lock_and_open(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    env = os.environ | {"HXDL_TEST_PASSWORD": password}

    keyring = init_keyring(keyring_path, password, scrypt_n=16384)
    export_public_key_document(keyring).write(public_path)
    plain_path.write_bytes("Python 公钥文档, Node v1 CLI".encode("utf-8"))

    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "lock",
            "--public",
            str(public_path),
            "--in",
            str(plain_path),
            "--out",
            str(envelope_path),
        ],
        check=True,
    )
    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        check=True,
        env=env,
    )

    assert opened_path.read_bytes() == plain_path.read_bytes()


def test_node_cli_reports_stable_v1_error_codes(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    opened_path = tmp_path / "opened.txt"
    env = os.environ | {"HXDL_TEST_PASSWORD": password}

    keyring = init_keyring(keyring_path, password, scrypt_n=16384)
    export_public_key_document(keyring).write(public_path)
    plain_path.write_bytes(b"stable node cli failures")

    rejected_keyring_lock = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "lock",
            "--public",
            str(keyring_path),
            "--in",
            str(plain_path),
            "--out",
            str(tmp_path / "rejected.hxdl.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected_keyring_lock.returncode != 0
    assert DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT.value in rejected_keyring_lock.stderr

    subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "lock",
            "--public",
            str(public_path),
            "--in",
            str(plain_path),
            "--out",
            str(envelope_path),
        ],
        check=True,
    )

    wrong_password = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        env=os.environ | {"HXDL_TEST_PASSWORD": "wrong password"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert wrong_password.returncode != 0
    assert DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING.value in wrong_password.stderr

    second_keyring_path = tmp_path / "second-keyring.hxdl.json"
    init_keyring(second_keyring_path, "another correct horse battery staple", scrypt_n=16384)
    mismatch_result = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(second_keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        env=os.environ | {"HXDL_TEST_PASSWORD": "another correct horse battery staple"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert mismatch_result.returncode != 0
    assert DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH.value in mismatch_result.stderr

    tampered = DataEnvelope.read(envelope_path).raw
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"
    envelope_path.write_text(__import__("json").dumps(tampered), encoding="utf-8")
    tampered_result = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert tampered_result.returncode != 0
    assert DataLockErrorCode.TAMPERED_ENVELOPE.value in tampered_result.stderr

    tampered["schema"] = "hxdl.envelope.v2"
    envelope_path.write_text(__import__("json").dumps(tampered), encoding="utf-8")
    unsupported_schema = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert unsupported_schema.returncode != 0
    assert DataLockErrorCode.UNSUPPORTED_SCHEMA.value in unsupported_schema.stderr

    tampered["schema"] = "hxdl.envelope.v1"
    tampered["alg"] = {**tampered["alg"], "aead": "ChaCha20-Poly1305"}
    envelope_path.write_text(__import__("json").dumps(tampered), encoding="utf-8")
    unsupported_algorithm = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "open",
            "--keyring",
            str(keyring_path),
            "--in",
            str(envelope_path),
            "--out",
            str(opened_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert unsupported_algorithm.returncode != 0
    assert DataLockErrorCode.UNSUPPORTED_ALGORITHM.value in unsupported_algorithm.stderr


def test_node_cli_rejects_oversized_v1_files(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    oversized_path = tmp_path / "oversized.bin"
    env = os.environ | {"HXDL_TEST_PASSWORD": "correct horse battery staple for hx datalock"}

    subprocess.run(
        [
            sys.executable,
            "-m",
            "hx_datalock.cli",
            "init",
            "--keyring",
            str(keyring_path),
            "--password-env",
            "HXDL_TEST_PASSWORD",
            "--scrypt-n",
            "16384",
        ],
        check=True,
        env=env,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "hx_datalock.cli",
            "export-public",
            "--keyring",
            str(keyring_path),
            "--out",
            str(public_path),
        ],
        check=True,
    )
    with oversized_path.open("wb") as file:
        file.truncate(25 * 1024 * 1024 + 1)

    result = subprocess.run(
        [
            "node",
            "sdk/node/hx-datalock.mjs",
            "lock",
            "--public",
            str(public_path),
            "--in",
            str(oversized_path),
            "--out",
            str(tmp_path / "oversized.hxdl.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert DataLockErrorCode.OVERSIZED_FILE.value in result.stderr


def test_node_cli_lock_rejects_public_key_document_key_id_mismatch(tmp_path: Path) -> None:
    trusted_keyring_path = tmp_path / "trusted-keyring.hxdl.json"
    replaced_keyring_path = tmp_path / "replaced-keyring.hxdl.json"
    trusted_public_path = tmp_path / "trusted-public.hxdl.json"
    replaced_public_path = tmp_path / "replaced-public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    output_path = tmp_path / "sealed.hxdl.json"
    trusted_keyring = init_keyring(trusted_keyring_path, PASSWORD, scrypt_n=16384)
    replaced_keyring = init_keyring(replaced_keyring_path, f"{PASSWORD} replacement", scrypt_n=16384)
    export_public_key_document(trusted_keyring).write(trusted_public_path)
    export_public_key_document(replaced_keyring).write(replaced_public_path)
    trusted_key_id = export_public_key_document(trusted_keyring).key_id
    plain_path.write_bytes(b"pin me")

    result = subprocess.run(
        [
            *_node_cli(),
            "lock",
            "--public",
            str(replaced_public_path),
            "--expect-key-id",
            trusted_key_id,
            "--in",
            str(plain_path),
            "--out",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert not output_path.exists()
    assert DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT.value in result.stderr


def test_node_cli_lock_rejects_oversized_public_key_document(tmp_path: Path) -> None:
    public_path = tmp_path / "public.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    output_path = tmp_path / "sealed.hxdl.json"
    public_path.write_text(" " * (64 * 1024 + 1), encoding="utf-8")
    plain_path.write_bytes(b"payload")

    result = subprocess.run(
        [
            *_node_cli(),
            "lock",
            "--public",
            str(public_path),
            "--in",
            str(plain_path),
            "--out",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert DataLockErrorCode.OVERSIZED_FILE.value in result.stderr


def test_node_cli_verify_rejects_non_stable_public_key_document(tmp_path: Path) -> None:
    keyring_path = tmp_path / "keyring.hxdl.json"
    public_path = tmp_path / "public.hxdl.json"
    keyring = init_keyring(keyring_path, PASSWORD, scrypt_n=16384)
    public_document = export_public_key_document(keyring)
    public_path.write_text(__import__("json").dumps(public_document.raw, separators=(",", ":")), encoding="utf-8")

    result = subprocess.run(
        [
            *_node_cli(),
            "verify-public",
            "--public",
            str(public_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT.value in result.stderr


def test_node_sdk_exposes_v1_datalock_surface(tmp_path: Path) -> None:
    script_path = tmp_path / "node-sdk-surface.mjs"
    script_path.write_text(
        f"""
import {{
  DataLockErrorCode,
  checkPasswordStrength,
  createKeyring,
  exportPublicKeyDocument,
  makeSenderDataLock,
  makeUserDataLock,
  verifyPublicKeyDocumentKeyId,
}} from {str((Path.cwd() / "sdk/node/hx-datalock.mjs").as_uri())!r};

const password = 'correct horse battery staple for hx datalock';
const keyring = createKeyring(password, {{ scryptN: 16384 }});
const publicDocument = exportPublicKeyDocument(keyring);
const replacedPublicDocument = exportPublicKeyDocument(createKeyring(`${{password}} replacement`, {{ scryptN: 16384 }}));
const report = checkPasswordStrength('password');
const sender = makeSenderDataLock(publicDocument);
const envelope = sender.lockText('typescript sdk payload');
const user = makeUserDataLock(keyring, {{ masterPassword: password }});
const opened = user.openText(envelope);

if (report.allowed !== true || report.level !== 'weak') throw new Error('bad password report');
if (opened !== 'typescript sdk payload') throw new Error('round trip failed');
if (typeof sender.openBytes !== 'undefined') throw new Error('sender can open');
for (const name of ['openBytes', 'openText', 'openFile', 'lockBytes', 'lockText', 'lockFile', 'close']) {{
  if (typeof user[name] !== 'function') throw new Error(`missing user method ${{name}}`);
}}
try {{
  makeSenderDataLock(keyring);
  throw new Error('accepted keyring as sender input');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT) throw error;
}}
try {{
  verifyPublicKeyDocumentKeyId(replacedPublicDocument, publicDocument.keyId);
  throw new Error('accepted replaced public document');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT) throw error;
}}
try {{
  makeSenderDataLock(replacedPublicDocument, {{ expectedKeyId: publicDocument.keyId }});
  throw new Error('accepted replaced public document for sender');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT) throw error;
}}
user.close();
""",
        encoding="utf-8",
    )

    subprocess.run(["node", str(script_path)], check=True)


def test_node_sdk_open_text_reports_invalid_utf8_with_stable_error_code(tmp_path: Path) -> None:
    script_path = tmp_path / "node-invalid-utf8.mjs"
    script_path.write_text(
        f"""
import {{
  DataLockErrorCode,
  createKeyring,
  makeUserDataLock,
}} from {str((Path.cwd() / "sdk/node/hx-datalock.mjs").as_uri())!r};

const password = 'correct horse battery staple for hx datalock';
const keyring = createKeyring(password, {{ scryptN: 16384 }});
const user = makeUserDataLock(keyring, {{ masterPassword: password }});
const envelope = user.lockBytes(Buffer.from([0xff]));

try {{
  user.openText(envelope);
  throw new Error('invalid UTF-8 payload was accepted');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.INVALID_UTF8) {{
    throw error;
  }}
}}
""",
        encoding="utf-8",
    )

    subprocess.run(["node", str(script_path)], check=True)


def test_node_sdk_rejects_hardened_untrusted_inputs(tmp_path: Path) -> None:
    script_path = tmp_path / "node-hardening.mjs"
    script_path.write_text(
        f"""
import {{
  DataLockErrorCode,
  createKeyring,
  makeUserDataLock,
}} from {str((Path.cwd() / "sdk/node/hx-datalock.mjs").as_uri())!r};
import {{ Keyring, DataEnvelope }} from {str((Path.cwd() / "sdk/node/dist/documents.js").as_uri())!r};
import {{ MAX_V1_FILE_BYTES }} from {str((Path.cwd() / "sdk/node/dist/constants.js").as_uri())!r};

const password = 'correct horse battery staple for hx datalock';
const keyring = createKeyring(password, {{ scryptN: 16384 }});
const user = makeUserDataLock(keyring, {{ masterPassword: password }});
const envelope = user.lockBytes(Buffer.from('hello'));

const oversizedKdf = structuredClone(keyring.raw);
oversizedKdf.encryptedReadKey.kdf.N = 2 ** 30;
try {{
  new Keyring(oversizedKdf).verify();
  throw new Error('accepted oversized scrypt N');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.INVALID_KEYRING) throw error;
}}

const shortNonce = structuredClone(envelope.raw);
shortNonce.nonce = 'AAAA';
try {{
  new DataEnvelope(shortNonce).verify();
  throw new Error('accepted short nonce');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.TAMPERED_ENVELOPE) throw error;
}}

const oversizedCiphertext = structuredClone(envelope.raw);
const maxB64Chars = Math.ceil(MAX_V1_FILE_BYTES / 3) * 4;
oversizedCiphertext.ciphertext = 'A'.repeat(maxB64Chars + 4);
try {{
  new DataEnvelope(oversizedCiphertext).verify();
  throw new Error('accepted oversized ciphertext');
}} catch (error) {{
  if (error.code !== DataLockErrorCode.OVERSIZED_FILE) throw error;
}}
""",
        encoding="utf-8",
    )

    subprocess.run(["node", str(script_path)], check=True)


def test_simple_python_api_round_trips_file(tmp_path: Path) -> None:
    password = "correct horse battery staple for hx datalock"
    keyring_path = tmp_path / "keyring.hxdl.json"
    plain_path = tmp_path / "plain.txt"
    envelope_path = tmp_path / "sealed.hxdl.json"
    decrypted_path = tmp_path / "decrypted.txt"

    init_keyring(keyring_path, password, scrypt_n=16384)
    plain_path.write_bytes(b"simple api, hidden internals")

    send_file(keyring_path, plain_path, envelope_path)
    open_file(keyring_path, envelope_path, decrypted_path, password)

    assert decrypted_path.read_bytes() == plain_path.read_bytes()
