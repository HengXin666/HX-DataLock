from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from .sdk import DEFAULT_SCRYPT_N, export_public_key_document, init_keyring, load_keyring, open_file, send_file


def _read_password(password_env: str | None) -> str:
    if password_env:
        value = os.environ.get(password_env)
        if not value:
            raise SystemExit(f"Environment variable {password_env} is empty or missing")
        return value
    return getpass.getpass("Master password: ")


def _cmd_init(args: argparse.Namespace) -> None:
    keyring = init_keyring(
        args.keyring,
        _read_password(args.password_env),
        scrypt_n=args.scrypt_n,
    )
    print(f"Keyring written: {args.keyring}")
    print(f"Write Key ID: {keyring.key_id}")


def _cmd_send(args: argparse.Namespace) -> None:
    send_file(args.keyring, args.input, args.output)
    print(f"Encrypted message written: {args.output}")


def _cmd_open(args: argparse.Namespace) -> None:
    open_file(args.keyring, args.input, args.output, _read_password(args.password_env))
    print(f"Plaintext written: {args.output}")


def _cmd_verify(args: argparse.Namespace) -> None:
    keyring = load_keyring(args.keyring)
    print(f"Valid Keyring: {keyring.key_id}")


def _cmd_public_key(args: argparse.Namespace) -> None:
    keyring = load_keyring(args.keyring)
    document = export_public_key_document(keyring)
    if args.output:
        document.write(args.output)
        print(f"Public Key Document written: {args.output}")
    print(f"Write Key ID: {document.key_id}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hxdl",
        description="HX-DataLock write-only encryption CLI",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="create a Keyring for GitHub storage")
    init.add_argument("--keyring", default="keyring.hxdl.json")
    init.add_argument("--password-env")
    init.add_argument("--scrypt-n", type=int, default=DEFAULT_SCRYPT_N)
    init.set_defaults(func=_cmd_init)

    send = subcommands.add_parser("send", help="encrypt a file for public storage")
    send.add_argument("--keyring", default="keyring.hxdl.json")
    send.add_argument("--in", dest="input", required=True)
    send.add_argument("--out", dest="output", required=True)
    send.set_defaults(func=_cmd_send)

    open_ = subcommands.add_parser("open", help="decrypt a Data Envelope locally")
    open_.add_argument("--keyring", default="keyring.hxdl.json")
    open_.add_argument("--in", dest="input", required=True)
    open_.add_argument("--out", dest="output", required=True)
    open_.add_argument("--password-env")
    open_.set_defaults(func=_cmd_open)

    verify = subcommands.add_parser("verify", help="verify a Keyring")
    verify.add_argument("--keyring", default="keyring.hxdl.json")
    verify.set_defaults(func=_cmd_verify)

    public_key = subcommands.add_parser("public-key", help="export the public Write Key")
    public_key.add_argument("--keyring", default="keyring.hxdl.json")
    public_key.add_argument("--out", dest="output")
    public_key.set_defaults(func=_cmd_public_key)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if hasattr(args, "input"):
        args.input = Path(args.input)
    if hasattr(args, "output"):
        args.output = Path(args.output)
    args.func(args)


if __name__ == "__main__":
    main()
