import argparse
import getpass
import os

from hx_datalock import open_file


def main() -> None:
    parser = argparse.ArgumentParser(description="使用主密码和 GitHub Keyring 解密消息")
    parser.add_argument("--keyring", default="keyring.hxdl.json", help="GitHub 仓库中的 Keyring")
    parser.add_argument("--in", dest="input_path", required=True, help="Data Envelope 密文")
    parser.add_argument("--out", dest="output_path", required=True, help="输出明文文件")
    parser.add_argument(
        "--password-env",
        help="从环境变量读取主密码；不传时使用隐藏交互输入",
    )
    args = parser.parse_args()

    if args.password_env:
        master_password = os.environ.get(args.password_env)
        if not master_password:
            raise SystemExit(f"环境变量 {args.password_env} 为空或不存在")
    else:
        master_password = getpass.getpass("主密码: ")

    open_file(args.keyring, args.input_path, args.output_path, master_password)
    print(f"已写入解密明文: {args.output_path}")


if __name__ == "__main__":
    main()
