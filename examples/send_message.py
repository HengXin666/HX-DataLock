import argparse

from hx_datalock import send_file


def main() -> None:
    parser = argparse.ArgumentParser(description="使用 GitHub Keyring 的 Write Key 加密消息")
    parser.add_argument("--keyring", default="keyring.hxdl.json", help="GitHub 仓库中的 Keyring")
    parser.add_argument("--in", dest="input_path", required=True, help="待发送明文文件")
    parser.add_argument("--out", dest="output_path", required=True, help="输出 Data Envelope")
    args = parser.parse_args()

    send_file(args.keyring, args.input_path, args.output_path)
    print(f"已写入可公开存储的密文: {args.output_path}")


if __name__ == "__main__":
    main()
