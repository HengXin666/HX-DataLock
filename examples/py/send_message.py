import argparse

from hx_datalock import PublicKeyDocument, makeSenderDataLock


def main() -> None:
    parser = argparse.ArgumentParser(description="使用 Public Key Document 加密消息")
    parser.add_argument("--public", required=True, help="Public Key Document")
    parser.add_argument("--in", dest="input_path", required=True, help="待发送明文文件")
    parser.add_argument("--out", dest="output_path", required=True, help="输出 Data Envelope")
    args = parser.parse_args()

    makeSenderDataLock(PublicKeyDocument.read(args.public)).lockFile(args.input_path, args.output_path)
    print(f"已写入可公开存储的密文: {args.output_path}")


if __name__ == "__main__":
    main()
