#!/usr/bin/env python3
"""生成审计用 Keyring: 每个密码生成一份, 记录 scrypt 参数。"""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/sdk/py/src")
from hx_datalock import init_keyring

OUT = Path("/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/.scratch/crack-audit/targets")
OUT.mkdir(parents=True, exist_ok=True)

# 真实用户密码, 分三档。不用随机数当"真理", 只当上界。
CASES = [
    ("weak_01",   "123456",              "弱"),
    ("weak_02",   "password",            "弱"),
    ("weak_03",   "qwerty",              "弱"),
    ("weak_04",   "iloveyou",            "弱"),
    ("weak_05",   "admin123",            "弱"),
    ("mid_01",    "Password1",           "中"),
    ("mid_02",    "P@ssw0rd",            "中"),
    ("mid_03",    "Summer2024",          "中"),
    ("mid_04",    "iloveyou123",         "中"),
    ("mid_05",    "Woaini1314",          "中(华人常见)"),
    ("strong_01", "correct horse battery staple", "强(口令短语)"),
    ("strong_02", "MyDogAteHomework2019!",        "强"),
    ("bound_01",  "Tz9#kLm4Qw2$Xp7Vn5Rb",        "上界(随机, 仅作边界)"),
]

index = []
for name, pw, tier in CASES:
    for N in (int(sys.argv[1]) if len(sys.argv) > 1 else 2**18,):
        p = OUT / f"{name}_N{N}.json"
        init_keyring(p, pw, scrypt_n=N)
        index.append({"case": name, "tier": tier, "password": pw, "N": N, "keyring": str(p)})
        print(f"  {name:10s} N={N:<8d} {tier:16s} {pw}")

(OUT / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n{len(index)} 个目标已写入 {OUT}")
