#!/usr/bin/env python3
"""CI 用: 生成已知口令的审计 Keyring 目标。"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, "sdk/py/src")
from hx_datalock import init_keyring

CASES = [
    ("weak_01","123456","弱"),("weak_02","password","弱"),("weak_03","qwerty","弱"),
    ("weak_04","iloveyou","弱"),("weak_05","admin123","弱"),("weak_06","abc123","弱"),
    ("weak_07","123456789","弱"),("weak_08","sunshine","弱"),
    ("mid_01","Password1","中"),("mid_02","P@ssw0rd","中"),("mid_03","Summer2024","中"),
    ("mid_04","iloveyou123","中"),("mid_05","Woaini1314","中(华人常见)"),
    ("mid_06","Aa123456","中(合规型)"),("mid_07","Password123!","中"),
    ("mid_08","qwerty2024","中"),
    ("strong_01","correct horse battery staple","强(短语)"),
    ("strong_02","MyDogAteHomework2019!","强"),
    ("strong_03","Tz9kLm4Qw2Xp7Vn5Rb","上界(随机)"),
]

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=16384)
a = ap.parse_args()
OUT = Path(".scratch/crack-audit/targets_ci"); OUT.mkdir(parents=True, exist_ok=True)
idx = []
for name, pw, tier in CASES:
    p = OUT / f"{name}.json"
    init_keyring(p, pw, scrypt_n=a.n)
    idx.append({"case": name, "tier": tier, "password": pw, "keyring": str(p)})
(OUT / "index.json").write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"{len(idx)} targets @ N=2^{a.n.bit_length()-1}")
