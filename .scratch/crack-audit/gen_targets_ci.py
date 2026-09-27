#!/usr/bin/env python3
"""CI 用: 生成已知口令的审计 Keyring 目标。

成本模型要求目标数受控 (单次扫描 = 候选 x 目标), 所以这里分成两个集合:
  primary   —— 有代表性的弱/中/强档, 用于拿命中排名
  costcheck —— 只取 3 个, 用于在默认 scrypt 参数下测单次派生耗时
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, "sdk/py/src")
from hx_datalock import init_keyring

PRIMARY = [
    ("weak_01", "123456", "弱"),
    ("weak_02", "password", "弱"),
    ("weak_04", "iloveyou", "弱"),
    ("weak_05", "admin123", "弱"),
    ("mid_01", "Password1", "中"),
    ("mid_05", "Woaini1314", "中(华人常见)"),
    ("strong_01", "correct horse battery staple", "强(短语)"),
    ("strong_02", "MyDogAteHomework2019!", "强"),
]
# 中等档单独成集: 弱档在纯字典下就失守了, 变形规则的价值需要用中等档来证明。
MID = [
    ("mid_01", "Password1", "中"),
    ("mid_02", "P@ssw0rd", "中"),
    ("mid_06", "Aa123456", "中(合规型)"),
]
COSTCHECK = PRIMARY[:3]

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=16384)
ap.add_argument("--set", dest="which",
                choices=["primary", "mid", "costcheck"], default="primary")
a = ap.parse_args()

cases = {"primary": PRIMARY, "mid": MID, "costcheck": COSTCHECK}[a.which]
OUT = Path(".scratch/crack-audit/targets_ci")
OUT.mkdir(parents=True, exist_ok=True)
idx = []
for name, pw, tier in cases:
    p = OUT / f"{name}.json"
    init_keyring(p, pw, scrypt_n=a.n)
    idx.append({"case": name, "tier": tier, "password": pw, "keyring": str(p)})
(OUT / "index.json").write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")

per = None
print(json.dumps({"set": a.which, "targets": len(idx), "scrypt_N": a.n}))
