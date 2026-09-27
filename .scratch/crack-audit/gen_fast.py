#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, "/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/sdk/py/src")
from hx_datalock import init_keyring
OUT = Path("/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/.scratch/crack-audit/targets_fast")
OUT.mkdir(parents=True, exist_ok=True)
CASES = [
    ("weak_01","123456","弱"),("weak_02","password","弱"),("weak_03","qwerty","弱"),
    ("weak_04","iloveyou","弱"),("weak_05","admin123","弱"),("weak_06","abc123","弱"),
    ("mid_01","Password1","中"),("mid_02","P@ssw0rd","中"),("mid_03","Summer2024","中"),
    ("mid_04","iloveyou123","中"),("mid_05","Woaini1314","中(华人常见)"),("mid_06","Aa123456","中(合规型)"),
    ("strong_01","correct horse battery staple","强(短语)"),("strong_02","MyDogAteHomework2019!","强"),
    ("bound_01","Tz9#kLm4Qw2$Xp7Vn5Rb","上界(随机)"),
]
idx=[]
for name,pw,tier in CASES:
    p = OUT/f"{name}.json"; init_keyring(p, pw, scrypt_n=2**14)
    idx.append({"case":name,"tier":tier,"password":pw,"keyring":str(p)})
(OUT/"index.json").write_text(json.dumps(idx,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"{len(idx)} 个快速目标 (N=2^14) 已生成")
