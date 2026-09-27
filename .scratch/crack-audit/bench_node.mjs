import { readFileSync } from 'node:fs';
import { scryptSync, createDecipheriv } from 'node:crypto';
const kr = JSON.parse(readFileSync('/home/hx/Loli/code/HXLoLis/utils/HX-DataLock/.scratch/crack-audit/targets/weak_02_N262144.json','utf8'));
const enc = kr.encryptedReadKey, keyId = kr.publicWriteKey.keyId;
const aad = Buffer.from('hxdl.keyring.v1:' + keyId + ':scrypt:AES-256-GCM','utf8');
function tryPw(pw, kdf) {
  try {
    const key = scryptSync(Buffer.from(pw.normalize('NFC'),'utf8'), Buffer.from(kdf.salt,'base64'), kdf.keyLength,
      { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: Math.max(512*1024*1024, 256*kdf.N*kdf.r) });
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(enc.aead.nonce,'base64'));
    d.setAAD(aad); d.setAuthTag(Buffer.from(enc.aead.tag,'base64'));
    Buffer.concat([d.update(Buffer.from(enc.ciphertext,'base64')), d.final()]);
    return true;
  } catch { return false; }
}
for (const N of [262144]) {
  const kdf = { ...enc.kdf, N };
  const t = process.hrtime.bigint();
  tryPw('__bench__', kdf);
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  console.log(JSON.stringify({ runtime:'node', kdf_N: N, ms_per_guess: Math.round(ms),
    guesses_per_sec_1core: +(1000/ms).toFixed(3), guesses_per_day_1core: Math.floor(86400*1000/ms) }));
}
