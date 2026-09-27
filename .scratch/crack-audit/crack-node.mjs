#!/usr/bin/env node
/**
 * HX-DataLock Keyring 离线爆破器 (CI 版)
 *
 * 威胁模型来自 ADR 0001 / 0019: Keyring 可放公有存储, 泄漏后攻击者无需任何
 * 交互即可离线猜测 Master Password; scrypt 是唯一减速带, 没有锁定。
 *
 * 本脚本只在 CI runner 上跑, 用于量化这个威胁。
 *
 * 用法:
 *   node crack-node.mjs dict=<file> targets=<file> shard=<i> shards=<n> rules=<0|1> limit=<n>
 */
import { readFileSync, readdirSync } from 'node:fs';
import { scryptSync, createDecipheriv } from 'node:crypto';

const A = Object.fromEntries(
  process.argv.slice(2).map((s) => { const i = s.indexOf('='); return [s.slice(0, i), s.slice(i + 1)]; })
);
const asInt = (k, d) => (A[k] === undefined ? d : parseInt(A[k], 10));

const DICT = A.dict;
const TARGETS_FILE = A.targets || 'targets/index.json';
const SHARD = asInt('shard', 0);
const SHARDS = asInt('shards', 1);
const RULES = asInt('rules', 0) === 1;
const LIMIT = asInt('limit', 0);
const TOPN = asInt('topn', 20000);

function nfc(s) { return s.normalize('NFC'); }

// All targets share one Keyring layout, so the KDF parameters are identical and
// only the salt differs. Deriving per candidate and reusing the key across
// targets is what keeps the sweep linear in candidates.
function deriveKey(pw, kdf) {
  return scryptSync(Buffer.from(nfc(pw), 'utf8'), Buffer.from(kdf.salt, 'base64'),
    kdf.keyLength, { N: kdf.N, r: kdf.r, p: kdf.p,
                     maxmem: Math.max(512 * 1024 * 1024, 256 * kdf.N * kdf.r) });
}

function decryptWith(key, enc, keyId) {
  try {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(enc.aead.nonce, 'base64'));
    d.setAAD(Buffer.from('hxdl.keyring.v1:' + keyId + ':scrypt:AES-256-GCM', 'utf8'));
    d.setAuthTag(Buffer.from(enc.aead.tag, 'base64'));
    Buffer.concat([d.update(Buffer.from(enc.ciphertext, 'base64')), d.final()]);
    return true;
  } catch { return false; }
}

function check(pw, enc, keyId) {
  return decryptWith(deriveKey(pw, enc.kdf), enc, keyId);
}

const SUFFIX = ['1','12','123','1234','12345','!','!!','@','#','.','_','2023','2024','2025','2026','1990','1966','888','520','1314'];
const LEET = (w) => w.replace(/a/gi,'@').replace(/o/gi,'0').replace(/e/gi,'3').replace(/i/gi,'1').replace(/s/gi,'$');

function buildCandidates(words) {
  const out = new Set(words);
  if (RULES) {
    for (const w of words.slice(0, TOPN)) {
      const cap = w.charAt(0).toUpperCase() + w.slice(1);
      const up = w.toUpperCase();
      out.add(cap); out.add(up);
      const l = LEET(w);
      out.add(l); out.add(l + '1'); out.add(l + '123'); out.add(LEET(cap));
      for (const s of SUFFIX) { out.add(w + s); out.add(cap + s); out.add(up + s); }
    }
  }
  return [...out];
}

const words = readFileSync(DICT, 'utf8').split('\n').map((s) => s.replace(/\r$/, '')).filter(Boolean);
const cands = LIMIT ? buildCandidates(words.slice(0, LIMIT)) : buildCandidates(words);

const mine = cands.filter((_, i) => i % SHARDS === SHARD);

const idx = JSON.parse(readFileSync(TARGETS_FILE, 'utf8'));
const targets = idx.map((e) => {
  const kr = JSON.parse(readFileSync(e.keyring, 'utf8'));
  return { case: e.case, tier: e.tier, truth: e.password,
           enc: kr.encryptedReadKey, keyId: kr.publicWriteKey.keyId, N: kr.encryptedReadKey.kdf.N };
});

console.log(JSON.stringify({ event: 'shard-start', shard: SHARD, shards: SHARDS, rules: RULES,
  total_candidates: cands.length, this_shard: mine.length, targets: targets.length,
  scrypt_N: targets[0]?.N ?? null, runtime: 'node ' + process.version }));

const perGuessMs = (() => {
  const t = process.hrtime.bigint();
  check('__warm__', targets[0].enc, targets[0].keyId);
  return Number(process.hrtime.bigint() - t) / 1e6;
})();
console.log(JSON.stringify({ event: 'throughput', ms_per_guess: +perGuessMs.toFixed(1),
  guesses_per_sec_1core: +(1000 / perGuessMs).toFixed(3),
  shard_eta_sec: Math.round(mine.length * perGuessMs / 1000) }));

// Every Keyring carries its own random salt, so one password yields a different
// scrypt output per target and the derivation cannot be shared between them.
// The sweep is therefore target-major, and the cost is bounded by shrinking the
// target set and the candidate list rather than by reordering the loops.
const found = {};
const t0 = Date.now();
for (let i = 0; i < mine.length; i += 1) {
  const pw = mine[i];
  for (const t of targets) {
    if (found[t.case]) continue;
    if (check(pw, t.enc, t.keyId)) {
      found[t.case] = { password: pw, shard_index: i, global_index: i * SHARDS + SHARD,
                        elapsed_sec: +((Date.now() - t0) / 1000).toFixed(1),
                        correct: pw === t.truth };
      console.log(JSON.stringify({ event: 'CRACKED', case: t.case, tier: t.tier, ...found[t.case] }));
    }
  }
  if (Object.keys(found).length === targets.length) break;
  if (i % 20000 === 0 && i > 0) {
    console.log(JSON.stringify({ event: 'progress', shard: SHARD, i, of: mine.length,
      elapsed_sec: +((Date.now() - t0) / 1000).toFixed(1) }));
  }
}

console.log(JSON.stringify({ event: 'shard-done', shard: SHARD, found,
  tried: mine.length, elapsed_sec: +((Date.now() - t0) / 1000).toFixed(1) }));

// 结果汇总写文件供 artifact 收集
import { writeFileSync } from 'node:fs';
writeFileSync(`shard-${SHARD}.json`, JSON.stringify({ shard: SHARD, shards: SHARDS, rules: RULES,
  scrypt_N: targets[0]?.N ?? null, ms_per_guess: +perGuessMs.toFixed(1),
  candidates_total: cands.length, tried: mine.length, found }, null, 2));
