// 用密碼把加密的 index.html 還原成原始網頁（要修改內容時使用）
// 用法：SITE_PASSWORD=密碼 node tools/decrypt.mjs index.html 原始.html
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const [src, out] = process.argv.slice(2);
const password = process.env.SITE_PASSWORD;
if (!src || !out || !password) {
  console.error('用法：SITE_PASSWORD=密碼 node tools/decrypt.mjs index.html 原始.html');
  process.exit(1);
}
const m = readFileSync(src, 'utf8').match(/<script id="payload" type="application\/json">(.*?)<\/script>/s);
if (!m) { console.error('找不到加密內容'); process.exit(1); }
const P = JSON.parse(m[1]);
const dec = s => Buffer.from(s, 'base64');
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: dec(P.salt), iterations: P.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
try {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: dec(P.iv) }, key, dec(P.ct));
  writeFileSync(out, Buffer.from(pt));
  console.log('已還原 → ' + out);
} catch {
  console.error('密碼不正確'); process.exit(1);
}
