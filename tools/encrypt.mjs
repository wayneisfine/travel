// 用密碼把原始網頁加密成可公開的 index.html
// 用法：SITE_PASSWORD=密碼 node tools/encrypt.mjs 原始.html index.html
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const [src, out] = process.argv.slice(2);
const password = process.env.SITE_PASSWORD;
if (!src || !out || !password) {
  console.error('用法：SITE_PASSWORD=密碼 node tools/encrypt.mjs 原始.html index.html');
  process.exit(1);
}
const ITER = 600000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, readFileSync(src)));
const b64 = u => Buffer.from(u).toString('base64');
const payload = JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) });

const page = `<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>旅遊行程</title>
<meta name="theme-color" content="#FFFCF6">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Huninn&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Huninn","PingFang TC","Microsoft JhengHei",sans-serif;background:#FFFCF6;color:#3E3A39;
  min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:16px;font-size:16px}
.box{width:100%;max-width:360px;border:3px solid #3E3A39;border-radius:22px;background:#fff;padding:24px 22px;text-align:center}
svg{width:96px;height:96px;animation:bob 2.4s ease-in-out infinite alternate}
h1{font-size:24px;font-weight:400;margin:8px 0 4px;letter-spacing:1px}
p{font-size:14px}
input[type=password]{width:100%;font:inherit;color:inherit;border:3px solid #3E3A39;border-radius:16px;padding:10px 14px;margin-top:16px;background:#FFFCF6;text-align:center}
input[type=password]:focus-visible,button:focus-visible{outline:3px solid #C8604F;outline-offset:2px}
label{display:flex;align-items:center;justify-content:center;gap:8px;font-size:14px;margin-top:12px;cursor:pointer}
label input{width:18px;height:18px;accent-color:#3E3A39}
button{width:100%;font:inherit;color:inherit;cursor:pointer;border:3px solid #3E3A39;border-radius:999px;background:#F6D27A;padding:10px;margin-top:14px;font-size:17px}
button:disabled{opacity:.6;cursor:wait}
#msg{min-height:22px;margin-top:10px;color:#C8604F}
.shake{animation:shake .4s}
@keyframes bob{from{transform:translateY(-3px)}to{transform:translateY(4px)}}
@keyframes shake{25%{transform:translateX(-8px)}50%{transform:translateX(8px)}75%{transform:translateX(-5px)}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}}
</style>
</head>
<body>
<form class="box" id="f">
  <svg viewBox="0 0 80 80" aria-hidden="true">
    <path d="M26 36V26a14 14 0 0 1 28 0v10" fill="none" stroke="#3E3A39" stroke-width="3" stroke-linecap="round"/>
    <rect x="16" y="36" width="48" height="36" rx="10" fill="#F2A497" stroke="#3E3A39" stroke-width="3"/>
    <circle cx="40" cy="51" r="5" fill="#fff" stroke="#3E3A39" stroke-width="3"/>
    <path d="M40 56v7" stroke="#3E3A39" stroke-width="3" stroke-linecap="round"/>
  </svg>
  <h1>旅遊行程</h1>
  <p>請輸入密碼才能查看</p>
  <input type="password" id="pw" autocomplete="current-password" aria-label="密碼" placeholder="密碼" required autofocus>
  <label><input type="checkbox" id="keep" checked>在這台裝置記住</label>
  <button id="go">進入</button>
  <p id="msg" role="alert"></p>
</form>
<script id="payload" type="application/json">${payload}</script>
<script>
(function(){
  var P = JSON.parse(document.getElementById('payload').textContent);
  var KEY = 'trip-key-' + P.salt;
  var f = document.getElementById('f'), msg = document.getElementById('msg'), btn = document.getElementById('go');
  function dec(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); }
  function enc(u){ return btoa(String.fromCharCode.apply(null, new Uint8Array(u))); }
  function open(raw){
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt'])
      .then(function(k){ return crypto.subtle.decrypt({name:'AES-GCM', iv:dec(P.iv)}, k, dec(P.ct)); })
      .then(function(buf){ return new TextDecoder().decode(buf); });
  }
  function show(html){ document.open(); document.write(html); document.close(); }
  function derive(pw){
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits'])
      .then(function(b){ return crypto.subtle.deriveBits({name:'PBKDF2', salt:dec(P.salt), iterations:P.iter, hash:'SHA-256'}, b, 256); });
  }
  if(!window.crypto || !crypto.subtle){ msg.textContent = '此瀏覽器不支援，請改用 https 網址開啟'; btn.disabled = true; return; }
  var saved = null;
  try{ saved = localStorage.getItem(KEY); }catch(e){}
  if(saved){ open(dec(saved)).then(show).catch(function(){ try{ localStorage.removeItem(KEY); }catch(e){} }); }
  f.addEventListener('submit', function(e){
    e.preventDefault();
    btn.disabled = true; msg.textContent = '解鎖中…';
    var keep = document.getElementById('keep').checked;
    derive(document.getElementById('pw').value).then(function(raw){
      return open(raw).then(function(html){
        if(keep){ try{ localStorage.setItem(KEY, enc(raw)); }catch(e){} }
        show(html);
      });
    }).catch(function(){
      btn.disabled = false; msg.textContent = '密碼不正確，再試一次';
      f.classList.remove('shake'); void f.offsetWidth; f.classList.add('shake');
    });
  });
})();
</script>
</body>
</html>
`;
writeFileSync(out, page);
console.log('已加密 → ' + out + '（' + page.length + ' 位元組）');
