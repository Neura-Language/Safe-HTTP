// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * 在 node 里模拟浏览器环境，直接执行 sdk/neura.js（与真实浏览器同一份代码），
 * 验证 load → boot → request → bodyOf 全流程。
 *
 *   node sdk/test_neura_js.mjs http://test.jqlhtm.cn
 */
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const base = process.argv[2] || 'http://test.jqlhtm.cn';

/* 1) 最小浏览器环境：window / location / fetch（相对 URL 补 base） */
const realFetch = globalThis.fetch;
globalThis.fetch = (url, opts) => {
  const u = typeof url === 'string' && url.startsWith('/') ? base + url : url;
  return realFetch(u, opts);
};
globalThis.location = { hostname: new URL(base).hostname };
globalThis.window = globalThis;

/* 2) 执行真实的 neura.js */
const src = await readFile(new URL('./neura.js', import.meta.url), 'utf8');
vm.runInThisContext(src, { filename: 'neura.js' });

/* 3) 拿边缘端公布的指纹作为 pin（真实部署中该值应离线核对一次） */
const pin = (await (await fetch('/neura-fp')).text()).trim();

const n = new Neura({ site: globalThis.location.hostname,
                      wasmUrl: '/neura-crypto.wasm', pinHex: pin });
await n.load();
console.log('neura.js load     = OK');
await n.boot();
console.log('boot              = OK  sid=' + n.sidHex.slice(0, 16) + '…');
console.log('fingerprint_pin   = ' + (n.fpHex === pin ? 'MATCH' : 'MISMATCH'));

const plain = await n.request('GET', '/');
const body = n.bodyOf(plain);
console.log('encrypted_bytes   = ' + plain.length + '（解密后）');
console.log('has_real_page     = ' + (/真实站点首页/.test(body) ? 'YES' : 'NO'));
console.log('has_script        = ' + (/页面脚本执行正常/.test(body) ? 'YES' : 'NO'));

/* 4) 错误 pin 必须被拒绝（模拟中间人调包公钥） */
let blocked = 'NO';
try {
  const bad = new Neura({ site: globalThis.location.hostname,
                          wasmUrl: '/neura-crypto.wasm',
                          pinHex: 'ff'.repeat(64) });
  await bad.load();
  await bad.boot();
} catch (e) {
  blocked = /指纹不匹配/.test(String(e.message)) ? 'YES' : 'NO(' + e.message + ')';
}
console.log('mitm_blocked      = ' + blocked);
