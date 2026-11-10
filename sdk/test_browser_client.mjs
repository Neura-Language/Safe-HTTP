// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * 用 node 复现浏览器端流程（同一份 neura-crypto.wasm + 同一套协议），
 * 用于在没有浏览器的环境里做端到端验证。
 *
 *   node sdk/test_browser_client.mjs http://127.0.0.1
 */
import { readFile } from 'node:fs/promises';

const base = process.argv[2] || 'http://127.0.0.1';

function wasiImports(getMemory) {
  const mem = () => getMemory().exports.memory.buffer;
  const table = {
    random_get(ptr, len) {
      new Uint8Array(mem(), ptr, len).set(crypto.getRandomValues(new Uint8Array(len)));
      return 0;
    },
    clock_time_get(id, prec, out) {
      new DataView(mem()).setBigUint64(out, BigInt(Date.now()) * 1000000n, true);
      return 0;
    },
    clock_res_get(id, out) {
      new DataView(mem()).setBigUint64(out, 1000000n, true);
      return 0;
    },
    args_sizes_get(argc, argvBufSize) {
      new DataView(mem()).setUint32(argc, 0, true);
      new DataView(mem()).setUint32(argvBufSize, 0, true);
      return 0;
    },
    fd_write: () => 0,
    fd_read: () => 8,          /* EBADF */
    fd_close: () => 0,
    fd_seek: () => 8,
    poll_oneoff: () => 8,
    proc_exit: () => 0,
    sched_yield: () => 0
  };
  return {
    wasi_snapshot_preview1: new Proxy(table, {
      get(target, prop) {
        if (prop in target) { return target[prop]; }
        return () => 0;        /* 其余 WASI 调用一律 no-op 成功 */
      },
      has() { return true; }
    })
  };
}

const wasmBytes = await readFile(new URL('./neura-crypto.wasm', import.meta.url));
let instance = null;
const { instance: inst } = await WebAssembly.instantiate(wasmBytes, wasiImports(() => instance));
instance = inst;
const ex = inst.exports;
if (ex.nw_init() !== 0) throw new Error('wasm init failed');

const put = (u8) => {
  const p = ex.malloc(u8.length);
  new Uint8Array(ex.memory.buffer, p, u8.length).set(u8);
  return p;
};
const take = (p, len) => new Uint8Array(ex.memory.buffer, p, len).slice();

/* 1) 取服务端静态公钥 + 校验指纹 pin */
const pk = new Uint8Array(await (await fetch(base + '/neura-pk')).arrayBuffer());
const pPk = put(pk);
const pFp = ex.malloc(64);
const fpLen = ex.nw_fp(pPk, pk.length, pFp, 64);
const fpHex = Buffer.from(take(pFp, fpLen)).toString('hex');
ex.free(pFp);
const pinned = (await (await fetch(base + '/neura-fp')).text()).trim();
console.log('server_pk_bytes =', pk.length);
console.log('fingerprint     =', fpHex.slice(0, 32) + '…');
console.log('pin_match       =', fpHex === pinned ? 'YES' : 'NO');

/* 2) boot：协商会话密钥 */
const txCap = 32 + 1216 + 1120;
const pTx = ex.malloc(txCap);
const txLen = ex.nw_boot(pPk, pk.length, pTx, txCap);
const tx = take(pTx, txLen);
ex.free(pTx);
ex.free(pPk);
const bootResp = await fetch(base + '/__neura/boot', { method: 'POST', body: tx });
const boot = new Uint8Array(await bootResp.arrayBuffer());
console.log('boot_http       =', bootResp.status, 'bytes =', boot.length);
const sidHex = Buffer.from(boot.slice(0, 16)).toString('hex');
const pFin = put(boot.slice(16));
const finOk = ex.nw_finish(pFin, boot.length - 16);
ex.free(pFin);
console.log('key_agreement   =', finOk === 1 ? 'OK' : 'FAILED');

/* 3) 通过加密通道取真实页面 */
const reqText = 'GET / HTTP/1.1\r\nHost: test.jqlhtm.cn\r\nConnection: close\r\n\r\n';
const reqU8 = new TextEncoder().encode(reqText);
const pIn = put(reqU8);
const pSealed = ex.malloc(reqU8.length + 128);
const sealedLen = ex.nw_seal(pIn, reqU8.length, pSealed, reqU8.length + 128);
const sealed = take(pSealed, sealedLen);
ex.free(pSealed);
ex.free(pIn);
console.log('ciphertext_len  =', sealedLen, '（明文请求', reqU8.length, '字节）');

const appResp = await fetch(base + '/__neura/app', {
  method: 'POST',
  body: sealed,
  headers: { 'X-Neura-Sid': sidHex }
});
const sealedResp = new Uint8Array(await appResp.arrayBuffer());
console.log('app_http        =', appResp.status, 'bytes =', sealedResp.length);
const pS = put(sealedResp);
const outCap = 512 * 1024;
const pOut = ex.malloc(outCap);
const plainLen = ex.nw_open(pS, sealedResp.length, pOut, outCap);
ex.free(pS);
if (plainLen < 0) throw new Error('decrypt failed');
const plain = Buffer.from(take(pOut, plainLen)).toString('utf8');
ex.free(pOut);

const body = plain.slice(plain.indexOf('\r\n\r\n') + 4);
console.log('decrypted_len   =', plainLen);
console.log('status_line     =', plain.split('\r\n')[0]);
console.log('has_real_page   =', /真实站点首页/.test(body) ? 'YES' : 'NO');
console.log('has_script      =', /页面脚本执行正常/.test(body) ? 'YES' : 'NO');

/* 4) 线上字节取证：密文里不应出现任何明文标记 */
const { writeFile } = await import('node:fs/promises');
await writeFile('/tmp/wire_req.bin', Buffer.from(sealed));
await writeFile('/tmp/wire_resp.bin', Buffer.from(sealedResp));

/* 5) 公钥调包检测：改 1 个比特，指纹必须变 */
const pk2 = pk.slice();
pk2[0] ^= 0x01;
const pPk2 = put(pk2);
const pFp2 = ex.malloc(64);
const n2 = ex.nw_fp(pPk2, pk2.length, pFp2, 64);
const fp2Hex = Buffer.from(take(pFp2, n2)).toString('hex');
ex.free(pFp2);
ex.free(pPk2);
console.log('tamper_detected =', fp2Hex !== fpHex ? 'YES (指纹改变)' : 'NO');
