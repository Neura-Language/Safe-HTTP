// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 浏览器端加密客户端（配合 neura-crypto.wasm）
 *
 * 流程：
 *   1. 取服务端静态 X-Wing 公钥 /neura-pk，用 WASM 算 SHA512 指纹；
 *      与页面里 pin 的指纹比对（不一致直接中止）——这一步让中间人无法
 *      调包公钥，量子计算机也伪造不了 SHA512 指纹。
 *   2. /__neura/boot：发送 nonce||ephemeral_pk||Encaps(静态pk)，
 *      拿回 sid||服务端 ephemeral_pk||Encaps(ephemeral_pk)；
 *      WASM 内派生根/方向密钥（浏览器侧不落任何长期密钥）。
 *   3. /__neura/app：把 HTTP 请求加密后 POST，响应在 WASM 内解密，
 *      得到真实页面后渲染。
 */
(function () {
  'use strict';

  /* WASI 导入：只实现真正会用到的，其余 no-op（用 Proxy 兜底，
   * 避免 wasm 侧新增导入时页面直接 instantiate 失败）。 */
  function wasiImports(getMemory) {
    var mem = function () { return getMemory().memory.buffer; };
    var table = {
      random_get: function (ptr, len) {
        var dst = new Uint8Array(mem(), ptr, len);
        dst.set(crypto.getRandomValues(new Uint8Array(len)));
        return 0;
      },
      clock_time_get: function (id, prec, out) {
        new DataView(mem()).setBigUint64(out, BigInt(Date.now()) * 1000000n, true);
        return 0;
      },
      clock_res_get: function (id, out) {
        new DataView(mem()).setBigUint64(out, 1000000n, true);
        return 0;
      },
      args_sizes_get: function (argc, bufSize) {
        var dv = new DataView(mem());
        dv.setUint32(argc, 0, true);
        dv.setUint32(bufSize, 0, true);
        return 0;
      },
      fd_write: function () { return 0; },
      fd_read: function () { return 8; },      /* EBADF */
      fd_close: function () { return 0; },
      fd_seek: function () { return 8; },
      poll_oneoff: function () { return 8; },
      proc_exit: function () { return 0; },
      sched_yield: function () { return 0; }
    };
    return {
      wasi_snapshot_preview1: new Proxy(table, {
        get: function (t, p) { return (p in t) ? t[p] : function () { return 0; }; },
        has: function () { return true; }
      })
    };
  }

  function Neura(opts) {
    this.site = (opts && opts.site) || location.hostname;
    this.wasmUrl = (opts && opts.wasmUrl) || '/neura-crypto.wasm';
    this.pinHex = (opts && opts.pinHex) || null;
    this.ex = null;
    this.sidHex = null;
    this.fpHex = null;
  }

  Neura.prototype.bytes = function (ptr, len) {
    return new Uint8Array(this.ex.memory.buffer, ptr, len).slice();
  };
  Neura.prototype.put = function (u8) {
    var p = this.ex.malloc(u8.length);
    if (!p) { throw new Error('wasm 内存不足'); }
    new Uint8Array(this.ex.memory.buffer, p, u8.length).set(u8);
    return p;
  };
  Neura.prototype.free = function (p) { if (p) { this.ex.free(p); } };
  Neura.prototype.hex = function (u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) {
      s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    }
    return s;
  };

  Neura.prototype.load = async function () {
    var resp = await fetch(this.wasmUrl, { cache: 'no-store' });
    if (!resp.ok) { throw new Error('wasm 下载失败 HTTP ' + resp.status); }
    var bytes = await resp.arrayBuffer();
    var self = this;
    var inst = await WebAssembly.instantiate(bytes, wasiImports(function () { return self.ex; }));
    this.ex = inst.instance.exports;
    if (this.ex.nw_init() !== 0) { throw new Error('wasm 初始化失败'); }
    return this;
  };

  Neura.prototype.fingerprint = function (pkU8) {
    var p = this.put(pkU8);
    var out = this.ex.malloc(64);
    var n = this.ex.nw_fp(p, pkU8.length, out, 64);
    var fp = n === 64 ? this.bytes(out, 64) : null;
    this.free(p);
    this.free(out);
    return fp;
  };

  Neura.prototype.boot = async function () {
    var pkResp = await fetch('/neura-pk', { cache: 'no-store' });
    if (!pkResp.ok) { throw new Error('/neura-pk 失败'); }
    var pk = new Uint8Array(await pkResp.arrayBuffer());
    if (pk.length !== 1216) { throw new Error('服务端公钥长度异常'); }

    var fp = this.fingerprint(pk);
    this.fpHex = this.hex(fp);
    if (this.pinHex && this.pinHex !== this.fpHex) {
      throw new Error('服务端公钥指纹不匹配（疑似中间人）：期望 ' +
                      this.pinHex.slice(0, 16) + '… 实际 ' + this.fpHex.slice(0, 16) + '…');
    }

    var pPk = this.put(pk);
    var txCap = 32 + 1216 + 1120;
    var tx = this.ex.malloc(txCap);
    var n = this.ex.nw_boot(pPk, pk.length, tx, txCap);
    this.free(pPk);
    if (n !== txCap) { this.free(tx); throw new Error('nw_boot 失败'); }
    var txU8 = this.bytes(tx, n);
    this.free(tx);

    var bootResp = await fetch('/__neura/boot', { method: 'POST', body: txU8,
                                                  cache: 'no-store' });
    if (!bootResp.ok) { throw new Error('密钥协商失败 HTTP ' + bootResp.status); }
    var boot = new Uint8Array(await bootResp.arrayBuffer());
    if (boot.length !== 16 + 1216 + 1120) { throw new Error('boot 回包长度异常'); }
    this.sidHex = this.hex(boot.slice(0, 16));

    var pFin = this.put(boot.slice(16));
    var ok = this.ex.nw_finish(pFin, boot.length - 16);
    this.free(pFin);
    if (ok !== 1) { throw new Error('会话密钥派生失败'); }
    return this;
  };

  /* 通过加密通道发起一次 HTTP 请求，返回明文字节 */
  Neura.prototype.request = async function (method, path, extraHeaders) {
    var req = method + ' ' + path + ' HTTP/1.1\r\nHost: ' + this.site +
              '\r\nConnection: close\r\n' + (extraHeaders || '') + '\r\n';
    var reqU8 = new TextEncoder().encode(req);
    var pIn = this.put(reqU8);
    var cap = reqU8.length + 128;
    var pOut = this.ex.malloc(cap);
    var n = this.ex.nw_seal(pIn, reqU8.length, pOut, cap);
    this.free(pIn);
    if (n <= 0) { this.free(pOut); throw new Error('请求加密失败'); }
    var frame = this.bytes(pOut, n);
    this.free(pOut);

    var resp = await fetch('/__neura/app', {
      method: 'POST', body: frame, cache: 'no-store',
      headers: { 'X-Neura-Sid': this.sidHex }
    });
    if (!resp.ok) { throw new Error('加密请求失败 HTTP ' + resp.status); }
    var sealed = new Uint8Array(await resp.arrayBuffer());

    var pS = this.put(sealed);
    var outCap = 512 * 1024;
    var pP = this.ex.malloc(outCap);
    var m = this.ex.nw_open(pS, sealed.length, pP, outCap);
    this.free(pS);
    if (m < 0) { this.free(pP); throw new Error('响应解密失败'); }
    var plain = this.bytes(pP, m);
    this.free(pP);
    return plain;
  };

  Neura.prototype.bodyOf = function (plainU8) {
    var s = new TextDecoder().decode(plainU8);
    var idx = s.indexOf('\r\n\r\n');
    return idx >= 0 ? s.slice(idx + 4) : s;
  };

  window.Neura = Neura;
})();
