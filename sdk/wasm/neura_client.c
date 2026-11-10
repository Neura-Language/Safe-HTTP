// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 浏览器端 Neura-S2S 客户端（编译为 WebAssembly）
 *
 * 安全目标（用户端"零密钥"）：
 *   浏览器**不持有任何长期密钥**，RootKey 永不下发。会话密钥由 X-Wing
 *   (ML-KEM-768 + X25519) 现场协商：
 *
 *     client: ephemeral X-Wing keypair (cpk/csk)
 *     client --(nonce || cpk || ct_auth = Encaps(server_static_pk))--> server
 *     server --(srv_eph_pk || ct_fs = Encaps(cpk))-------------------> client
 *     ss_auth = Decaps(ct_auth, server_static_sk)   (服务端认证 + 抗量子)
 *     ss_fs   = Decaps(ct_fs,   csk)                (前向保密)
 *     ikm     = ss_auth || ss_fs
 *     salt    = SHA512(server_static_pk)            (客户端 pin 的指纹)
 *     info    = "neura-s2s-v1/http-boot" || transcript
 *     okm     = HKDF-SHA512(ikm, salt, info, 128) → root(64) || c2s(32) || s2c(32)
 *     ns2s_session_init(role=CLIENT, alg=CHACHA20_POLY1305, root, c2s, s2c)
 *
 *   中间人（含量子计算机）视角：
 *     - 拿不到任何长期密钥（本端没有，传输里也没有）；
 *     - 解不开 ML-KEM-768 / X25519 任一条腿 → 无法得到 ikm；
 *     - 想换掉 server_static_pk，必须同时伪造 SHA512 指纹（与 pin 冲突）。
 *
 * 说明：浏览器没有 AES-NI，因此本端固定用 ChaCha20-Poly1305。
 *
 * C ABI（供 JS 调用，全部在 wasm 线性内存上操作）：
 *   int nw_init(void);
 *   int nw_boot(const uint8_t *srv_pk, int pk_len, uint8_t *out, int out_cap);
 *   int nw_finish(const uint8_t *in, int in_len);
 *   int nw_seal(const uint8_t *in, int in_len, uint8_t *out, int out_cap);
 *   int nw_open(const uint8_t *in, int in_len, uint8_t *out, int out_cap);
 *   int nw_fp(uint8_t *out, int out_cap);   // 计算 srv_pk 的 SHA512 指纹（调试用）
 */
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "neura/s2s.h"
#include "neura/s2s_crypto.h"

#define NW_MAX_FRAME   (256u * 1024u)
#define NW_TX_LEN      (32u + NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES)
#define NW_FIN_LEN     (NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES)
#define NW_HDR_LEN     (NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + NS2S_TAG_BYTES)

static ns2s_session g_sess;
static int           g_ready;

static uint8_t g_nonce[32];
static uint8_t g_cpk[NS2S_XWING_PK_BYTES];
static uint8_t g_csk[NS2S_XWING_SK_BYTES];
static uint8_t g_ct_auth[NS2S_XWING_CT_BYTES];
static uint8_t g_ss_auth[NS2S_XWING_SS_BYTES];
static uint8_t g_spk[NS2S_XWING_PK_BYTES];      /* 服务端静态公钥（已 pin） */
static uint8_t g_srv_eph[NS2S_XWING_PK_BYTES];
static uint8_t g_ct_fs[NS2S_XWING_CT_BYTES];

static uint8_t g_io[NW_MAX_FRAME + NW_HDR_LEN + 64u];

static void put_nonce_log_marker(void) { /* 占位，便于 JS 侧断点 */ }

__attribute__((visibility("default")))
int nw_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }
    g_ready = 0;
    put_nonce_log_marker();
    return 0;
}

/*
 * 第一步：生成 ephemeral 密钥对 + 对服务端静态公钥做 Encaps。
 * out = nonce(32) || client_pk(1216) || ct_auth(1120) = 2368 字节
 * 返回写入字节数，<0 表示失败。
 */
__attribute__((visibility("default")))
int nw_boot(const uint8_t *srv_pk, int pk_len, uint8_t *out, int out_cap)
{
    if (srv_pk == NULL || out == NULL ||
        pk_len != (int)NS2S_XWING_PK_BYTES || out_cap < (int)NW_TX_LEN) {
        return -1;
    }
    memcpy(g_spk, srv_pk, NS2S_XWING_PK_BYTES);
    ns2s_random_bytes(g_nonce, sizeof g_nonce);

    if (ns2s_xwing_keypair(g_cpk, g_csk) != NS2S_OK) {
        return -1;
    }
    if (ns2s_xwing_enc(g_ct_auth, g_ss_auth, g_spk) != NS2S_OK) {
        return -1;
    }

    unsigned char *p = out;
    memcpy(p, g_nonce, sizeof g_nonce);
    memcpy(p + sizeof g_nonce, g_cpk, NS2S_XWING_PK_BYTES);
    memcpy(p + sizeof g_nonce + NS2S_XWING_PK_BYTES, g_ct_auth,
           NS2S_XWING_CT_BYTES);
    return (int)NW_TX_LEN;
}

/* 用派生出的密钥初始化业务会话；client 侧 auto_ratchet 恒为 0 */
static int derive_and_init(const uint8_t ct_fs[NS2S_XWING_CT_BYTES],
                           const uint8_t ss_fs[NS2S_XWING_SS_BYTES])
{
    uint8_t ikm[NS2S_XWING_SS_BYTES * 2];
    memcpy(ikm, g_ss_auth, NS2S_XWING_SS_BYTES);
    memcpy(ikm + NS2S_XWING_SS_BYTES, ss_fs, NS2S_XWING_SS_BYTES);

    uint8_t salt[NS2S_SHA512_BYTES];
    ns2s_sha512 h;
    ns2s_sha512_init(&h);
    ns2s_sha512_update(&h, g_spk, NS2S_XWING_PK_BYTES);
    ns2s_sha512_final(&h, salt);

    /* info = "neura-s2s-v1/http-boot" || transcript */
    static const char info_base[] = "neura-s2s-v1/http-boot";
    size_t info_len = (sizeof info_base - 1) + NW_TX_LEN + NW_FIN_LEN;
    char *info = (char *)malloc(info_len);
    if (info == NULL) {
        return -1;
    }
    size_t off = 0;
    memcpy(info + off, info_base, sizeof info_base - 1);
    off += sizeof info_base - 1;
    memcpy(info + off, g_nonce, sizeof g_nonce);
    off += sizeof g_nonce;
    memcpy(info + off, g_cpk, NS2S_XWING_PK_BYTES);
    off += NS2S_XWING_PK_BYTES;
    memcpy(info + off, g_srv_eph, NS2S_XWING_PK_BYTES);
    off += NS2S_XWING_PK_BYTES;
    memcpy(info + off, g_ct_auth, NS2S_XWING_CT_BYTES);
    off += NS2S_XWING_CT_BYTES;
    memcpy(info + off, ct_fs, NS2S_XWING_CT_BYTES);
    off += NS2S_XWING_CT_BYTES;

    uint8_t okm[128];
    int rc = ns2s_hkdf_sha512(ikm, sizeof ikm, salt, sizeof salt, info, off,
                              okm, sizeof okm);
    free(info);
    if (rc != NS2S_OK) {
        return -1;
    }

    uint8_t root[NS2S_ROOT_BYTES];
    uint8_t c2s[NS2S_KEY_BYTES];
    uint8_t s2c[NS2S_KEY_BYTES];
    memcpy(root, okm, NS2S_ROOT_BYTES);
    memcpy(c2s, okm + NS2S_ROOT_BYTES, NS2S_KEY_BYTES);
    memcpy(s2c, okm + NS2S_ROOT_BYTES + NS2S_KEY_BYTES, NS2S_KEY_BYTES);

    rc = ns2s_session_init(&g_sess, NS2S_ROLE_CLIENT, NS2S_ALG_CHACHA20POLY1305,
                           NW_MAX_FRAME, root, c2s, s2c, 1);
    sodium_memzero(okm, sizeof okm);
    sodium_memzero(root, sizeof root);
    sodium_memzero(c2s, sizeof c2s);
    sodium_memzero(s2c, sizeof s2c);
    sodium_memzero(ikm, sizeof ikm);
    if (rc != NS2S_OK) {
        return -1;
    }
    g_ready = 1;
    return 0;
}

/* 第二步：吃服务端回包 srv_eph_pk(1216) || ct_fs(1120)，完成密钥协商 */
__attribute__((visibility("default")))
int nw_finish(const uint8_t *in, int in_len)
{
    if (in == NULL || in_len != (int)NW_FIN_LEN) {
        return -1;
    }
    memcpy(g_srv_eph, in, NS2S_XWING_PK_BYTES);
    memcpy(g_ct_fs, in + NS2S_XWING_PK_BYTES, NS2S_XWING_CT_BYTES);

    uint8_t ss_fs[NS2S_XWING_SS_BYTES];
    if (ns2s_xwing_dec(ss_fs, g_ct_fs, g_csk) != NS2S_OK) {
        return -1;
    }
    int rc = derive_and_init(g_ct_fs, ss_fs);
    sodium_memzero(ss_fs, sizeof ss_fs);
    sodium_memzero(g_csk, sizeof g_csk);      /* ephemeral 私钥用完即毁 */
    sodium_memzero(g_ss_auth, sizeof g_ss_auth);
    return rc == 0 ? 1 : -1;
}

__attribute__((visibility("default")))
int nw_seal(const uint8_t *in, int in_len, uint8_t *out, int out_cap)
{
    if (!g_ready || in == NULL || out == NULL || in_len < 0) {
        return -1;
    }
    if ((size_t)in_len > NW_MAX_FRAME) {
        return -1;
    }
    size_t need = NW_HDR_LEN + (size_t)in_len;
    if ((size_t)out_cap < need) {
        return -1;
    }
    size_t written = 0;
    int rc = ns2s_session_seal(&g_sess, in, (size_t)in_len, out,
                               (size_t)out_cap, &written, 1);
    if (rc != NS2S_OK) {
        return -1;
    }
    return (int)written;
}

__attribute__((visibility("default")))
int nw_open(const uint8_t *in, int in_len, uint8_t *out, int out_cap)
{
    if (!g_ready || in == NULL || out == NULL || in_len <= 0) {
        return -1;
    }
    size_t got = 0;
    int rc = ns2s_session_open(&g_sess, in, (size_t)in_len, out,
                               (size_t)out_cap, &got);
    if (rc != NS2S_OK) {
        return -1;
    }
    return (int)got;
}

/* 计算服务端静态公钥指纹（SHA512），供 JS 与运维侧核对 pin 值 */
__attribute__((visibility("default")))
int nw_fp(const uint8_t *pk, int pk_len, uint8_t *out, int out_cap)
{
    if (pk == NULL || out == NULL || pk_len != (int)NS2S_XWING_PK_BYTES ||
        out_cap < (int)NS2S_SHA512_BYTES) {
        return -1;
    }
    ns2s_sha512 h;
    ns2s_sha512_init(&h);
    ns2s_sha512_update(&h, pk, NS2S_XWING_PK_BYTES);
    ns2s_sha512_final(&h, out);
    return (int)NS2S_SHA512_BYTES;
}

/* 供 JS 申请临时缓冲（避免把大缓冲直接放在 JS 侧反复拷贝） */
__attribute__((visibility("default")))
uint8_t *nw_scratch(int len)
{
    if (len < 0 || (size_t)len > sizeof g_io) {
        return NULL;
    }
    return g_io;
}

__attribute__((visibility("default")))
int nw_scratch_max(void)
{
    return (int)sizeof g_io;
}
