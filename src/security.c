// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Neura-S2S 加密层实现（libs2s 薄封装）
 *
 * 当前实现范围（骨架阶段）：
 *   1. 全局初始化、算法名、libsodium 版本
 *   2. RootKey 生成/读写/校验（0600 + 临时文件 rename）
 *   3. 信任锚指纹派生、TXT 记录生成/解析/比对
 *   4. sh_neura_conn 生命周期（secure region + ns2s_handshake_init）
 *
 * 待实现（下一步：src/neura_conn.c 的握手/会话胶水）：
 *   handshake_start / handshake_pump / take_kem_job / kem_done /
 *   seal / open / ratchet_tick / ratchet_apply / sh_crypto_*
 *
 * 约束：密钥只用 sodium_memzero / ns2s_secure_zero；不使用 memset。
 */
#include "security.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>

#include "neura/s2s_crypto.h"
#include "neura/s2s_secure_mem.h"

#include "neura_internal.h"

/* ==========================================================================
 * 静态工具
 * ========================================================================== */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_encode_lower(const uint8_t *in, size_t len, char *out, size_t cap)
{
    static const char digits[] = "0123456789abcdef";
    if (out == NULL || cap < len * 2u + 1u) {
        return NS2S_ERR_INVALID;
    }
    for (size_t i = 0; i < len; i++) {
        out[i * 2u] = digits[(in[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = digits[in[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
    return NS2S_OK;
}

static int hex_decode(const char *in, size_t len, uint8_t *out, size_t cap)
{
    if (in == NULL || out == NULL || len % 2u != 0 || len / 2u > cap) {
        return NS2S_ERR_INVALID;
    }
    for (size_t i = 0; i < len / 2u; i++) {
        int hi = hex_nibble(in[i * 2u]);
        int lo = hex_nibble(in[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return NS2S_ERR_INVALID;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return NS2S_OK;
}

/* 读整个文件（上限 max_len），成功返回读取长度，失败 -1 */
static ssize_t read_small_file(const char *path, char *buf, size_t max_len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, max_len - 1u);
    int saved = errno;
    close(fd);
    if (n < 0) {
        errno = saved;
        return -1;
    }
    buf[n] = '\0';
    return n;
}

/* 只做 "消息[: 详情]" 拼接，避免可变格式串带来的 -Wformat-nonliteral */
static void set_err(char *err, size_t cap, const char *msg, const char *detail)
{
    if (err == NULL || cap == 0) {
        return;
    }
    if (detail != NULL) {
        snprintf(err, cap, "%s: %s", msg, detail);
    } else {
        snprintf(err, cap, "%s", msg);
    }
}

/* ==========================================================================
 * 1. 全局初始化
 * ========================================================================== */
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static int g_init_status = NS2S_ERR_STATE;

static void global_init_once(void)
{
    /*
     * ns2s_init() 内部会调用 sodium_init()；ns2s_crypto_init() 再校验
     * 所需 libsodium 能力（X-Wing / AEAD / HKDF-SHA512）。
     */
    int rc = ns2s_init();
    if (rc != NS2S_OK) {
        g_init_status = rc;
        return;
    }
    rc = ns2s_crypto_init();
    g_init_status = (rc == 0) ? NS2S_OK : NS2S_ERR_CRYPTO;
}

int sh_neura_global_init(void)
{
    pthread_once(&g_init_once, global_init_once);
    return g_init_status;
}

const char *sh_neura_alg_name(uint8_t alg)
{
    switch (alg) {
    case NS2S_ALG_AES256GCM:
        return "AES-256-GCM";
    case NS2S_ALG_CHACHA20POLY1305:
        return "ChaCha20-Poly1305";
    default:
        return "unknown";
    }
}

const char *sh_neura_crypto_version(void)
{
    return sodium_version_string();
}

/* ==========================================================================
 * 2. RootKey
 * ========================================================================== */
int sh_rootkey_generate(uint8_t out[SH_ROOTKEY_BYTES])
{
    if (out == NULL) {
        return NS2S_ERR_INVALID;
    }
    ns2s_random_bytes(out, SH_ROOTKEY_BYTES);
    return NS2S_OK;
}

int sh_rootkey_hex(const uint8_t key[SH_ROOTKEY_BYTES],
                   char out[SH_ROOTKEY_HEX_LEN])
{
    if (key == NULL) {
        return NS2S_ERR_INVALID;
    }
    return hex_encode_lower(key, SH_ROOTKEY_BYTES, out, SH_ROOTKEY_HEX_LEN);
}

int sh_rootkey_from_hex(const char *hex, uint8_t out[SH_ROOTKEY_BYTES])
{
    if (hex == NULL || out == NULL) {
        return NS2S_ERR_INVALID;
    }
    /* 容忍前后空白与 \r\n */
    while (*hex == ' ' || *hex == '\t' || *hex == '\r' || *hex == '\n') {
        hex++;
    }
    size_t len = strnlen(hex, SH_ROOTKEY_HEX_LEN + 8u);
    while (len > 0 && (hex[len - 1u] == '\r' || hex[len - 1u] == '\n' ||
                       hex[len - 1u] == ' ' || hex[len - 1u] == '\t')) {
        len--;
    }
    if (len != SH_ROOTKEY_BYTES * 2u) {
        return NS2S_ERR_INVALID;
    }
    return hex_decode(hex, len, out, SH_ROOTKEY_BYTES);
}

int sh_rootkey_load(const char *path, uint8_t out[SH_ROOTKEY_BYTES],
                    char *err, size_t errcap)
{
    if (path == NULL || out == NULL) {
        return NS2S_ERR_INVALID;
    }
    char buf[SH_ROOTKEY_HEX_LEN + 16u];
    ssize_t n = read_small_file(path, buf, sizeof buf);
    if (n <= 0) {
        set_err(err, errcap, "无法读取 RootKey 文件", path);
        return NS2S_ERR_IO;
    }
    int rc = sh_rootkey_from_hex(buf, out);
    if (rc != NS2S_OK) {
        set_err(err, errcap, "RootKey 文件内容非法（需 64 位 hex）", path);
        ns2s_secure_zero(buf, sizeof buf);
        return rc;
    }
    ns2s_secure_zero(buf, sizeof buf);
    return NS2S_OK;
}

int sh_rootkey_save(const char *path, const uint8_t key[SH_ROOTKEY_BYTES],
                    unsigned mode, char *err, size_t errcap)
{
    if (path == NULL || key == NULL) {
        return NS2S_ERR_INVALID;
    }
    char hex[SH_ROOTKEY_HEX_LEN];
    int rc = sh_rootkey_hex(key, hex);
    if (rc != NS2S_OK) {
        return rc;
    }

    char tmp[4096];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) {
        return NS2S_ERR_INVALID;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  (mode_t)(mode == 0 ? 0600u : mode));
    if (fd < 0) {
        set_err(err, errcap, "无法创建临时文件", tmp);
        return NS2S_ERR_IO;
    }

    size_t total = 0;
    size_t want = SH_ROOTKEY_BYTES * 2u;
    bool ok = true;
    while (total < want) {
        ssize_t w = write(fd, hex + total, want - total);
        if (w <= 0) {
            ok = false;
            break;
        }
        total += (size_t)w;
    }
    if (ok && write(fd, "\n", 1) != 1) {
        ok = false;
    }
    if (ok && fsync(fd) != 0) {
        ok = false;
    }
    close(fd);

    /* 无论成败都擦掉明文 hex */
    ns2s_secure_zero(hex, sizeof hex);

    if (!ok) {
        unlink(tmp);
        set_err(err, errcap, "写入 RootKey 失败", tmp);
        return NS2S_ERR_IO;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        set_err(err, errcap, "重命名 RootKey 失败", path);
        return NS2S_ERR_IO;
    }
    return NS2S_OK;
}

int sh_rootkey_load_or_create(const char *path, unsigned mode, bool *created,
                              uint8_t out[SH_ROOTKEY_BYTES],
                              char *err, size_t errcap)
{
    if (created != NULL) {
        *created = false;
    }
    uint8_t key[SH_ROOTKEY_BYTES];
    int rc = sh_rootkey_load(path, key, err, errcap);
    if (rc == NS2S_OK) {
        memcpy(out, key, sizeof key);
        ns2s_secure_zero(key, sizeof key);
        return NS2S_OK;
    }
    if (rc != NS2S_ERR_IO) {
        return rc;    /* 文件存在但内容非法：拒绝静默覆盖 */
    }

    rc = sh_rootkey_generate(key);
    if (rc != NS2S_OK) {
        return rc;
    }
    rc = sh_rootkey_save(path, key, mode, err, errcap);
    if (rc != NS2S_OK) {
        ns2s_secure_zero(key, sizeof key);
        return rc;
    }
    memcpy(out, key, sizeof key);
    ns2s_secure_zero(key, sizeof key);
    if (created != NULL) {
        *created = true;
    }
    return NS2S_OK;
}

/* ==========================================================================
 * 3. 信任锚指纹 / TXT
 * ========================================================================== */
int sh_anchor_fingerprint(const uint8_t root_key[SH_ROOTKEY_BYTES],
                          uint8_t out[SH_ANCHOR_FP_BYTES])
{
    if (root_key == NULL || out == NULL) {
        return NS2S_ERR_INVALID;
    }
    /*
     * fp = SHA-512(SH_ANCHOR_FP_DOMAIN || rootkey)[0..31]
     * 必须与 install.sh 里 openssl dgst -sha512 的复算逐字节一致。
     */
    ns2s_sha512 st;
    uint8_t digest[NS2S_SHA512_BYTES];
    ns2s_sha512_init(&st);
    ns2s_sha512_update(&st, (const uint8_t *)SH_ANCHOR_FP_DOMAIN,
                       SH_ANCHOR_FP_DOMAIN_LEN);
    ns2s_sha512_update(&st, root_key, SH_ROOTKEY_BYTES);
    ns2s_sha512_final(&st, digest);
    memcpy(out, digest, SH_ANCHOR_FP_BYTES);
    ns2s_secure_zero(digest, sizeof digest);
    return NS2S_OK;
}

int sh_anchor_fingerprint_hex(const uint8_t root_key[SH_ROOTKEY_BYTES],
                              char out[SH_FINGERPRINT_HEX_LEN])
{
    uint8_t fp[SH_ANCHOR_FP_BYTES];
    int rc = sh_anchor_fingerprint(root_key, fp);
    if (rc == NS2S_OK) {
        rc = hex_encode_lower(fp, sizeof fp, out, SH_FINGERPRINT_HEX_LEN);
    }
    ns2s_secure_zero(fp, sizeof fp);
    return rc;
}

int sh_anchor_txt_name(const char *host, char *out, size_t cap)
{
    if (host == NULL || out == NULL) {
        return NS2S_ERR_INVALID;
    }
    int n = snprintf(out, cap, "%s%s", SH_DNS_TXT_PREFIX, host);
    if (n < 0 || (size_t)n >= cap) {
        return NS2S_ERR_LENGTH;
    }
    return NS2S_OK;
}

int sh_anchor_format_txt(const uint8_t root_key[SH_ROOTKEY_BYTES],
                         char *out, size_t cap)
{
    char fp[SH_FINGERPRINT_HEX_LEN];
    int rc = sh_anchor_fingerprint_hex(root_key, fp);
    if (rc != NS2S_OK) {
        return rc;
    }
    int n = snprintf(out, cap, "v=%s; fp=%s", SH_ANCHOR_TXT_VERSION, fp);
    ns2s_secure_zero(fp, sizeof fp);
    if (n < 0 || (size_t)n >= cap) {
        return NS2S_ERR_LENGTH;
    }
    return NS2S_OK;
}

/* 在 "k=v" 串里找 key，返回值起点与长度 */
static bool txt_field(const char *txt, const char *key,
                      const char **val, size_t *val_len)
{
    size_t klen = strlen(key);
    const char *p = txt;
    while ((p = strstr(p, key)) != NULL) {
        if (p[klen] == '=') {
            const char *v = p + klen + 1u;
            const char *end = v;
            while (*end != '\0' && *end != ';' && *end != ' ' && *end != '\t') {
                end++;
            }
            *val = v;
            *val_len = (size_t)(end - v);
            return true;
        }
        p += klen;
    }
    return false;
}

int sh_anchor_parse_txt(const char *txt, sh_anchor *out,
                        char *err, size_t errcap)
{
    if (txt == NULL || out == NULL) {
        return NS2S_ERR_INVALID;
    }
    const char *ver = NULL;
    size_t ver_len = 0;
    if (!txt_field(txt, "v", &ver, &ver_len) ||
        ver_len != strlen(SH_ANCHOR_TXT_VERSION) ||
        memcmp(ver, SH_ANCHOR_TXT_VERSION, ver_len) != 0) {
        set_err(err, errcap, "TXT 版本字段非法（期望 v=ns2s1）", NULL);
        return NS2S_ERR_INVALID;
    }
    const char *fp = NULL;
    size_t fp_len = 0;
    if (!txt_field(txt, "fp", &fp, &fp_len) || fp_len != 64u) {
        set_err(err, errcap, "TXT 缺少 64 位 fp 字段", NULL);
        return NS2S_ERR_INVALID;
    }
    uint8_t raw[SH_ANCHOR_FP_BYTES];
    if (hex_decode(fp, fp_len, raw, sizeof raw) != NS2S_OK) {
        set_err(err, errcap, "TXT fp 字段不是合法 hex", NULL);
        return NS2S_ERR_INVALID;
    }
    memcpy(out->fp, raw, sizeof raw);
    memcpy(out->fp_hex, fp, 64);
    out->fp_hex[64] = '\0';
    ns2s_secure_zero(raw, sizeof raw);
    return NS2S_OK;
}

int sh_anchor_verify(const uint8_t root_key[SH_ROOTKEY_BYTES], sh_anchor *a)
{
    if (root_key == NULL || a == NULL) {
        return NS2S_ERR_INVALID;
    }
    uint8_t local[SH_ANCHOR_FP_BYTES];
    int rc = sh_anchor_fingerprint(root_key, local);
    if (rc != NS2S_OK) {
        return rc;
    }
    bool same = (sodium_memcmp(local, a->fp, sizeof local) == 0);
    ns2s_secure_zero(local, sizeof local);
    a->verified = same;
    return same ? NS2S_OK : SH_ERR_TRUST_ANCHOR;
}

/* ==========================================================================
 * 4. 会话生命周期
 * ========================================================================== */
sh_neura_conn *sh_neura_conn_new(const sh_neura_opts *opts)
{
    if (opts == NULL || opts->root_key == NULL || opts->role == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (sh_neura_global_init() != NS2S_OK) {
        errno = EIO;
        return NULL;
    }

    /* 整个上下文（含 session/root/ratchet 私钥）必须落在安全区 */
    ns2s_secure_region region;
    if (ns2s_secure_alloc(&region, sizeof(sh_neura_conn) + sizeof(ns2s_handshake)) != 0) {
        errno = ENOMEM;
        return NULL;
    }
    sh_neura_conn *n = (sh_neura_conn *)region.ptr;
    sodium_memzero(n, sizeof(sh_neura_conn) + sizeof(ns2s_handshake));

    n->region = region;
    n->hs = (ns2s_handshake *)(void *)((uint8_t *)n + sizeof(sh_neura_conn));
    n->magic = SH_NEURA_MAGIC;
    n->role = opts->role;
    n->phase = SH_NEURA_IDLE;
    n->alg = 0;
    n->alg_mask = opts->alg_mask != 0 ? opts->alg_mask : SH_ALG_MASK_DEFAULT;
    n->max_frame = opts->max_frame != 0 ? opts->max_frame : SH_DEFAULT_MAX_FRAME;
    n->handshake_timeout_ms = opts->handshake_timeout_ms != 0
                                  ? opts->handshake_timeout_ms
                                  : SH_HANDSHAKE_TIMEOUT_MS;
    memcpy(n->root_key, opts->root_key, SH_ROOTKEY_BYTES);
    n->require_anchor = opts->require_trust_anchor;
    if (opts->server_name != NULL) {
        snprintf(n->server_name, sizeof n->server_name, "%s", opts->server_name);
    }
    if (opts->doh != NULL) {
        n->doh = *opts->doh;
        n->has_doh = true;
    }
    n->last_status = NS2S_OK;
    n->created_ms = 0;

    /*
     * 用 now_ms=0 初始化只确定角色/RootKey/alg_mask；真正的握手在
     * sh_neura_handshake_start() 里用真实 now_ms 重新 init（库把
     * deadline 算成 now_ms + 3s，用 0 会让 check_deadline 立刻超时）。
     */
    ns2s_handshake_init(n->hs, n->role, n->root_key, n->alg_mask, 0);
    return n;
}

void sh_neura_conn_free(sh_neura_conn *n)
{
    if (n == NULL) {
        return;
    }
    if (n->magic != SH_NEURA_MAGIC) {
        return;    /* 已释放或未初始化：拒绝二次释放 */
    }
    for (ns2s_kem_job *j = n->pending; j != NULL; ) {
        ns2s_kem_job *next = j->next;
        ns2s_kem_job_destroy(j);
        free(j);
        j = next;
    }
    n->pending = NULL;
    if (n->hs != NULL) {
        ns2s_handshake_destroy(n->hs);
        n->hs = NULL;
    }
    ns2s_session_destroy(&n->session);

    ns2s_secure_region region = n->region;
    n->magic = 0;
    sodium_memzero(n->root_key, sizeof n->root_key);
    ns2s_secure_free(&region);
}

sh_neura_phase sh_neura_phase_of(const sh_neura_conn *n)
{
    return n != NULL ? n->phase : SH_NEURA_FAILED;
}

bool sh_neura_established(const sh_neura_conn *n)
{
    return n != NULL && n->phase == SH_NEURA_ESTABLISHED &&
           n->session.magic == NS2S_SESSION_MAGIC;
}

uint8_t sh_neura_alg(const sh_neura_conn *n)
{
    return n != NULL ? n->alg : 0;
}

uint64_t sh_neura_epoch(const sh_neura_conn *n)
{
    if (!sh_neura_established(n)) {
        return 0;
    }
    return n->session.current_ratchet_id;
}

int sh_neura_last_status(const sh_neura_conn *n)
{
    return n != NULL ? n->last_status : NS2S_ERR_INVALID;
}
