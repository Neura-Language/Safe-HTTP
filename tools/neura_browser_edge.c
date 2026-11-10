// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 浏览器边缘接入（browser edge，监听 80）
 *
 * 作用：让**浏览器直接**通过 Neura-S2S 加密访问站点，从而"用户看到真实页面、
 * 但传输层是密文"，且浏览器端不持有任何长期密钥。
 *
 *  浏览器 (WASM 客户端)                本进程 (edge)                站点上游
 *    |-- GET /  ----------------------> 返回 shell 页 + wasm
 *    |-- GET /neura-pk --------------> 返回服务端静态 X-Wing 公钥
 *    |-- POST /__neura/boot ---------> Decaps(ct_auth, 静态sk) + Encaps(cpk)
 *    |<-- sid || spk_e || ct_fs ------ 派生 root/c2s/s2c，建会话
 *    |-- POST /__neura/app ----------> ns2s_session_open → 明文 HTTP 请求
 *    |                                  → 转发上游 → ns2s_session_seal
 *    |<-- 密文响应 -------------------- 浏览器 WASM 解密后渲染真实页面
 *
 * 密钥协商（与 sdk/wasm/neura_client.c 逐字节一致）：
 *   ikm  = ss_auth || ss_fs
 *   salt = SHA512(server_static_pk)                 ← 客户端 pin 的指纹
 *   info = "neura-s2s-v1/http-boot" || nonce||cpk||spk_e||ct_auth||ct_fs
 *   okm  = HKDF-SHA512(ikm, salt, info, 128) → root(64)||c2s(32)||s2c(32)
 *
 * 中间人（含量子）拿不到：传输里没有任何长期密钥；破解需同时攻破
 * ML-KEM-768 与 X25519；调包服务端公钥需伪造 SHA512 指纹（与 pin 冲突）。
 *
 * 用法：
 *   build/proxy/neura-browser-edge --listen 0.0.0.0:80 \
 *       --upstream 127.0.0.1:19080 --host test.jqlhtm.cn \
 *       --sdk-dir build/sdk --page sdk/index.html \
 *       --id /etc/safe-http/id.xwing
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "neura/s2s.h"
#include "neura/s2s_crypto.h"

#define EDGE_MAX_BODY   (512u * 1024u)
#define EDGE_MAX_UP     (8u * 1024u * 1024u)
#define EDGE_MAX_SESS   128
#define EDGE_SESS_TTL   120000u
#define EDGE_BOOT_LEN   (32u + NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES)
#define EDGE_FIN_LEN    (NS2S_XWING_PK_BYTES + NS2S_XWING_CT_BYTES)
#define EDGE_FRAME_OVH  (NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + NS2S_TAG_BYTES)
#define EDGE_MAX_FRAME  (256u * 1024u)

typedef struct {
    int          used;
    uint8_t      sid[16];
    uint64_t     last_ms;
    ns2s_session sess;
} edge_session;

static edge_session g_sess[EDGE_MAX_SESS];

static uint8_t g_id_pk[NS2S_XWING_PK_BYTES];
static uint8_t g_id_sk[NS2S_XWING_SK_BYTES];
static uint8_t g_id_fp[NS2S_SHA512_BYTES];

static const char *g_up_host = "127.0.0.1";
static uint16_t    g_up_port = 19080;
static const char *g_site_host = "test.jqlhtm.cn";

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static void hexify(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = d[p[i] >> 4];
        out[i * 2 + 1] = d[p[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* ---------------- 服务端长期身份（静态 X-Wing 密钥对） ---------------- */
static int identity_load(const char *path)
{
    struct stat st;
    FILE *fp = fopen(path, "rb");
    if (fp != NULL && stat(path, &st) == 0 &&
        st.st_size == (off_t)(NS2S_XWING_PK_BYTES + NS2S_XWING_SK_BYTES)) {
        if (fread(g_id_pk, 1, sizeof g_id_pk, fp) != sizeof g_id_pk ||
            fread(g_id_sk, 1, sizeof g_id_sk, fp) != sizeof g_id_sk) {
            fclose(fp);
            return -1;
        }
        fclose(fp);
    } else {
        if (fp != NULL) {
            fclose(fp);
        }
        if (ns2s_xwing_keypair(g_id_pk, g_id_sk) != NS2S_OK) {
            return -1;
        }
        mode_t old = umask(0077);
        fp = fopen(path, "wb");
        umask(old);
        if (fp == NULL) {
            fprintf(stderr, "无法写入身份文件 %s\n", path);
            return -1;
        }
        (void)fwrite(g_id_pk, 1, sizeof g_id_pk, fp);
        (void)fwrite(g_id_sk, 1, sizeof g_id_sk, fp);
        fclose(fp);
        fprintf(stderr, "[edge] 已生成服务端静态 X-Wing 身份: %s\n", path);
    }

    ns2s_sha512 h;
    ns2s_sha512_init(&h);
    ns2s_sha512_update(&h, g_id_pk, sizeof g_id_pk);
    ns2s_sha512_final(&h, g_id_fp);
    return 0;
}

/* ---------------- 会话表 ---------------- */
static void sess_gc(void)
{
    uint64_t now = now_ms();
    for (size_t i = 0; i < EDGE_MAX_SESS; i++) {
        if (g_sess[i].used && now > g_sess[i].last_ms + EDGE_SESS_TTL) {
            ns2s_session_destroy(&g_sess[i].sess);
            memset(&g_sess[i], 0, sizeof g_sess[i]);
        }
    }
}

static edge_session *sess_new(void)
{
    sess_gc();
    for (size_t i = 0; i < EDGE_MAX_SESS; i++) {
        if (!g_sess[i].used) {
            memset(&g_sess[i], 0, sizeof g_sess[i]);
            g_sess[i].used = 1;
            g_sess[i].last_ms = now_ms();
            ns2s_random_bytes(g_sess[i].sid, sizeof g_sess[i].sid);
            return &g_sess[i];
        }
    }
    return NULL;
}

static edge_session *sess_find(const char *hex)
{
    if (hex == NULL || strlen(hex) != 32) {
        return NULL;
    }
    uint8_t sid[16];
    for (size_t i = 0; i < 16; i++) {
        char b[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        char *end = NULL;
        long v = strtol(b, &end, 16);
        if (end == b + 2) {
            sid[i] = (uint8_t)v;
        } else {
            return NULL;
        }
    }
    for (size_t i = 0; i < EDGE_MAX_SESS; i++) {
        if (g_sess[i].used &&
            sodium_memcmp(g_sess[i].sid, sid, sizeof sid) == 0) {
            g_sess[i].last_ms = now_ms();
            return &g_sess[i];
        }
    }
    return NULL;
}

/* ---------------- 密钥派生（与 wasm 侧一致） ---------------- */
static int derive_keys(const uint8_t nonce[32],
                       const uint8_t cpk[NS2S_XWING_PK_BYTES],
                       const uint8_t spk_e[NS2S_XWING_PK_BYTES],
                       const uint8_t ct_auth[NS2S_XWING_CT_BYTES],
                       const uint8_t ct_fs[NS2S_XWING_CT_BYTES],
                       const uint8_t ss_auth[NS2S_XWING_SS_BYTES],
                       const uint8_t ss_fs[NS2S_XWING_SS_BYTES],
                       uint8_t root[NS2S_ROOT_BYTES], uint8_t c2s[NS2S_KEY_BYTES],
                       uint8_t s2c[NS2S_KEY_BYTES])
{
    uint8_t ikm[NS2S_XWING_SS_BYTES * 2];
    memcpy(ikm, ss_auth, NS2S_XWING_SS_BYTES);
    memcpy(ikm + NS2S_XWING_SS_BYTES, ss_fs, NS2S_XWING_SS_BYTES);

    uint8_t salt[NS2S_SHA512_BYTES];
    ns2s_sha512 h;
    ns2s_sha512_init(&h);
    ns2s_sha512_update(&h, g_id_pk, sizeof g_id_pk);
    ns2s_sha512_final(&h, salt);

    static const char info_base[] = "neura-s2s-v1/http-boot";
    uint8_t info[sizeof info_base + EDGE_BOOT_LEN + EDGE_FIN_LEN];
    size_t off = 0;
    memcpy(info + off, info_base, sizeof info_base - 1);
    off += sizeof info_base - 1;
    memcpy(info + off, nonce, 32);
    off += 32;
    memcpy(info + off, cpk, NS2S_XWING_PK_BYTES);
    off += NS2S_XWING_PK_BYTES;
    memcpy(info + off, spk_e, NS2S_XWING_PK_BYTES);
    off += NS2S_XWING_PK_BYTES;
    memcpy(info + off, ct_auth, NS2S_XWING_CT_BYTES);
    off += NS2S_XWING_CT_BYTES;
    memcpy(info + off, ct_fs, NS2S_XWING_CT_BYTES);
    off += NS2S_XWING_CT_BYTES;

    uint8_t okm[128];
    int rc = ns2s_hkdf_sha512(ikm, sizeof ikm, salt, sizeof salt, (const char *)info,
                              off, okm, sizeof okm);
    if (rc != NS2S_OK) {
        return -1;
    }
    memcpy(root, okm, NS2S_ROOT_BYTES);
    memcpy(c2s, okm + NS2S_ROOT_BYTES, NS2S_KEY_BYTES);
    memcpy(s2c, okm + NS2S_ROOT_BYTES + NS2S_KEY_BYTES, NS2S_KEY_BYTES);
    sodium_memzero(okm, sizeof okm);
    sodium_memzero(ikm, sizeof ikm);
    sodium_memzero(salt, sizeof salt);
    return 0;
}

/* ---------------- HTTP 小工具 ---------------- */
static int write_all(int fd, const void *p, size_t len)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, b + off, len - off);
        if (w <= 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int send_simple(int fd, int code, const char *ctype, const void *body,
                       size_t len, const char *extra_hdr)
{
    char hdr[512];
    int n = snprintf(hdr, sizeof hdr,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n%sConnection: close\r\n\r\n",
                     code, code == 200 ? "OK" : code == 404 ? "Not Found" : "Error",
                     ctype, len, extra_hdr != NULL ? extra_hdr : "");
    if (n <= 0 || (size_t)n >= sizeof hdr) {
        return -1;
    }
    if (write_all(fd, hdr, (size_t)n) != 0) {
        return -1;
    }
    return len > 0 ? write_all(fd, body, len) : 0;
}

static int read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz <= 0 || sz > (long)EDGE_MAX_UP) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out = buf;
    *len = (size_t)sz;
    return 0;
}

/* 读完整 HTTP 请求（头 + Content-Length 体） */
static int read_request(int fd, uint8_t *buf, size_t cap, size_t *len, char *sid_hex,
                        size_t sid_cap, char *path, size_t path_cap, char *method,
                        size_t method_cap)
{
    size_t used = 0;
    size_t head_len = 0;
    long clen = 0;
    for (;;) {
        if (used >= cap) {
            return -1;
        }
        ssize_t n = read(fd, buf + used, cap - used);
        if (n <= 0) {
            return -1;
        }
        used += (size_t)n;
        if (head_len == 0) {
            for (size_t i = 0; i + 3 < used; i++) {
                if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
                    buf[i + 3] == '\n') {
                    head_len = i + 4;
                    break;
                }
            }
            if (head_len == 0) {
                continue;
            }
            /* 方法 / 路径 */
            size_t sp1 = 0;
            while (sp1 < head_len && buf[sp1] != ' ') {
                sp1++;
            }
            size_t sp2 = sp1 + 1;
            while (sp2 < head_len && buf[sp2] != ' ') {
                sp2++;
            }
            if (sp1 == 0 || sp2 == sp1 + 1) {
                return -1;
            }
            size_t ml = sp1 < method_cap - 1 ? sp1 : method_cap - 1;
            memcpy(method, buf, ml);
            method[ml] = '\0';
            size_t pl = sp2 - sp1 - 1;
            if (pl >= path_cap) {
                return -1;
            }
            memcpy(path, buf + sp1 + 1, pl);
            path[pl] = '\0';

            /* 头部逐行扫描 */
            sid_hex[0] = '\0';
            size_t i = sp2 + 1;
            while (i + 1 < head_len) {
                size_t e = i;
                while (e + 1 < head_len && !(buf[e] == '\r' && buf[e + 1] == '\n')) {
                    e++;
                }
                size_t hl = e - i;
                if (hl == 0) {
                    break;
                }
                if (hl > 15 && strncasecmp((char *)buf + i, "content-length:", 15) == 0) {
                    clen = strtol((char *)buf + i + 15, NULL, 10);
                } else if (hl > 11 && strncasecmp((char *)buf + i, "x-neura-sid:", 12) == 0) {
                    size_t vs = i + 12;
                    while (vs < e && (buf[vs] == ' ' || buf[vs] == '\t')) {
                        vs++;
                    }
                    size_t vn = e - vs;
                    if (vn >= sid_cap) {
                        vn = sid_cap - 1;
                    }
                    memcpy(sid_hex, buf + vs, vn);
                    sid_hex[vn] = '\0';
                }
                i = e + 2;
            }
        }
        if (head_len > 0 && used >= head_len + (size_t)clen) {
            *len = used;
            return (int)head_len;
        }
    }
}

/* 把明文请求转发给上游（阻塞、Connection: close、读到 EOF） */
static int forward_upstream(const char *req, size_t req_len, uint8_t **resp,
                            size_t *resp_len)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)g_up_port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_up_host, portstr, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = {8, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    if (write_all(fd, req, req_len) != 0) {
        close(fd);
        return -1;
    }

    size_t cap = 8192;
    size_t used = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (buf == NULL) {
        close(fd);
        return -1;
    }
    for (;;) {
        if (used + 4096 > cap) {
            size_t ncap = cap * 2;
            if (ncap > EDGE_MAX_UP) {
                break;
            }
            uint8_t *nb = (uint8_t *)realloc(buf, ncap);
            if (nb == NULL) {
                break;
            }
            buf = nb;
            cap = ncap;
        }
        ssize_t n = read(fd, buf + used, cap - used);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
    }
    close(fd);
    if (used == 0) {
        free(buf);
        return -1;
    }
    *resp = buf;
    *resp_len = used;
    return 0;
}

/* ---------------- 业务处理 ---------------- */
static void handle_boot(int cfd, const uint8_t *body, size_t len)
{
    if (len != EDGE_BOOT_LEN) {
        send_simple(cfd, 400, "text/plain", "bad boot len\n", 14, NULL);
        return;
    }
    const uint8_t *nonce = body;
    const uint8_t *cpk = body + 32;
    const uint8_t *ct_auth = cpk + NS2S_XWING_PK_BYTES;

    uint8_t ss_auth[NS2S_XWING_SS_BYTES];
    if (ns2s_xwing_dec(ss_auth, ct_auth, g_id_sk) != NS2S_OK) {
        send_simple(cfd, 400, "text/plain", "decaps failed\n", 14, NULL);
        return;
    }

    uint8_t spk_e[NS2S_XWING_PK_BYTES];
    uint8_t sk_e[NS2S_XWING_SK_BYTES];
    uint8_t ct_fs[NS2S_XWING_CT_BYTES];
    uint8_t ss_fs[NS2S_XWING_SS_BYTES];
    if (ns2s_xwing_keypair(spk_e, sk_e) != NS2S_OK ||
        ns2s_xwing_enc(ct_fs, ss_fs, cpk) != NS2S_OK) {
        send_simple(cfd, 500, "text/plain", "kem failed\n", 11, NULL);
        return;
    }

    uint8_t root[NS2S_ROOT_BYTES], c2s[NS2S_KEY_BYTES], s2c[NS2S_KEY_BYTES];
    if (derive_keys(nonce, cpk, spk_e, ct_auth, ct_fs, ss_auth, ss_fs, root, c2s,
                    s2c) != 0) {
        send_simple(cfd, 500, "text/plain", "kdf failed\n", 11, NULL);
        return;
    }

    edge_session *s = sess_new();
    if (s == NULL) {
        send_simple(cfd, 503, "text/plain", "no session\n", 12, NULL);
        return;
    }
    if (ns2s_session_init(&s->sess, NS2S_ROLE_SERVER, NS2S_ALG_CHACHA20POLY1305,
                          EDGE_MAX_FRAME, root, c2s, s2c, now_ms()) != NS2S_OK) {
        memset(s, 0, sizeof *s);
        send_simple(cfd, 500, "text/plain", "session init\n", 13, NULL);
        return;
    }
    sodium_memzero(sk_e, sizeof sk_e);
    sodium_memzero(ss_auth, sizeof ss_auth);
    sodium_memzero(ss_fs, sizeof ss_fs);
    sodium_memzero(root, sizeof root);
    sodium_memzero(c2s, sizeof c2s);
    sodium_memzero(s2c, sizeof s2c);

    uint8_t out[16 + EDGE_FIN_LEN];
    memcpy(out, s->sid, 16);
    memcpy(out + 16, spk_e, NS2S_XWING_PK_BYTES);
    memcpy(out + 16 + NS2S_XWING_PK_BYTES, ct_fs, NS2S_XWING_CT_BYTES);
    send_simple(cfd, 200, "application/octet-stream", out, sizeof out, NULL);
}

static void handle_app(int cfd, const char *sid_hex, const uint8_t *body, size_t len)
{
    edge_session *s = sess_find(sid_hex);
    if (s == NULL) {
        send_simple(cfd, 404, "text/plain", "no session\n", 12, NULL);
        return;
    }
    uint8_t *plain = (uint8_t *)malloc(EDGE_MAX_FRAME + 64);
    if (plain == NULL) {
        send_simple(cfd, 500, "text/plain", "oom\n", 4, NULL);
        return;
    }
    size_t got = 0;
    if (ns2s_session_open(&s->sess, body, len, plain, EDGE_MAX_FRAME + 64, &got) !=
        NS2S_OK) {
        free(plain);
        send_simple(cfd, 400, "text/plain", "decrypt failed\n", 15, NULL);
        return;
    }

    /* 把浏览器请求改写成发往上游的请求（Host 固定、加 Connection: close） */
    size_t req_cap = got + 256;
    char *req = (char *)malloc(req_cap);
    if (req == NULL) {
        free(plain);
        send_simple(cfd, 500, "text/plain", "oom\n", 4, NULL);
        return;
    }
    size_t head_len = 0;
    for (size_t i = 0; i + 3 < got; i++) {
        if (plain[i] == '\r' && plain[i + 1] == '\n' && plain[i + 2] == '\r' &&
            plain[i + 3] == '\n') {
            head_len = i + 4;
            break;
        }
    }
    if (head_len == 0) {
        free(req);
        free(plain);
        send_simple(cfd, 400, "text/plain", "bad inner request\n", 19, NULL);
        return;
    }
    /* 请求行 + 强制 Host + Connection: close + 其余头 + 体 */
    size_t eol = 0;
    while (eol + 1 < head_len && !(plain[eol] == '\r' && plain[eol + 1] == '\n')) {
        eol++;
    }
    int n = snprintf(req, req_cap, "%.*s\r\nHost: %s\r\nConnection: close\r\n",
                     (int)eol, (const char *)plain, g_site_host);
    if (n <= 0) {
        free(req);
        free(plain);
        send_simple(cfd, 500, "text/plain", "oom\n", 4, NULL);
        return;
    }
    size_t off = (size_t)n;
    size_t i = eol + 2;
    while (i + 1 < head_len) {
        size_t e = i;
        while (e + 1 < head_len && !(plain[e] == '\r' && plain[e + 1] == '\n')) {
            e++;
        }
        size_t hl = e - i;
        if (hl == 0) {
            break;
        }
        bool skip = false;
        if ((hl >= 5 && strncasecmp((char *)plain + i, "host:", 5) == 0) ||
            (hl >= 11 && strncasecmp((char *)plain + i, "connection:", 11) == 0) ||
            (hl >= 15 && strncasecmp((char *)plain + i, "content-length:", 15) == 0)) {
            skip = true;
        }
        if (!skip && off + hl + 2 < req_cap) {
            memcpy(req + off, plain + i, hl);
            off += hl;
            req[off++] = '\r';
            req[off++] = '\n';
        }
        i = e + 2;
    }
    if (got > head_len && off + 2 + (got - head_len) < req_cap) {
        memcpy(req + off, "\r\n", 2);
        off += 2;
        memcpy(req + off, plain + head_len, got - head_len);
        off += got - head_len;
    } else {
        memcpy(req + off, "\r\n", 2);
        off += 2;
    }

    uint8_t *up = NULL;
    size_t up_len = 0;
    int rc = forward_upstream(req, off, &up, &up_len);
    free(req);
    free(plain);
    if (rc != 0) {
        send_simple(cfd, 502, "text/plain", "upstream failed\n", 16, NULL);
        return;
    }

    size_t seal_cap = up_len + EDGE_FRAME_OVH + 64;
    uint8_t *sealed = (uint8_t *)malloc(seal_cap);
    if (sealed == NULL) {
        free(up);
        send_simple(cfd, 500, "text/plain", "oom\n", 4, NULL);
        return;
    }
    size_t sealed_len = 0;
    if (ns2s_session_seal(&s->sess, up, up_len, sealed, seal_cap, &sealed_len,
                          now_ms()) != NS2S_OK) {
        free(sealed);
        free(up);
        send_simple(cfd, 500, "text/plain", "seal failed\n", 12, NULL);
        return;
    }
    free(up);
    send_simple(cfd, 200, "application/octet-stream", sealed, sealed_len, NULL);
    free(sealed);
}

static void handle_conn(int cfd, const char *sdk_dir, const char *page)
{
    uint8_t *buf = (uint8_t *)malloc(EDGE_MAX_BODY);
    if (buf == NULL) {
        close(cfd);
        return;
    }
    char sid_hex[64];
    char path[1024];
    char method[16];
    size_t len = 0;
    int head = read_request(cfd, buf, EDGE_MAX_BODY, &len, sid_hex, sizeof sid_hex,
                            path, sizeof path, method, sizeof method);
    if (head <= 0) {
        free(buf);
        close(cfd);
        return;
    }
    const uint8_t *body = buf + head;
    size_t body_len = len - (size_t)head;

    if (strcmp(method, "POST") == 0 && strcmp(path, "/__neura/boot") == 0) {
        handle_boot(cfd, body, body_len);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/__neura/app") == 0) {
        handle_app(cfd, sid_hex, body, body_len);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/neura-pk") == 0) {
        send_simple(cfd, 200, "application/octet-stream", g_id_pk, sizeof g_id_pk,
                    NULL);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/neura-fp") == 0) {
        char fp_hex[NS2S_SHA512_BYTES * 2 + 2];
        hexify(g_id_fp, sizeof g_id_fp, fp_hex);
        fp_hex[sizeof g_id_fp * 2] = '\n';
        send_simple(cfd, 200, "text/plain; charset=utf-8", fp_hex,
                    sizeof g_id_fp * 2 + 1, NULL);
    } else if (strcmp(method, "GET") == 0 &&
               (strcmp(path, "/neura-crypto.wasm") == 0 ||
                strcmp(path, "/neura.js") == 0)) {
        char fp[512];
        snprintf(fp, sizeof fp, "%s/%s", sdk_dir,
                 strcmp(path, "/neura.js") == 0 ? "neura.js" : "neura-crypto.wasm");
        uint8_t *data = NULL;
        size_t dlen = 0;
        if (read_file(fp, &data, &dlen) != 0) {
            send_simple(cfd, 404, "text/plain", "not found\n", 10, NULL);
        } else {
            send_simple(cfd, 200,
                        strcmp(path, "/neura.js") == 0
                            ? "application/javascript; charset=utf-8"
                            : "application/wasm",
                        data, dlen, NULL);
            free(data);
        }
    } else if (strcmp(method, "GET") == 0 &&
               (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0)) {
        uint8_t *data = NULL;
        size_t dlen = 0;
        if (read_file(page, &data, &dlen) != 0) {
            send_simple(cfd, 404, "text/plain", "no shell page\n", 14, NULL);
        } else {
            /* 注入指纹 pin 与站点名（占位符替换，长度可控） */
            char fp_hex[NS2S_SHA512_BYTES * 2 + 1];
            hexify(g_id_fp, sizeof g_id_fp, fp_hex);
            char *src = (char *)data;
            size_t src_len = dlen;
            size_t cap = src_len + 4096;
            char *out = (char *)malloc(cap);
            if (out == NULL) {
                free(data);
                send_simple(cfd, 500, "text/plain", "oom\n", 4, NULL);
            } else {
                size_t o = 0;
                for (size_t i = 0; i < src_len; i++) {
                    if (o + 512 >= cap) {
                        break;
                    }
                    if (src[i] == '_' &&
                        i + 12 <= src_len &&
                        memcmp(src + i, "__NEURA_PIN__", 13) == 0) {
                        size_t l = strlen(fp_hex);
                        memcpy(out + o, fp_hex, l);
                        o += l;
                        i += 12;
                    } else if (src[i] == '_' && i + 13 <= src_len &&
                               memcmp(src + i, "__NEURA_SITE__", 14) == 0) {
                        size_t l = strlen(g_site_host);
                        memcpy(out + o, g_site_host, l);
                        o += l;
                        i += 13;
                    } else {
                        out[o++] = src[i];
                    }
                }
                send_simple(cfd, 200, "text/html; charset=utf-8", out, o, NULL);
                free(out);
                free(data);
            }
        }
    } else {
        send_simple(cfd, 404, "text/plain", "not found\n", 10, NULL);
    }
    free(buf);
    close(cfd);
}

int main(int argc, char **argv)
{
    const char *listen_addr = "0.0.0.0:80";
    const char *upstream = "127.0.0.1:19080";
    const char *sdk_dir = "build/sdk";
    const char *page = "sdk/index.html";
    const char *id_path = "/etc/safe-http/id.xwing";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            printf("用法: %s --listen 0.0.0.0:80 --upstream 127.0.0.1:19080 "
                   "--host test.jqlhtm.cn --sdk-dir build/sdk --page sdk/index.html "
                   "--id /etc/safe-http/id.xwing\n", argv[0]);
            return 0;
        } else if (v == NULL) {
            fprintf(stderr, "选项 %s 缺少参数\n", a);
            return 2;
        } else if (strcmp(a, "--listen") == 0) {
            listen_addr = v;
            i++;
        } else if (strcmp(a, "--upstream") == 0) {
            upstream = v;
            i++;
        } else if (strcmp(a, "--host") == 0) {
            g_site_host = v;
            i++;
        } else if (strcmp(a, "--sdk-dir") == 0) {
            sdk_dir = v;
            i++;
        } else if (strcmp(a, "--page") == 0) {
            page = v;
            i++;
        } else if (strcmp(a, "--id") == 0) {
            id_path = v;
            i++;
        } else {
            fprintf(stderr, "未知选项 %s\n", a);
            return 2;
        }
    }

    char lhost[128];
    snprintf(lhost, sizeof lhost, "%s", listen_addr);
    char *lc = strrchr(lhost, ':');
    if (lc == NULL) {
        fprintf(stderr, "--listen 需要 host:port\n");
        return 2;
    }
    *lc = '\0';
    unsigned lport = (unsigned)atoi(lc + 1);

    char uh[128];
    snprintf(uh, sizeof uh, "%s", upstream);
    char *uc = strrchr(uh, ':');
    if (uc == NULL) {
        fprintf(stderr, "--upstream 需要 host:port\n");
        return 2;
    }
    *uc = '\0';
    g_up_host = strdup(uh);
    g_up_port = (uint16_t)atoi(uc + 1);

    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0 || ns2s_crypto_init() != NS2S_OK) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }
    if (identity_load(id_path) != 0) {
        fprintf(stderr, "身份加载失败\n");
        return 1;
    }

    char fp_hex[NS2S_SHA512_BYTES * 2 + 1];
    hexify(g_id_fp, sizeof g_id_fp, fp_hex);
    printf("[edge] 站点 Host=%s 上游=%s:%u\n", g_site_host, g_up_host,
           (unsigned)g_up_port);
    printf("[edge] 服务端静态公钥指纹(SHA512)=%s\n", fp_hex);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)lport);
    if (inet_pton(AF_INET, lhost, &sa.sin_addr) != 1) {
        fprintf(stderr, "监听地址非法 %s\n", lhost);
        return 2;
    }
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(lfd, 256) != 0) {
        perror("listen");
        return 1;
    }
    printf("[edge] listening on %s:%u\n", lhost, lport);
    fflush(stdout);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            continue;
        }
        int nd = 1;
        (void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof nd);
        struct timeval tv = {10, 0};
        (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        handle_conn(cfd, sdk_dir, page);
    }
}
