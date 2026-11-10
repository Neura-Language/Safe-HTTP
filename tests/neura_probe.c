// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Neura-S2S 客户端探针（真实加密通道联调 / 压测 / 断言验证工具）
 *
 * 能力：
 *   1. 单发模式：握手一次 → 发一个请求 → 打印解密后的响应（含 status=NNN）；
 *   2. 长连接压测：--loop N 只握手一次，之后在同一 Neura-S2S 通道上
 *      串行复用 N 个请求（keep-alive），输出
 *        · 握手耗时（TCP connect / 握手各自计时）
 *        · 每请求延迟 P50 / P90 / P99 / max
 *        · 稳态 QPS（不含握手）
 *        · 客户端 + 服务端 CPU 占用
 *   3. 明文模式：--plain 用纯 C 阻塞 socket 发一个明文请求，只报状态码；
 *   4. 断言模式：--expect-status N / --assert-neura，校验状态码与响应
 *      JSON 里的 neura 字段是否为 "1"（手写极简扫描，不用任何外部解析器）；
 *   5. 矩阵模式：--suite 内部 fork 子进程跑「明文 403 / 加密 200」全矩阵断言，
 *      纯 C 实现，已完全取代原 scripts/verify-crypto.sh（该脚本已废弃删除）。
 *   6. 等待完成用 pthread_cond_timedwait 阻塞等待，**绝无忙等/轮询**。
 *
 * 用法：
 *   neura-probe --host 127.0.0.1 --port 80 --root-key /etc/safe-http/rootkey.hex \
 *               --path /echo --host-header test.jqlhtm.cn [--loop 10000] \
 *               [--warmup 50] [--out FILE] [--timeout-ms 30000] [--server-pid PID]
 *   neura-probe --host H --port P --path /api/x --plain --expect-status 403
 *   neura-probe --host H --port P --root-key K --host-header test.jqlhtm.cn --suite
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "network.h"
#include "security.h"

#define PROBE_MAX_REQ 65536
#define PROBE_MAX_HEAD (16u * 1024u)
#define PROBE_BODY_MAX (256u * 1024u)

static sh_reactor g_r;

/* ---- 完成同步（条件变量，阻塞等待，不轮询） ---- */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;
static int             g_finished;

static volatile int g_connected;
static volatile int g_hs_ok;
static volatile int g_failed;
static char         g_err[192];

/* ---- 请求/响应状态 ---- */
static uint32_t g_loop;              /* 总请求数 */
static uint32_t g_warmup;            /* 预热请求数（不计入统计） */
static uint32_t g_served;            /* 已完成请求数 */
static uint32_t g_sent;              /* 已发送请求数 */
static uint64_t *g_lat_us;           /* 每请求延迟（微秒），容量 g_loop+g_warmup */
static size_t    g_lat_n;
static uint64_t  g_t_first_send;
static uint64_t  g_t_last_done;

static sh_buf g_cur;                 /* 当前响应累积 */
static sh_buf g_last;                /* 最后一个完整响应（重置前快照，供 --out/断言用） */
static int    g_last_status;         /* 最后一个响应的 HTTP 状态码（0=未知） */
static bool   g_head_done;
static size_t g_head_len;
static size_t g_body_len;
static bool   g_close_delimited;     /* 无 Content-Length：只能靠 EOF 判完 */

static char   g_path[512];
static char   g_host_header[320];

static uint64_t g_t_start;           /* 进程起点 */
static uint64_t g_t_connected;
static uint64_t g_t_handshake;

static struct rusage g_ru_start;
static long           g_srv_ticks_start = -1;
static long           g_srv_ticks_end = -1;

/* 一次性初始化标记（同一进程内可重复调用 neura_perform） */
static bool g_bufs_ready;
static bool g_crypto_ready;

/* ==========================================================================
 * 工具
 * ========================================================================== */
static uint64_t now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

static long proc_cpu_ticks(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    /* stat: pid (comm) state ppid ... utime(14) stime(15) */
    char *p = strrchr(buf, ')');
    if (p == NULL) {
        return -1;
    }
    p++;
    long utime = 0, stime = 0;
    /* 跳过 state..到第 14/15 字段 */
    int field = 3;
    char *save = NULL;
    for (char *t = strtok_r(p, " ", &save); t != NULL;
         t = strtok_r(NULL, " ", &save)) {
        if (field == 14) {
            utime = atol(t);
        } else if (field == 15) {
            stime = atol(t);
            break;
        }
        field++;
    }
    if (utime == 0 && stime == 0) {
        return -1;
    }
    return utime + stime;
}

static void probe_fail(const char *why)
{
    if (g_err[0] == '\0') {
        snprintf(g_err, sizeof g_err, "%s", why != NULL ? why : "unknown");
    }
    g_failed = 1;
    pthread_mutex_lock(&g_mu);
    g_finished = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static void probe_finish(void)
{
    g_t_last_done = now_us();
    pthread_mutex_lock(&g_mu);
    g_finished = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static uint64_t pct(const uint64_t *v, size_t n, unsigned p)
{
    if (n == 0) {
        return 0;
    }
    size_t idx = (size_t)((double)p * (double)(n - 1) / 100.0 + 0.5);
    if (idx >= n) {
        idx = n - 1;
    }
    return v[idx];
}

/* ==========================================================================
 * 请求发送 / 响应分帧
 * ========================================================================== */
static uint64_t g_last_send_us;      /* 最近一次请求发出的时刻 */

static int probe_send_request(sh_reactor *r, sh_conn *c)
{
    char req[512];
    int n = snprintf(req, sizeof req,
                     "GET %s?i=%u HTTP/1.1\r\nHost: %s\r\n"
                     "User-Agent: neura-probe/loop\r\nAccept: */*\r\n"
                     "Connection: keep-alive\r\n\r\n",
                     g_path, (unsigned)g_sent, g_host_header);
    if (n <= 0 || (size_t)n >= sizeof req) {
        probe_fail("request too long");
        return -1;
    }
    if (sh_crypto_write(r, c, (const uint8_t *)req, (size_t)n) != NS2S_OK) {
        probe_fail("encrypt request");
        return -1;
    }
    g_sent++;
    g_last_send_us = now_us();
    if (g_t_first_send == 0) {
        g_t_first_send = g_last_send_us;
    }
    if (sh_buf_readable(&c->out) > 0) {
        if (sh_conn_flush(r, c, c->fd, &c->out) < 0) {
            probe_fail("flush request");
            return -1;
        }
        (void)sh_conn_want(r, c, true, false);
    }
    return 0;
}

/* 从响应头里找 Content-Length（大小写无关） */
static long header_content_length(const char *buf, size_t head_len)
{
    const char *name = "content-length:";
    size_t nl = strlen(name);
    for (size_t i = 0; i + nl < head_len; i++) {
        if (i > 0 && buf[i - 1] != '\n') {
            continue;
        }
        size_t k = 0;
        while (k < nl && i + k < head_len &&
               (char)((buf[i + k] >= 'A' && buf[i + k] <= 'Z')
                          ? buf[i + k] + 32
                          : buf[i + k]) == name[k]) {
            k++;
        }
        if (k != nl) {
            continue;
        }
        size_t j = i + nl;
        while (j < head_len && (buf[j] == ' ' || buf[j] == '\t')) {
            j++;
        }
        long v = 0;
        bool any = false;
        while (j < head_len && buf[j] >= '0' && buf[j] <= '9') {
            v = v * 10 + (buf[j] - '0');
            any = true;
            j++;
        }
        if (any) {
            return v;
        }
    }
    return -1;
}

/* 响应是否完整；返回 1 完成，0 继续等 */
static int response_complete(void)
{
    size_t len = 0;
    const char *buf = (const char *)sh_buf_peek(&g_cur, &len);
    if (!g_head_done) {
        if (len < 5) {
            return 0;
        }
        for (size_t i = 0; i + 3 < len; i++) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
                buf[i + 3] == '\n') {
                g_head_len = i + 4;
                long cl = header_content_length(buf, g_head_len);
                if (cl < 0) {
                    g_close_delimited = true;
                    g_body_len = 0;
                } else {
                    g_body_len = (size_t)cl;
                }
                g_head_done = true;
                break;
            }
        }
        if (!g_head_done) {
            if (len > PROBE_MAX_HEAD) {
                probe_fail("response head too large");
                return -1;
            }
            return 0;
        }
    }
    if (g_close_delimited) {
        return 0;    /* 由 EOF 判定（不适用于 --loop） */
    }
    return len >= g_head_len + g_body_len ? 1 : 0;
}

/* 解密后累积 + 判断一个响应是否结束 */
static int probe_drain_plain(sh_reactor *r, sh_conn *c, bool *completed)
{
    sh_buf plain;
    if (sh_buf_init(&plain, 8192) != 0) {
        return -1;
    }
    ssize_t n = sh_crypto_read(r, c, &plain);
    int rc = 0;
    if (n < 0) {
        rc = -1;
    } else if (n > 0) {
        size_t len = 0;
        const uint8_t *p = sh_buf_peek(&plain, &len);
        if (len > 0 && sh_buf_append(&g_cur, p, len) != len) {
            rc = -1;
        }
    }
    sh_buf_free(&plain);
    if (rc != 0) {
        return rc;
    }
    int done = response_complete();
    if (done < 0) {
        return -1;
    }
    *completed = (done == 1);
    return 0;
}

/* 一个响应收完：记录延迟/状态码/快照 → 决定继续还是结束 */
static int probe_on_response_done(sh_reactor *r, sh_conn *c)
{
    uint64_t t = now_us();
    if (g_lat_n < (size_t)g_loop + g_warmup + 8u) {
        g_lat_us[g_lat_n++] = t - g_last_send_us;
    }
    g_served++;

    /* 快照最后一个完整响应：下面会 reset g_cur，否则单发模式永远
     * 打印 decrypted=0、--out 也永远写不出文件、断言也没数据可用 */
    sh_buf_reset(&g_last);
    size_t snap_len = 0;
    const uint8_t *snap = sh_buf_peek(&g_cur, &snap_len);
    if (snap_len > 0 && sh_buf_reserve(&g_last, snap_len) == 0) {
        (void)sh_buf_append(&g_last, snap, snap_len);
    }
    if (snap_len > 12 && memcmp(snap, "HTTP/", 5) == 0) {
        const uint8_t *sp = memchr(snap, ' ', snap_len);
        if (sp != NULL) {
            g_last_status = atoi((const char *)sp + 1);
        }
    }

    sh_buf_reset(&g_cur);
    g_head_done = false;
    g_head_len = 0;
    g_body_len = 0;
    g_close_delimited = false;

    uint32_t total = g_loop + g_warmup;
    if (g_served >= total) {
        probe_finish();
        return 0;
    }
    /* 预热请求的延迟不计入统计（保留最后 g_loop 个样本） */
    if (g_warmup > 0 && g_served >= g_warmup && g_lat_n > g_loop) {
        memmove(g_lat_us, g_lat_us + (g_lat_n - g_loop), g_loop * sizeof(uint64_t));
        g_lat_n = g_loop;
    }
    return probe_send_request(r, c);
}

/* ==========================================================================
 * 极简 JSON 断言（纯手写扫描，无 jq / 无 Python / 无正则库）
 * ========================================================================== */

/* 从完整 HTTP 响应里切出正文（跳过头部） */
static const char *resp_body_of(const char *resp, size_t n, size_t *blen)
{
    if (blen != NULL) {
        *blen = 0;
    }
    if (resp == NULL || n < 4) {
        return NULL;
    }
    const char *p = memmem(resp, n, "\r\n\r\n", 4);
    if (p == NULL) {
        return NULL;
    }
    p += 4;
    size_t off = (size_t)(p - resp);
    if (off > n) {
        return NULL;
    }
    if (blen != NULL) {
        *blen = n - off;
    }
    return p;
}

static bool is_json_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*
 * 判断 JSON 文本 s[0..n) 中是否存在字段 key，且其值为 "1" 或数字 1。
 * 只做最小语法扫描：定位 "key" → 冒号 → 值，不建语法树、不依赖外部工具。
 */
static bool json_field_is_one(const char *s, size_t n, const char *key)
{
    if (s == NULL || key == NULL || *key == '\0' || n < 4) {
        return false;
    }
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 2 <= n; i++) {
        if (s[i] != '"') {
            continue;
        }
        if (memcmp(s + i + 1, key, klen) != 0) {
            continue;
        }
        if (s[i + 1 + klen] != '"') {
            continue;
        }
        size_t j = i + klen + 2;
        while (j < n && is_json_ws(s[j])) {
            j++;
        }
        if (j >= n || s[j] != ':') {
            continue;    /* 不是字段名（可能是值或别的键的一部分） */
        }
        j++;
        while (j < n && is_json_ws(s[j])) {
            j++;
        }
        if (j >= n) {
            return false;
        }
        if (s[j] == '"') {                       /* 字符串值 "1" */
            if (j + 2 < n && s[j + 1] == '1' && s[j + 2] == '"') {
                return true;
            }
            continue;
        }
        if (s[j] == '1') {                       /* 数字值 1 */
            size_t k = j + 1;
            while (k < n && is_json_ws(s[k])) {
                k++;
            }
            if (k >= n || s[k] == ',' || s[k] == '}' || s[k] == ']') {
                return true;
            }
        }
    }
    return false;
}

/* ==========================================================================
 * 纯 C 明文 HTTP 客户端（只用于断言明文是否被拒，不解析 JSON 以外的东西）
 * ========================================================================== */
static int plain_http_get(const char *host, uint16_t port, const char *hosthdr,
                          const char *path, int timeout_ms, int *status,
                          char *body, size_t bodycap, size_t *bodylen)
{
    if (status != NULL) {
        *status = 0;
    }
    if (bodylen != NULL) {
        *bodylen = 0;
    }
    if (body != NULL && bodycap > 0) {
        body[0] = '\0';
    }

    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (long)(timeout_ms % 1000) * 1000L;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    char req[1024];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\nHost: %s\r\n"
                     "User-Agent: neura-probe/plain\r\nAccept: */*\r\n"
                     "Connection: close\r\n\r\n",
                     path, hosthdr);
    if (n <= 0 || (size_t)n >= sizeof req) {
        close(fd);
        return -1;
    }
    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t w = write(fd, req + off, (size_t)n - off);
        if (w <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }

    sh_buf raw;
    if (sh_buf_init(&raw, 4096) != 0) {
        close(fd);
        return -1;
    }
    char tmp[8192];
    size_t head_len = 0;
    long cl = -1;
    for (;;) {
        if (sh_buf_readable(&raw) > PROBE_BODY_MAX) {
            break;
        }
        if (sh_buf_reserve(&raw, 8192) != 0) {
            break;
        }
        ssize_t r = read(fd, tmp, sizeof tmp);
        if (r <= 0) {
            break;                       /* EOF 或超时：有多少算多少 */
        }
        if (sh_buf_append(&raw, tmp, (size_t)r) != (size_t)r) {
            break;
        }
        size_t len = 0;
        const char *b = (const char *)sh_buf_peek(&raw, &len);
        if (head_len == 0) {
            for (size_t i = 0; i + 3 < len; i++) {
                if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' &&
                    b[i + 3] == '\n') {
                    head_len = i + 4;
                    break;
                }
            }
            if (head_len > 0) {
                cl = header_content_length(b, head_len);
            }
        }
        if (head_len > 0) {
            if (cl < 0) {
                break;                   /* close-delimited：头部到手即可判定 */
            }
            if (len >= head_len + (size_t)cl) {
                break;                   /* 正文收全 */
            }
        }
    }
    close(fd);

    size_t len = 0;
    const char *b = (const char *)sh_buf_peek(&raw, &len);
    if (len < 12 || memcmp(b, "HTTP/", 5) != 0) {
        sh_buf_free(&raw);
        return -1;
    }
    const char *sp = memchr(b, ' ', len);
    if (sp != NULL && status != NULL) {
        *status = atoi(sp + 1);
    }
    if (body != NULL && bodycap > 1 && head_len > 0 && len > head_len) {
        size_t bl = len - head_len;
        if (bl > bodycap - 1) {
            bl = bodycap - 1;
        }
        memcpy(body, b + head_len, bl);
        body[bl] = '\0';
        if (bodylen != NULL) {
            *bodylen = bl;
        }
    }
    sh_buf_free(&raw);
    return 0;
}

/* ==========================================================================
 * 纯 C 明文 keep-alive 基准（A/B 用：隔离「上游/代理」与「加密」的延迟来源）
 * ========================================================================== */
static int plain_bench(const char *host, uint16_t port, const char *hosthdr,
                       const char *path, uint32_t loop, uint32_t warmup,
                       int timeout_ms)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "[probe] FAIL: 解析 %s 失败\n", host);
        return 1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return 1;
    }
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (long)(timeout_ms % 1000) * 1000L;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        fprintf(stderr, "[probe] FAIL: 连接 %s:%u 失败\n", host, (unsigned)port);
        return 1;
    }
    freeaddrinfo(res);

    uint32_t total = loop + warmup;
    uint64_t *lat = (uint64_t *)calloc((size_t)total + 8u, sizeof(uint64_t));
    if (lat == NULL) {
        close(fd);
        return 1;
    }

    sh_buf raw;
    if (sh_buf_init(&raw, 8192) != 0) {
        free(lat);
        close(fd);
        return 1;
    }

    size_t lat_n = 0;
    int status = 0;
    int rc = 0;
    uint64_t t_first = 0;
    uint64_t t_last = 0;

    for (uint32_t i = 0; i < total; i++) {
        char req[512];
        int n = snprintf(req, sizeof req,
                         "GET %s?i=%u HTTP/1.1\r\nHost: %s\r\n"
                         "User-Agent: neura-probe/plain-loop\r\nAccept: */*\r\n"
                         "Connection: keep-alive\r\n\r\n",
                         path, (unsigned)i, hosthdr);
        uint64_t t0 = now_us();
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = write(fd, req + off, (size_t)n - off);
            if (w <= 0) {
                rc = 1;
                break;
            }
            off += (size_t)w;
        }
        if (rc != 0) {
            break;
        }
        /* 读一个完整响应（Content-Length 或 close-delimited） */
        sh_buf_reset(&raw);
        size_t head_len = 0;
        long cl = -1;
        for (;;) {
            if (sh_buf_readable(&raw) > PROBE_BODY_MAX) {
                break;
            }
            if (sh_buf_reserve(&raw, 8192) != 0) {
                rc = 1;
                break;
            }
            char tmp[8192];
            ssize_t r = read(fd, tmp, sizeof tmp);
            if (r <= 0) {
                rc = (r == 0) ? 2 : 1;     /* 2 = 对端提前关闭 */
                break;
            }
            if (sh_buf_append(&raw, tmp, (size_t)r) != (size_t)r) {
                rc = 1;
                break;
            }
            size_t len = 0;
            const char *b = (const char *)sh_buf_peek(&raw, &len);
            if (head_len == 0) {
                for (size_t k = 0; k + 3 < len; k++) {
                    if (b[k] == '\r' && b[k + 1] == '\n' && b[k + 2] == '\r' &&
                        b[k + 3] == '\n') {
                        head_len = k + 4;
                        break;
                    }
                }
                if (head_len > 0) {
                    cl = header_content_length(b, head_len);
                    if (len >= 12 && memcmp(b, "HTTP/", 5) == 0) {
                        const char *sp = memchr(b, ' ', len);
                        if (sp != NULL) {
                            status = atoi(sp + 1);
                        }
                    }
                }
            }
            if (head_len > 0) {
                if (cl < 0 || len >= head_len + (size_t)cl) {
                    break;
                }
            }
        }
        if (rc != 0) {
            break;
        }
        uint64_t t1 = now_us();
        if (i == warmup) {
            t_first = t0;
        }
        t_last = t1;
        if (i >= warmup && lat_n < (size_t)total + 8u) {
            lat[lat_n++] = t1 - t0;
        }
    }
    close(fd);
    sh_buf_free(&raw);

    if (rc != 0) {
        fprintf(stderr, "[probe] FAIL: 明文 keep-alive 第 %zu 次请求中断（rc=%d，"
                        "已完成 %zu/%u）\n", lat_n + 1u, rc, lat_n, loop);
        free(lat);
        return 1;
    }
    qsort(lat, lat_n, sizeof(uint64_t), cmp_u64);
    double secs = (double)(t_last - t_first) / 1000000.0;
    printf("[probe] plain loop=%u warmup=%u status=%d 稳态: %u 请求 / %.3f s = "
           "%.1f QPS\n", loop, warmup, status, loop, secs,
           secs > 0 ? (double)loop / secs : 0.0);
    printf("[probe] plain 延迟(us): min=%llu P50=%llu P90=%llu P99=%llu "
           "max=%llu\n",
           (unsigned long long)lat[0],
           (unsigned long long)pct(lat, lat_n, 50),
           (unsigned long long)pct(lat, lat_n, 90),
           (unsigned long long)pct(lat, lat_n, 99),
           (unsigned long long)lat[lat_n - 1]);
    free(lat);
    return 0;
}

/* ==========================================================================
 * 钩子
 * ========================================================================== */
static int probe_on_write(sh_reactor *r, sh_conn *c)
{
    if (!g_connected) {
        if (sh_net_connect_result(c->fd) < 0) {
            probe_fail("connect");
            return -1;
        }
        g_connected = 1;
        g_t_connected = now_us();
        sh_net_set_nodelay(c->fd, true);
        if (sh_crypto_start(r, c, NS2S_ROLE_CLIENT) != NS2S_OK) {
            probe_fail("crypto start");
            return -1;
        }
    }
    if (sh_buf_readable(&c->out) > 0 && sh_conn_flush(r, c, c->fd, &c->out) < 0) {
        probe_fail("flush");
        return -1;
    }
    (void)sh_conn_want(r, c, true, false);
    return 0;
}

static int probe_on_read(sh_reactor *r, sh_conn *c)
{
    for (;;) {
        if (sh_buf_reserve(&c->in, 16384) != 0) {
            probe_fail("reserve");
            return -1;
        }
        size_t space = sh_buf_writable(&c->in);
        if (space == 0) {
            break;
        }
        ssize_t n = read(c->fd, c->in.data + c->in.wpos, space);
        if (n > 0) {
            c->in.wpos += (size_t)n;
            r->stats.bytes_client_in += (uint64_t)n;
            continue;
        }
        if (n == 0) {
            /* 对端关闭：单发模式可接受（close-delimited），压测模式算失败 */
            if (c->crypto == SH_CRYPTO_READY) {
                bool completed = false;
                if (probe_drain_plain(r, c, &completed) != 0) {
                    probe_fail("decrypt tail");
                    return -1;
                }
                if (completed) {
                    (void)probe_on_response_done(r, c);
                    return 0;
                }
            }
            if (g_served < g_loop + g_warmup && g_loop > 1) {
                char why[128];
                snprintf(why, sizeof why,
                         "服务端提前关闭连接（keep-alive 未生效？已完成 %u/%u，"
                         "最后 status=%d）",
                         g_served, g_loop + g_warmup, g_last_status);
                probe_fail(why);
            } else {
                probe_finish();
            }
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        probe_fail("read");
        return -1;
    }

    if (c->crypto == SH_CRYPTO_HANDSHAKE) {
        if (sh_crypto_pump(r, c) != NS2S_OK) {
            probe_fail("handshake pump");
            return -1;
        }
        if (sh_buf_readable(&c->out) > 0) {
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
        if (c->crypto != SH_CRYPTO_READY) {
            return 0;
        }
        g_hs_ok = 1;
        g_t_handshake = now_us();
        if (g_loop > 1) {
            SH_LOGI("probe: 握手完成 connect=%.3fms handshake=%.3fms",
                    (double)(g_t_connected - g_t_start) / 1000.0,
                    (double)(g_t_handshake - g_t_connected) / 1000.0);
        }
    }

    if (c->crypto == SH_CRYPTO_READY) {
        if (g_sent == 0 && probe_send_request(r, c) != 0) {
            return -1;
        }
        bool completed = false;
        if (probe_drain_plain(r, c, &completed) != 0) {
            probe_fail("decrypt");
            return -1;
        }
        if (completed) {
            return probe_on_response_done(r, c);
        }
    }
    return 0;
}

static int probe_on_tick(sh_reactor *r, sh_conn *c)
{
    return sh_crypto_tick(r, c);
}

static void probe_on_close(sh_reactor *r, sh_conn *c)
{
    (void)r;
    (void)c;
}

static const sh_conn_hooks k_probe_hooks = {
    .name = "probe-client",
    .on_client_read = probe_on_read,
    .on_client_write = probe_on_write,
    .on_tick = probe_on_tick,
    .on_close = probe_on_close,
};

static void *reactor_thread(void *arg)
{
    sh_reactor_run((sh_reactor *)arg);
    return NULL;
}

/* ==========================================================================
 * 一次完整的 Neura-S2S 会话（握手 → loop 个请求 → 统计）
 * ========================================================================== */
typedef struct {
    const char *host;
    uint16_t    port;
    const char *root_key_path;
    const char *path;
    const char *host_header;
    int         timeout_ms;
    long        server_pid;
    uint32_t    loop;
    uint32_t    warmup;
    bool        quiet;
} neura_req;

static int neura_perform(const neura_req *o, int *status_out,
                         const char **resp_out, size_t *resp_len_out)
{
    if (status_out != NULL) {
        *status_out = 0;
    }
    if (resp_out != NULL) {
        *resp_out = NULL;
    }
    if (resp_len_out != NULL) {
        *resp_len_out = 0;
    }

    /* 复位运行期状态（同一进程内可重复调用） */
    g_finished = 0;
    g_connected = 0;
    g_hs_ok = 0;
    g_failed = 0;
    g_err[0] = '\0';
    g_served = 0;
    g_sent = 0;
    g_lat_n = 0;
    g_t_first_send = 0;
    g_t_last_done = 0;
    g_t_start = 0;
    g_t_connected = 0;
    g_t_handshake = 0;
    g_last_send_us = 0;
    g_last_status = 0;
    g_head_done = false;
    g_head_len = 0;
    g_body_len = 0;
    g_close_delimited = false;
    g_srv_ticks_start = -1;
    g_srv_ticks_end = -1;
    g_loop = o->loop ? o->loop : 1;
    g_warmup = o->warmup;

    signal(SIGPIPE, SIG_IGN);
    sh_log_init(stderr, o->quiet ? SH_LOG_ERROR : SH_LOG_WARN);

    if (!g_bufs_ready) {
        if (sh_buf_init(&g_cur, 16384) != 0 || sh_buf_init(&g_last, 16384) != 0) {
            fprintf(stderr, "OOM\n");
            return 1;
        }
        g_bufs_ready = true;
    }
    sh_buf_reset(&g_cur);
    sh_buf_reset(&g_last);

    free(g_lat_us);
    size_t cap = (size_t)g_loop + g_warmup + 8u;
    g_lat_us = calloc(cap, sizeof(uint64_t));
    if (g_lat_us == NULL) {
        fprintf(stderr, "OOM\n");
        return 1;
    }

    if (!g_crypto_ready) {
        if (sh_neura_global_init() != NS2S_OK) {
            fprintf(stderr, "crypto init failed\n");
            return 1;
        }
        g_crypto_ready = true;
    }
    uint8_t root_key[SH_ROOTKEY_BYTES];
    char err[192] = {0};
    if (sh_rootkey_load(o->root_key_path, root_key, err, sizeof err) != NS2S_OK) {
        fprintf(stderr, "RootKey 加载失败: %s\n", err);
        return 1;
    }

    snprintf(g_path, sizeof g_path, "%s", o->path);
    snprintf(g_host_header, sizeof g_host_header, "%s", o->host_header);

    sh_settings s;
    sh_settings_defaults(&s);
    s.max_frame = SH_DEFAULT_MAX_FRAME;
    s.kem_workers = 2;
    s.trust_anchor_required = false;

    if (sh_reactor_init(&g_r, &s, NULL, NULL) != 0) {
        fprintf(stderr, "reactor init failed\n");
        return 1;
    }
    memcpy(g_r.root_key, root_key, sizeof root_key);
    g_r.have_root_key = true;
    g_r.hooks = &k_probe_hooks;

    bool in_progress = false;
    int fd = sh_net_connect(o->host, o->port, &in_progress);
    if (fd < 0) {
        fprintf(stderr, "连接 %s:%u 失败: %s\n", o->host, (unsigned)o->port,
                strerror(errno));
        sh_reactor_destroy(&g_r);
        return 1;
    }
    sh_addr peer;
    memset(&peer, 0, sizeof peer);
    sh_conn *c = sh_conn_acquire(&g_r, fd, &peer);
    if (c == NULL) {
        fprintf(stderr, "acquire conn failed\n");
        sh_reactor_destroy(&g_r);
        return 1;
    }
    (void)sh_conn_want(&g_r, c, true, true);

    getrusage(RUSAGE_SELF, &g_ru_start);
    if (o->server_pid > 0) {
        g_srv_ticks_start = proc_cpu_ticks((pid_t)o->server_pid);
    }
    g_t_start = now_us();

    pthread_t th;
    if (pthread_create(&th, NULL, reactor_thread, &g_r) != 0) {
        fprintf(stderr, "thread create failed\n");
        sh_reactor_destroy(&g_r);
        return 1;
    }

    /* 阻塞等待：条件变量 + 绝对超时，绝不轮询 */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += o->timeout_ms / 1000;
    deadline.tv_nsec += (long)(o->timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&g_mu);
    while (!g_finished && !g_failed) {
        int wrc = pthread_cond_timedwait(&g_cv, &g_mu, &deadline);
        if (wrc == ETIMEDOUT) {
            break;
        }
    }
    int finished = g_finished;
    pthread_mutex_unlock(&g_mu);

    if (o->server_pid > 0) {
        g_srv_ticks_end = proc_cpu_ticks((pid_t)o->server_pid);
    }
    sh_reactor_stop(&g_r);
    pthread_join(th, NULL);
    sh_reactor_destroy(&g_r);

    double handshake_ms = 0.0;
    double connect_ms = 0.0;
    if (g_connected && g_hs_ok) {
        connect_ms = (double)(g_t_connected - g_t_start) / 1000.0;
        handshake_ms = (double)(g_t_handshake - g_t_connected) / 1000.0;
    }

    int rc = 0;
    if (g_failed) {
        fprintf(stderr, "[probe] FAIL: %s\n", g_err);
        rc = 1;
    } else if (!finished) {
        fprintf(stderr, "[probe] FAIL: 超时 %d ms（已完成 %u/%u）\n",
                o->timeout_ms, g_served, g_loop + g_warmup);
        rc = 3;
    } else if (!g_hs_ok) {
        fprintf(stderr, "[probe] FAIL: 握手未完成\n");
        rc = 1;
    }

    if (rc == 0 && !o->quiet) {
        if (g_loop <= 1) {
            printf("[probe] handshake=OK connect=%.3fms handshake=%.3fms "
                   "status=%d\n", connect_ms, handshake_ms, g_last_status);
        } else {
            uint64_t wall = g_t_last_done - g_t_first_send;
            double secs = (double)wall / 1000000.0;
            double qps = secs > 0 ? (double)g_loop / secs : 0.0;
            qsort(g_lat_us, g_lat_n, sizeof(uint64_t), cmp_u64);
            struct rusage ru_end;
            getrusage(RUSAGE_SELF, &ru_end);
            double cpu_user = (double)(ru_end.ru_utime.tv_sec -
                                       g_ru_start.ru_utime.tv_sec) * 1000.0 +
                              (double)(ru_end.ru_utime.tv_usec -
                                       g_ru_start.ru_utime.tv_usec) / 1000.0;
            double cpu_sys = (double)(ru_end.ru_stime.tv_sec -
                                      g_ru_start.ru_stime.tv_sec) * 1000.0 +
                             (double)(ru_end.ru_stime.tv_usec -
                                      g_ru_start.ru_stime.tv_usec) / 1000.0;
            printf("[probe] loop=%u warmup=%u status=%d 握手: connect=%.3fms "
                   "handshake=%.3fms\n", g_loop, g_warmup, g_last_status,
                   connect_ms, handshake_ms);
            printf("[probe] 稳态: %u 请求 / %.3f s = %.1f QPS\n", g_loop, secs,
                   qps);
            printf("[probe] 延迟(us): min=%llu P50=%llu P90=%llu P99=%llu "
                   "max=%llu\n",
                   (unsigned long long)g_lat_us[0],
                   (unsigned long long)pct(g_lat_us, g_lat_n, 50),
                   (unsigned long long)pct(g_lat_us, g_lat_n, 90),
                   (unsigned long long)pct(g_lat_us, g_lat_n, 99),
                   (unsigned long long)g_lat_us[g_lat_n - 1]);
            printf("[probe] CPU 客户端: user=%.0fms sys=%.0fms (%.1f%% of "
                   "wall)\n", cpu_user, cpu_sys,
                   100.0 * (cpu_user + cpu_sys) / (secs * 1000.0));
            if (g_srv_ticks_start >= 0 && g_srv_ticks_end >= 0) {
                double srv_ms = (double)(g_srv_ticks_end - g_srv_ticks_start) *
                                1000.0 / 100.0;   /* USER_HZ=100 */
                printf("[probe] CPU 服务端(pid %ld): %.0fms = %.1f%% of wall\n",
                       o->server_pid, srv_ms, 100.0 * srv_ms / (secs * 1000.0));
            }
            printf("[probe] 加密字节: in=%llu out≈%llu\n",
                   (unsigned long long)g_r.stats.bytes_client_in,
                   (unsigned long long)(g_r.stats.bytes_client_in));
        }
    }

    if (status_out != NULL) {
        *status_out = g_last_status;
    }
    if (resp_out != NULL) {
        size_t n = 0;
        *resp_out = (const char *)sh_buf_peek(&g_last, &n);
        if (resp_len_out != NULL) {
            *resp_len_out = n;
        }
    }

    free(g_lat_us);
    g_lat_us = NULL;
    return rc;
}

/* ==========================================================================
 * --suite：纯 C 断言矩阵（已取代 scripts/verify-crypto.sh）
 * ========================================================================== */
typedef struct {
    bool        plain;        /* true=明文直连，false=Neura-S2S 加密 */
    const char *path;
    int         expect;       /* 期望状态码 */
    bool        need_neura;   /* 是否要求响应 JSON 里 neura == "1" */
} suite_case;

static const suite_case k_suite[] = {
    { true,  "/",      200, false },
    { true,  "/echo",  200, false },
    { true,  "/api/x", 403, false },
    { false, "/",      200, false },
    { false, "/echo",  200, true  },
    { false, "/api/x", 200, false },
};

typedef struct {
    int status;
    int neura_ok;
    int err;
} case_result;

/* 子进程内跑一个用例，结果通过管道回传（纯二进制结构体，不做文本解析） */
static void child_run_case(const suite_case *cs, const neura_req *base, int wfd)
{
    case_result r;
    memset(&r, 0, sizeof r);

    if (cs->plain) {
        char body[8192];
        size_t blen = 0;
        if (plain_http_get(base->host, base->port, base->host_header, cs->path,
                           base->timeout_ms, &r.status, body, sizeof body,
                           &blen) != 0) {
            r.err = 1;
        } else if (cs->need_neura) {
            r.neura_ok = json_field_is_one(body, blen, "neura") ? 1 : 0;
        }
    } else {
        neura_req o = *base;
        o.path = cs->path;
        o.loop = 1;
        o.warmup = 0;
        o.quiet = true;
        int st = 0;
        const char *resp = NULL;
        size_t rlen = 0;
        if (neura_perform(&o, &st, &resp, &rlen) != 0) {
            r.err = 1;
        } else {
            r.status = st;
            if (cs->need_neura) {
                size_t blen = 0;
                const char *body = resp_body_of(resp, rlen, &blen);
                r.neura_ok = json_field_is_one(body, blen, "neura") ? 1 : 0;
            }
        }
    }

    size_t off = 0;
    while (off < sizeof r) {
        ssize_t w = write(wfd, (const char *)&r + off, sizeof r - off);
        if (w <= 0) {
            break;
        }
        off += (size_t)w;
    }
}

static int run_suite(const char *host, uint16_t port, const char *hosthdr,
                     const char *rootkey, int timeout_ms)
{
    neura_req base;
    memset(&base, 0, sizeof base);
    base.host = host;
    base.port = port;
    base.root_key_path = rootkey;
    base.host_header = hosthdr;
    base.timeout_ms = timeout_ms;

    size_t ncase = sizeof k_suite / sizeof k_suite[0];
    int fail = 0;

    printf("[suite] 目标 %s:%u Host=%s 用例=%zu\n", host, (unsigned)port,
           hosthdr, ncase);

    for (size_t i = 0; i < ncase; i++) {
        int pfd[2];
        if (pipe(pfd) != 0) {
            printf("[suite] %-5s %-8s ERROR pipe\n",
                   k_suite[i].plain ? "plain" : "neura", k_suite[i].path);
            fail++;
            continue;
        }
        pid_t pid = fork();
        if (pid < 0) {
            close(pfd[0]);
            close(pfd[1]);
            printf("[suite] %-5s %-8s ERROR fork\n",
                   k_suite[i].plain ? "plain" : "neura", k_suite[i].path);
            fail++;
            continue;
        }
        if (pid == 0) {
            close(pfd[0]);
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) {                 /* 静音子进程输出，父进程只认结构体 */
                (void)dup2(dn, STDOUT_FILENO);
                (void)dup2(dn, STDERR_FILENO);
                if (dn > STDERR_FILENO) {
                    close(dn);
                }
            }
            child_run_case(&k_suite[i], &base, pfd[1]);
            close(pfd[1]);
            _exit(0);
        }

        close(pfd[1]);
        case_result r;
        memset(&r, 0, sizeof r);
        size_t got = 0;
        while (got < sizeof r) {
            ssize_t n = read(pfd[0], (char *)&r + got, sizeof r - got);
            if (n <= 0) {
                break;
            }
            got += (size_t)n;
        }
        close(pfd[0]);
        int wst = 0;
        (void)waitpid(pid, &wst, 0);

        bool ok = (got == sizeof r) && (r.err == 0) &&
                  (r.status == k_suite[i].expect) &&
                  (!k_suite[i].need_neura || r.neura_ok == 1);
        if (!ok) {
            fail++;
        }
        char neura_note[16];
        if (k_suite[i].need_neura) {
            snprintf(neura_note, sizeof neura_note, "%s",
                     (got == sizeof r && r.neura_ok) ? "1" : "0");
        } else {
            snprintf(neura_note, sizeof neura_note, "%s", "-");
        }
        printf("[suite] %-5s %-8s status=%-4d expect=%-4d neura=%-2s %s\n",
               k_suite[i].plain ? "plain" : "neura", k_suite[i].path,
               (got == sizeof r) ? r.status : -1, k_suite[i].expect,
               neura_note, ok ? "PASS" : "FAIL");
    }

    printf("[suite] %s  PASS=%d FAIL=%d\n", fail == 0 ? "PASS" : "FAIL",
           (int)ncase - fail, fail);
    return fail == 0 ? 0 : 1;
}

/* ==========================================================================
 * CLI
 * ========================================================================== */
static void usage(const char *argv0)
{
    fprintf(stderr,
            "用法: %s --host H --port P --root-key FILE [选项]\n\n"
            "  --path PATH            请求路径（默认 /echo）\n"
            "  --host-header VALUE    Host 头（默认 H:P）\n"
            "  --loop N               同一加密通道上复用 N 个请求（默认 1）\n"
            "  --warmup N             预热请求数（不计入统计，默认 0）\n"
            "  --out FILE             把（最后一个）解密后响应写入文件\n"
            "  --timeout-ms N         总超时（默认 30000）\n"
            "  --server-pid PID       额外统计该进程 CPU\n"
            "  --print-body           只打印响应正文\n"
            "  --quiet                只输出结论行\n"
            "  --plain                明文直连模式（纯 C socket，不加密）\n"
            "  --expect-status N      断言 HTTP 状态码等于 N\n"
            "  --assert-neura         断言响应 JSON 中 neura 字段为 1\n"
            "  --suite                跑明文/加密断言矩阵（替代 verify-crypto.sh）\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1";
    const char *root_key_path = NULL;
    const char *path = "/echo";
    const char *host_header = NULL;
    const char *out_file = NULL;
    uint16_t port = 0;
    int timeout_ms = 30000;
    long server_pid = 0;
    int expect_status = 0;
    bool print_body = false;
    bool quiet = false;
    bool plain_mode = false;
    bool suite_mode = false;
    bool assert_neura = false;
    uint32_t loop = 1;
    uint32_t warmup = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(a, "--quiet") == 0) {
            quiet = true;
        } else if (strcmp(a, "--print-body") == 0) {
            print_body = true;
        } else if (strcmp(a, "--plain") == 0) {
            plain_mode = true;
        } else if (strcmp(a, "--suite") == 0) {
            suite_mode = true;
        } else if (strcmp(a, "--assert-neura") == 0) {
            assert_neura = true;
        } else if (v == NULL) {
            fprintf(stderr, "选项 %s 缺少参数\n", a);
            return 2;
        } else if (strcmp(a, "--host") == 0) {
            host = v;
            i++;
        } else if (strcmp(a, "--port") == 0) {
            port = (uint16_t)atoi(v);
            i++;
        } else if (strcmp(a, "--root-key") == 0) {
            root_key_path = v;
            i++;
        } else if (strcmp(a, "--path") == 0) {
            path = v;
            i++;
        } else if (strcmp(a, "--host-header") == 0) {
            host_header = v;
            i++;
        } else if (strcmp(a, "--loop") == 0) {
            loop = (uint32_t)atoi(v);
            i++;
        } else if (strcmp(a, "--warmup") == 0) {
            warmup = (uint32_t)atoi(v);
            i++;
        } else if (strcmp(a, "--out") == 0) {
            out_file = v;
            i++;
        } else if (strcmp(a, "--timeout-ms") == 0) {
            timeout_ms = atoi(v);
            i++;
        } else if (strcmp(a, "--server-pid") == 0) {
            server_pid = atol(v);
            i++;
        } else if (strcmp(a, "--expect-status") == 0) {
            expect_status = atoi(v);
            i++;
        } else {
            fprintf(stderr, "未知选项 %s\n", a);
            return 2;
        }
    }
    if (port == 0) {
        usage(argv[0]);
        return 2;
    }
    if (!plain_mode && root_key_path == NULL) {
        fprintf(stderr, "缺少 --root-key（明文模式请加 --plain）\n");
        usage(argv[0]);
        return 2;
    }
    if (loop == 0) {
        loop = 1;
    }

    char hdr_buf[320];
    if (host_header != NULL) {
        snprintf(hdr_buf, sizeof hdr_buf, "%s", host_header);
    } else {
        snprintf(hdr_buf, sizeof hdr_buf, "%s:%u", host, (unsigned)port);
    }

    /* ---- 断言矩阵 ---- */
    if (suite_mode) {
        return run_suite(host, port, hdr_buf, root_key_path, timeout_ms);
    }

    /* ---- 明文直连 ---- */
    if (plain_mode) {
        if (loop > 1 || warmup > 0) {
            return plain_bench(host, port, hdr_buf, path, loop, warmup,
                               timeout_ms);
        }
        char body[8192];
        size_t blen = 0;
        int st = 0;
        if (plain_http_get(host, port, hdr_buf, path, timeout_ms, &st, body,
                           sizeof body, &blen) != 0) {
            fprintf(stderr, "[probe] FAIL: 明文请求失败\n");
            return 1;
        }
        bool nok = json_field_is_one(body, blen, "neura");
        int rc = 0;
        printf("[probe] plain status=%d neura=%s\n", st, nok ? "1" : "0");
        if (expect_status != 0 && st != expect_status) {
            printf("[probe] ASSERT FAIL status=%d expect=%d\n", st,
                   expect_status);
            rc = 1;
        }
        if (assert_neura && !nok) {
            printf("[probe] ASSERT FAIL neura 字段不为 1\n");
            rc = 1;
        }
        if (print_body && blen > 0) {
            fwrite(body, 1, blen, stdout);
            fputc('\n', stdout);
        }
        return rc;
    }

    /* ---- Neura-S2S 加密 ---- */
    neura_req o;
    memset(&o, 0, sizeof o);
    o.host = host;
    o.port = port;
    o.root_key_path = root_key_path;
    o.path = path;
    o.host_header = hdr_buf;
    o.timeout_ms = timeout_ms;
    o.server_pid = server_pid;
    o.loop = loop;
    o.warmup = warmup;
    o.quiet = quiet;

    int st = 0;
    const char *resp = NULL;
    size_t rlen = 0;
    int rc = neura_perform(&o, &st, &resp, &rlen);

    if (rc == 0) {
        if (expect_status != 0 && st != expect_status) {
            printf("[probe] ASSERT FAIL status=%d expect=%d\n", st,
                   expect_status);
            rc = 1;
        }
        if (assert_neura) {
            size_t blen = 0;
            const char *body = resp_body_of(resp, rlen, &blen);
            bool nok = json_field_is_one(body, blen, "neura");
            printf("[probe] assert neura=%s %s\n", nok ? "1" : "0",
                   nok ? "PASS" : "FAIL");
            if (!nok) {
                rc = 1;
            }
        }
        if (out_file != NULL && rlen > 0) {
            FILE *fp = fopen(out_file, "wb");
            if (fp != NULL) {
                fwrite(resp, 1, rlen, fp);
                fclose(fp);
            }
        } else if (print_body && rlen > 0) {
            size_t blen = 0;
            const char *body = resp_body_of(resp, rlen, &blen);
            if (body != NULL && blen > 0) {
                fwrite(body, 1, blen, stdout);
            }
        }
    }

    if (g_bufs_ready) {
        sh_buf_free(&g_cur);
        sh_buf_free(&g_last);
        g_bufs_ready = false;
    }
    return rc;
}
