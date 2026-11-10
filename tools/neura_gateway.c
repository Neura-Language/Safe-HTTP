// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 本地客户端网关（neura-gateway）
 *
 * 解决的问题：普通用户只有浏览器 / curl，不会说 Neura-S2S 协议，
 * 因此在"无证书纯 HTTP"部署里始终只能走明文。本网关在用户本机（或内网）
 * 提供一个普通 HTTP 接入点，再由它用 Neura-S2S 加密转发到站点：
 *
 *     浏览器/curl --明文--> neura-gateway --Neura-S2S 加密--> Safe-HTTP 站点
 *
 * 用户侧完全无感：不用装证书、不用改协议、不用了解抗量子握手。
 *
 * 用法：
 *   build/proxy/neura-gateway --listen 127.0.0.1:8899 \
 *       --server 127.0.0.1:18081 --root-key /tmp/rk.hex \
 *       --host test.jqlhtm.cn [--timeout-ms 15000]
 *
 *   curl -H 'Host: test.jqlhtm.cn' http://127.0.0.1:8899/echo
 *   curl -x http://127.0.0.1:8899 http://test.jqlhtm.cn/echo   # 也支持代理式访问
 *
 * 设计取舍（v1，简单即正确）：
 *   - 一个用户请求对应一条到站点的加密连接，请求头强制 Connection: close，
 *     靠服务端 EOF 判定响应结束，不做响应分帧，避免半包/流水线复杂度；
 *   - 单进程串行处理（一次一个用户连接），够普通用户浏览/调试使用；
 *   - Host 头可被 --host 强制覆盖，用户不必伪造域名就能访问目标 vhost。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "network.h"
#include "security.h"

#define GW_REQ_MAX   (512u * 1024u)
#define GW_RESP_MAX  (8u * 1024u * 1024u)

/* ---- 一次加密往返的运行期状态 ---- */
static sh_reactor     g_r;
static sh_buf         g_resp;          /* 解密后的响应累积 */
static const uint8_t *g_req;           /* 待发送的明文请求 */
static size_t         g_req_len;
static bool           g_req_sent;
static volatile int   g_connected;
static volatile int   g_hs_ok;
static volatile int   g_eof;
static volatile int   g_failed;
static volatile int   g_finished;
static char           g_err[192];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;

static void gw_fail(const char *why)
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

static void gw_finish(void)
{
    pthread_mutex_lock(&g_mu);
    g_finished = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static int gw_on_write(sh_reactor *r, sh_conn *c)
{
    if (!g_connected) {
        if (sh_net_connect_result(c->fd) < 0) {
            gw_fail("connect");
            return -1;
        }
        g_connected = 1;
        sh_net_set_nodelay(c->fd, true);
        if (sh_crypto_start(r, c, NS2S_ROLE_CLIENT) != NS2S_OK) {
            gw_fail("crypto start");
            return -1;
        }
    }
    if (sh_buf_readable(&c->out) > 0 &&
        sh_conn_flush(r, c, c->fd, &c->out) < 0) {
        gw_fail("flush");
        return -1;
    }
    (void)sh_conn_want(r, c, true, false);
    return 0;
}

static int gw_on_read(sh_reactor *r, sh_conn *c)
{
    for (;;) {
        if (sh_buf_reserve(&c->in, 16384) != 0) {
            gw_fail("reserve");
            return -1;
        }
        size_t space = sh_buf_writable(&c->in);
        if (space == 0) {
            break;
        }
        ssize_t n = read(c->fd, c->in.data + c->in.wpos, space);
        if (n > 0) {
            c->in.wpos += (size_t)n;
            continue;
        }
        if (n == 0) {
            g_eof = 1;
            break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        gw_fail("read");
        return -1;
    }

    if (c->crypto == SH_CRYPTO_HANDSHAKE) {
        if (sh_crypto_pump(r, c) != NS2S_OK) {
            gw_fail("handshake");
            return -1;
        }
        if (sh_buf_readable(&c->out) > 0) {
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
        if (c->crypto != SH_CRYPTO_READY) {
            if (g_eof) {
                gw_fail("握手期对端关闭");
                return -1;
            }
            return 0;
        }
        g_hs_ok = 1;
    }

    if (c->crypto == SH_CRYPTO_READY) {
        if (!g_req_sent) {
            if (sh_crypto_write(r, c, g_req, g_req_len) != NS2S_OK) {
                gw_fail("encrypt request");
                return -1;
            }
            g_req_sent = 1;
            if (sh_buf_readable(&c->out) > 0) {
                if (sh_conn_flush(r, c, c->fd, &c->out) < 0) {
                    gw_fail("flush request");
                    return -1;
                }
                (void)sh_conn_want(r, c, true, false);
            }
        }
        sh_buf plain;
        if (sh_buf_init(&plain, 8192) != 0) {
            gw_fail("oom");
            return -1;
        }
        ssize_t n = sh_crypto_read(r, c, &plain);
        if (n < 0) {
            sh_buf_free(&plain);
            gw_fail("decrypt");
            return -1;
        }
        if (n > 0) {
            size_t len = 0;
            const uint8_t *p = sh_buf_peek(&plain, &len);
            if (len > 0 && sh_buf_append(&g_resp, p, len) != len) {
                sh_buf_free(&plain);
                gw_fail("oom");
                return -1;
            }
        }
        sh_buf_free(&plain);
    }

    if (g_eof) {
        /* 站点的响应也在同一次读取里结束（Connection: close 语义） */
        if (c->crypto == SH_CRYPTO_READY) {
            sh_buf plain;
            if (sh_buf_init(&plain, 8192) == 0) {
                while (sh_crypto_read(r, c, &plain) > 0) {
                    size_t len = 0;
                    const uint8_t *p = sh_buf_peek(&plain, &len);
                    if (len > 0) {
                        (void)sh_buf_append(&g_resp, p, len);
                    }
                    sh_buf_reset(&plain);
                }
                sh_buf_free(&plain);
            }
            gw_finish();
        } else {
            gw_fail("加密通道未建立对端即关闭");
        }
    }
    return 0;
}

static int gw_on_tick(sh_reactor *r, sh_conn *c)
{
    return sh_crypto_tick(r, c);
}

static void gw_on_close(sh_reactor *r, sh_conn *c)
{
    (void)r;
    (void)c;
}

static const sh_conn_hooks k_gw_hooks = {
    .name = "gateway-client",
    .on_client_read = gw_on_read,
    .on_client_write = gw_on_write,
    .on_tick = gw_on_tick,
    .on_close = gw_on_close,
};

static void *gw_reactor_thread(void *arg)
{
    sh_reactor_run((sh_reactor *)arg);
    return NULL;
}

/* ==========================================================================
 * 一次加密往返：把明文请求发给站点，收下完整响应（解密后）
 * ========================================================================== */
static int crypto_fetch(const char *host, uint16_t port, const uint8_t root_key[SH_ROOTKEY_BYTES],
                        const uint8_t *req, size_t req_len, int timeout_ms)
{
    g_connected = 0;
    g_hs_ok = 0;
    g_eof = 0;
    g_failed = 0;
    g_finished = 0;
    g_req_sent = false;
    g_req = req;
    g_req_len = req_len;
    g_err[0] = '\0';
    sh_buf_reset(&g_resp);

    sh_settings s;
    sh_settings_defaults(&s);
    s.max_frame = SH_DEFAULT_MAX_FRAME;
    s.kem_workers = 2;
    s.trust_anchor_required = false;

    if (sh_reactor_init(&g_r, &s, NULL, NULL) != 0) {
        return -1;
    }
    memcpy(g_r.root_key, root_key, sizeof g_r.root_key);
    g_r.have_root_key = true;
    g_r.hooks = &k_gw_hooks;

    bool in_progress = false;
    int fd = sh_net_connect(host, port, &in_progress);
    if (fd < 0) {
        sh_reactor_destroy(&g_r);
        return -1;
    }
    sh_addr peer;
    memset(&peer, 0, sizeof peer);
    sh_conn *c = sh_conn_acquire(&g_r, fd, &peer);
    if (c == NULL) {
        sh_reactor_destroy(&g_r);
        return -1;
    }
    (void)sh_conn_want(&g_r, c, true, true);

    pthread_t th;
    if (pthread_create(&th, NULL, gw_reactor_thread, &g_r) != 0) {
        sh_reactor_destroy(&g_r);
        return -1;
    }

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&g_mu);
    while (!g_finished && !g_failed) {
        if (pthread_cond_timedwait(&g_cv, &g_mu, &deadline) == ETIMEDOUT) {
            break;
        }
    }
    int finished = g_finished;
    pthread_mutex_unlock(&g_mu);

    sh_reactor_stop(&g_r);
    pthread_join(th, NULL);
    sh_reactor_destroy(&g_r);

    if (g_failed) {
        return -1;
    }
    if (!finished) {
        snprintf(g_err, sizeof g_err, "超时 %d ms", timeout_ms);
        return -1;
    }
    return 0;
}

/* ==========================================================================
 * 用户侧：极简 HTTP 解析/改写
 * ========================================================================== */
static int read_full_request(int fd, char *buf, size_t cap, size_t *len_out,
                            int timeout_ms)
{
    (void)timeout_ms;
    size_t used = 0;
    size_t head_len = 0;
    long content_len = 0;
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
            if (head_len > 0) {
                /* 取 Content-Length（大小写无关、逐行扫描） */
                for (size_t i = 0; i + 15 < head_len; i++) {
                    if ((i == 0 || buf[i - 1] == '\n') &&
                        strncasecmp(buf + i, "content-length:", 15) == 0) {
                        content_len = strtol(buf + i + 15, NULL, 10);
                        break;
                    }
                }
            }
        }
        if (head_len > 0 && used >= head_len + (size_t)content_len) {
            *len_out = used;
            return 0;
        }
    }
}

/* 把用户请求改写成发给站点的请求：强制 Host 与 Connection: close */
static int rewrite_request(const char *in, size_t in_len, const char *forced_host,
                           sh_buf *out)
{
    size_t head_len = 0;
    for (size_t i = 0; i + 3 < in_len; i++) {
        if (in[i] == '\r' && in[i + 1] == '\n' && in[i + 2] == '\r' &&
            in[i + 3] == '\n') {
            head_len = i + 4;
            break;
        }
    }
    if (head_len == 0) {
        return -1;
    }

    /* 请求行：支持 origin-form 与 proxy 的 absolute-form */
    size_t eol = 0;
    while (eol + 1 < head_len && !(in[eol] == '\r' && in[eol + 1] == '\n')) {
        eol++;
    }
    const char *line = in;
    size_t llen = eol;
    char method[16] = {0};
    char target[4096] = {0};
    char version[16] = {0};
    size_t sp1 = 0;
    while (sp1 < llen && line[sp1] != ' ') {
        sp1++;
    }
    size_t sp2 = sp1 + 1;
    while (sp2 < llen && line[sp2] != ' ') {
        sp2++;
    }
    if (sp1 == 0 || sp2 >= llen || sp1 >= sizeof method || (sp2 - sp1) >= sizeof target) {
        return -1;
    }
    memcpy(method, line, sp1);
    memcpy(target, line + sp1 + 1, sp2 - sp1 - 1);
    size_t vlen = llen - sp2 - 1;
    if (vlen >= sizeof version) {
        vlen = sizeof version - 1;
    }
    memcpy(version, line + sp2 + 1, vlen);

    const char *tgt = target;
    if (strncasecmp(tgt, "http://", 7) == 0) {          /* absolute-form */
        const char *slash = strchr(tgt + 7, '/');
        tgt = slash != NULL ? slash : "/";
    }

    if (sh_buf_appendf(out, "%s %s %s\r\n", method, tgt,
                       version[0] != '\0' ? version : "HTTP/1.1") == 0) {
        return -1;
    }
    if (sh_buf_appendf(out, "Host: %s\r\n", forced_host) == 0) {
        return -1;
    }

    /* 透传其余头，跳过 Host / Connection / Proxy-Connection / Content-Length */
    long content_len = -1;
    size_t i = eol + 2;
    while (i + 1 < head_len) {
        size_t e = i;
        while (e + 1 < head_len && !(in[e] == '\r' && in[e + 1] == '\n')) {
            e++;
        }
        size_t hl = e - i;
        if (hl == 0) {
            break;
        }
        bool skip = false;
        static const char *drop[] = {"host:", "connection:", "proxy-connection:",
                                     "content-length:", "transfer-encoding:"};
        for (size_t k = 0; k < sizeof drop / sizeof drop[0]; k++) {
            size_t dl = strlen(drop[k]);
            if (hl >= dl && strncasecmp(in + i, drop[k], dl) == 0) {
                skip = true;
                if (strcasecmp(drop[k], "content-length:") == 0) {
                    content_len = strtol(in + i + dl, NULL, 10);
                }
                break;
            }
        }
        if (!skip) {
            if (sh_buf_append(out, in + i, hl) != hl ||
                sh_buf_append(out, "\r\n", 2) != 2) {
                return -1;
            }
        }
        i = e + 2;
    }
    if (sh_buf_append(out, "Connection: close\r\n", 19) != 19) {
        return -1;
    }
    if (content_len > 0) {
        if (sh_buf_appendf(out, "Content-Length: %ld\r\n", content_len) == 0) {
            return -1;
        }
    }
    if (sh_buf_append(out, "\r\n", 2) != 2) {
        return -1;
    }
    if (content_len > 0 && in_len > head_len) {
        size_t bl = in_len - head_len;
        if (bl > (size_t)content_len) {
            bl = (size_t)content_len;
        }
        if (sh_buf_append(out, in + head_len, bl) != bl) {
            return -1;
        }
    }
    return 0;
}

static int write_all(int fd, const uint8_t *p, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
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

int main(int argc, char **argv)
{
    const char *listen_addr = "127.0.0.1:8899";
    const char *server = "127.0.0.1:18081";
    const char *root_key_path = "/etc/safe-http/rootkey.hex";
    const char *forced_host = NULL;
    int timeout_ms = 15000;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            printf("用法: %s --listen 127.0.0.1:8899 --server 127.0.0.1:18081 "
                   "--root-key FILE --host test.jqlhtm.cn [--timeout-ms 15000]\n",
                   argv[0]);
            return 0;
        } else if (v == NULL) {
            fprintf(stderr, "选项 %s 缺少参数\n", a);
            return 2;
        } else if (strcmp(a, "--listen") == 0) {
            listen_addr = v;
            i++;
        } else if (strcmp(a, "--server") == 0) {
            server = v;
            i++;
        } else if (strcmp(a, "--root-key") == 0) {
            root_key_path = v;
            i++;
        } else if (strcmp(a, "--host") == 0) {
            forced_host = v;
            i++;
        } else if (strcmp(a, "--timeout-ms") == 0) {
            timeout_ms = atoi(v);
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

    char shost[128];
    snprintf(shost, sizeof shost, "%s", server);
    char *sc = strrchr(shost, ':');
    if (sc == NULL) {
        fprintf(stderr, "--server 需要 host:port\n");
        return 2;
    }
    *sc = '\0';
    unsigned sport = (unsigned)atoi(sc + 1);

    char host_hdr[192];
    snprintf(host_hdr, sizeof host_hdr, "%s", forced_host != NULL ? forced_host : shost);

    signal(SIGPIPE, SIG_IGN);
    sh_log_init(stderr, SH_LOG_WARN);
    if (sh_neura_global_init() != NS2S_OK) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }
    uint8_t root_key[SH_ROOTKEY_BYTES];
    char err[192] = {0};
    if (sh_rootkey_load(root_key_path, root_key, err, sizeof err) != NS2S_OK) {
        fprintf(stderr, "RootKey 加载失败: %s\n", err);
        return 1;
    }
    if (sh_buf_init(&g_resp, 16384) != 0) {
        fprintf(stderr, "OOM\n");
        return 1;
    }

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
        fprintf(stderr, "非法监听地址 %s\n", lhost);
        return 2;
    }
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(lfd, 128) != 0) {
        perror("listen");
        return 1;
    }
    printf("[gateway] 普通用户入口 http://%s:%u/  → Neura-S2S → %s:%u "
           "(Host: %s)\n", lhost, lport, shost, sport, host_hdr);
    fflush(stdout);

    char *reqbuf = (char *)malloc(GW_REQ_MAX);
    if (reqbuf == NULL) {
        return 1;
    }

    for (;;) {
        int ufd = accept(lfd, NULL, NULL);
        if (ufd < 0) {
            if (errno == EINTR) {
                continue;
            }
            continue;
        }
        int nd = 1;
        (void)setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof nd);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (long)(timeout_ms % 1000) * 1000L;
        (void)setsockopt(ufd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(ufd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        size_t req_len = 0;
        if (read_full_request(ufd, reqbuf, GW_REQ_MAX, &req_len, timeout_ms) != 0) {
            close(ufd);
            continue;
        }

        sh_buf out;
        if (sh_buf_init(&out, 4096) != 0) {
            close(ufd);
            continue;
        }
        if (rewrite_request(reqbuf, req_len, host_hdr, &out) != 0) {
            static const char bad[] = "HTTP/1.1 400 Bad Request\r\n"
                                      "Content-Length: 0\r\nConnection: close\r\n\r\n";
            (void)write_all(ufd, (const uint8_t *)bad, sizeof bad - 1);
            sh_buf_free(&out);
            close(ufd);
            continue;
        }

        size_t out_len = 0;
        const uint8_t *out_p = sh_buf_peek(&out, &out_len);
        int rc = crypto_fetch(shost, (uint16_t)sport, root_key, out_p, out_len,
                              timeout_ms);
        sh_buf_free(&out);

        if (rc != 0) {
            char msg[512];
            int ml = snprintf(msg, sizeof msg,
                              "HTTP/1.1 502 Bad Gateway\r\n"
                              "Content-Type: text/plain; charset=utf-8\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n"
                              "gateway: 加密通道失败: %s\n", strlen(g_err) + 27,
                              g_err);
            (void)write_all(ufd, (const uint8_t *)msg, (size_t)ml);
            close(ufd);
            continue;
        }

        size_t rlen = 0;
        const uint8_t *rp = sh_buf_peek(&g_resp, &rlen);
        if (rlen == 0) {
            static const char empty[] = "HTTP/1.1 502 Bad Gateway\r\n"
                                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
            (void)write_all(ufd, (const uint8_t *)empty, sizeof empty - 1);
        } else {
            (void)write_all(ufd, rp, rlen);
        }
        close(ufd);
    }
}
