// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Proxy 模式：Neura-S2S 解密 → WAF → 明文转发上游
 *
 * 首版范围（明确）：
 *   - 每条连接一个请求（上游 Connection: close），不做响应分帧与连接复用；
 *   - 支持 Neura-S2S 加密通道与明文 HTTP 通道共存（同一端口按首字节判别）；
 *   - 全链路无阻塞：客户端读写、上游非阻塞 connect、上游读写；
 *     上游 connect 由 EPOLLOUT 判定完成，绝不阻塞事件循环；
 *   - 双向背压：客户端积压 → 停读上游；上游积压 → 停读客户端；
 *     恢复读取用 EPOLL_CTL_MOD 重新 arm（ET 下唯一可靠的做法）。
 *
 * 收尾（half-close）语义：
 *   客户端 FIN  → 请求体送完后 shutdown(upstream, SHUT_WR)，
 *                 继续把上游响应回传给客户端；
 *   上游 FIN    → 已收到的响应字节冲净后再关客户端；
 *   两侧都静默且缓冲清空 → 返回 1 由 reactor 优雅关闭。
 */
#include "config.h"      /* 必须先拿到 SH_MODE_PROXY 才能决定是否编译本文件 */

#if SH_MODE_PROXY

#include "neura_proxy.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "config_parser.h"
#include "log.h"
#include "waf.h"

/* ==========================================================================
 * 阈值
 * ========================================================================== */
#define PROXY_OUT_HIGH_WATER  (256u * 1024u)   /* 待发客户端 > 此值 → 停读上游 */
#define PROXY_OUT_LOW_WATER   (64u * 1024u)    /* 降到此值以下 → 恢复读上游 */
#define PROXY_UP_HIGH_WATER   (256u * 1024u)   /* 待发上游 > 此值 → 停读客户端 */
#define PROXY_UP_LOW_WATER    (64u * 1024u)    /* 降到此值以下 → 恢复读客户端 */
#define PROXY_READ_LIMIT      (256u * 1024u)   /* 单次回调最多读这么多，保证公平 */

/* ==========================================================================
 * 上下文
 * ========================================================================== */
static proxy_ctx *ctx_of(sh_conn *c)
{
    return (proxy_ctx *)c->user;
}

static proxy_ctx *ctx_ensure(sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx != NULL) {
        return ctx;
    }
    ctx = calloc(1, sizeof *ctx);
    if (ctx == NULL) {
        return NULL;
    }
    if (sh_buf_init(&ctx->plain_buf, SH_PREAUTH_CAP) != 0) {
        free(ctx);
        return NULL;
    }
    ctx->up_state = PROXY_UP_IDLE;
    ctx->upstream_deadline_ms = 0;
    ctx->last_io_ms = c->accepted_ms;
    c->user = ctx;
    return ctx;
}

static uint64_t proxy_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static void ctx_touch(sh_conn *c, proxy_ctx *ctx)
{
    if (c != NULL && ctx != NULL) {
        ctx->last_io_ms = c->last_active_ms;
    }
}

/* ==========================================================================
 * 响应辅助
 * ========================================================================== */
static int send_plain_response(sh_reactor *r, sh_conn *c, int code,
                               const char *message)
{
    sh_buf tmp;
    if (sh_buf_init(&tmp, 1024) != 0) {
        return -1;
    }
    if (sh_http_send_error(&tmp, code, message) != 0) {
        sh_buf_free(&tmp);
        return -1;
    }
    size_t len = 0;
    const uint8_t *p = sh_buf_peek(&tmp, &len);
    int rc = 0;
    if (c->crypto == SH_CRYPTO_READY) {
        rc = sh_crypto_write(r, c, p, len);
    } else {
        rc = sh_buf_append(&c->out, p, len) == len ? 0 : -1;
    }
    sh_buf_free(&tmp);
    if (rc != 0) {
        return -1;
    }
    (void)sh_conn_flush(r, c, c->fd, &c->out);
    return 0;
}

/* ==========================================================================
 * 读取
 * ========================================================================== */
/*
 * ET：读到 EAGAIN / 达到 limit / 缓冲压满为止。
 * 返回本次读到的字节数（>=0）；-1 仅表示参数错误。
 *   *drained = true  → 已读到 EAGAIN（内核缓冲已空，ET 下不会再有边沿）
 *   *eof     = true  → 对端 FIN 或硬错误
 *
 * 关键：EOF 与数据常常在同一次 read 循环里同时出现（对端"回完即关"），
 * 因此遇到 n==0 时必须 **保留已读到的字节** 并单独上报 eof，
 * 绝不能像旧实现那样直接 return -1 把数据丢掉。
 */
static ssize_t fill_from_fd(int fd, sh_buf *b, uint64_t *counter, size_t limit,
                            bool *drained, bool *eof)
{
    if (drained != NULL) {
        *drained = false;
    }
    if (eof != NULL) {
        *eof = false;
    }
    if (fd < 0 || b == NULL) {
        if (eof != NULL) {
            *eof = true;
        }
        return -1;
    }
    ssize_t total = 0;
    while (sh_buf_readable(b) < limit) {
        if (sh_buf_reserve(b, 4096) != 0) {
            if (eof != NULL) {
                *eof = true;               /* 内存不足：按致命错误处理 */
            }
            return total;
        }
        size_t space = sh_buf_writable(b);
        if (space == 0) {
            break;
        }
        ssize_t n = read(fd, b->data + b->wpos, space);
        if (n > 0) {
            b->wpos += (size_t)n;
            total += n;
            if (counter != NULL) {
                *counter += (uint64_t)n;
            }
            continue;
        }
        if (n == 0) {
            if (eof != NULL) {
                *eof = true;
            }
            return total;                  /* 保留已读字节 */
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (drained != NULL) {
                *drained = true;
            }
            return total;
        }
        if (errno == EINTR) {
            continue;
        }
        if (eof != NULL) {
            *eof = true;
        }
        return total;
    }
    return total;
}

/* ==========================================================================
 * 上游
 * ========================================================================== */
int proxy_upstream_connect(sh_reactor *r, sh_conn *c,
                           const char *host, uint16_t port)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL) {
        return -1;
    }
    if (c->upstream_fd >= 0) {
        return 0;                             /* 已连接 */
    }
    bool in_progress = false;
    int fd = sh_net_connect(host, port, &in_progress);
    if (fd < 0) {
        SH_LOGE("conn#%u 连接上游 %s:%u 失败: %s", c->id, host, (unsigned)port,
                strerror(errno));
        return -1;
    }
    sh_net_set_nodelay(fd, true);
    sh_net_set_keepalive(fd, true, 30, 5, 3);
    c->upstream_fd = fd;
    c->upstream_events = 0;
    ctx->up_state = in_progress ? PROXY_UP_DIALING : PROXY_UP_CONNECTED;
    ctx->upstream_deadline_ms = SH_UPSTREAM_CONNECT_TIMEOUT_MS + c->last_active_ms;
    ctx->up_shut_wr = false;
    ctx->upstream_eof = false;
    c->state = SH_CONN_UPSTREAM_CONNECT;

    /* DIALING 必须订阅 EPOLLOUT（connect 完成 / 失败都靠它） */
    if (sh_conn_want_upstream(r, c, true, true) != 0) {
        SH_LOGW("conn#%u 上游 fd 注册 epoll 失败: %s", c->id, strerror(errno));
        return -1;
    }
    if (!in_progress) {
        return proxy_upstream_start(r, c);
    }
    return 0;
}

int proxy_upstream_start(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL || c->upstream_fd < 0) {
        return -1;
    }
    if (ctx->up_state == PROXY_UP_DIALING) {
        return 0;                             /* 等 EPOLLOUT */
    }
    ctx->up_state = PROXY_UP_CONNECTED;
    c->state = SH_CONN_UPSTREAM_ACTIVE;
    if (sh_buf_readable(&c->up_out) > 0) {
        if (sh_conn_flush(r, c, c->upstream_fd, &c->up_out) < 0) {
            SH_LOGW("conn#%u 发送请求到上游失败: %s", c->id, strerror(errno));
            return -1;
        }
    }
    if (sh_buf_readable(&c->up_out) == 0) {
        ctx->up_state = PROXY_UP_STREAMING;
    }
    (void)sh_conn_want_upstream(r, c, true, sh_buf_readable(&c->up_out) > 0);
    return 0;
}

void proxy_upstream_close(sh_reactor *r, sh_conn *c, bool graceful)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx != NULL) {
        ctx->upstream_eof = true;
        ctx->up_state = PROXY_UP_CLOSED;
    }
    if (c == NULL || c->upstream_fd < 0) {
        return;
    }
    if (graceful) {
        (void)sh_conn_flush(r, c, c->upstream_fd, &c->up_out);
    } else {
        struct linger lg;
        lg.l_onoff = 1;
        lg.l_linger = 0;
        (void)setsockopt(c->upstream_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    }
    if (r != NULL) {
        epoll_ctl(r->epfd, EPOLL_CTL_DEL, c->upstream_fd, NULL);
    }
    close(c->upstream_fd);
    c->upstream_fd = -1;
    c->upstream_events = 0;
    c->upstream_paused = false;
}

/* ==========================================================================
 * 背压
 * ========================================================================== */
void proxy_apply_backpressure(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL) {
        return;
    }
    /* 方向 1：客户端发不出去 → 暂停读上游（内核 TCP 窗口自然限流） */
    size_t out_pending = sh_buf_readable(&c->out);
    if (!c->upstream_paused && out_pending > PROXY_OUT_HIGH_WATER) {
        c->upstream_paused = true;
        SH_LOGD("conn#%u 背压：out=%zu，暂停读上游", c->id, out_pending);
    } else if (c->upstream_paused && out_pending <= PROXY_OUT_LOW_WATER) {
        c->upstream_paused = false;
        SH_LOGD("conn#%u 背压解除：out=%zu，恢复读上游", c->id, out_pending);
        (void)sh_conn_rearm(r, c, true);       /* ET：必须重新 arm 才会再投递 */
    }

    /* 方向 2：上游写不出去 → 暂停读客户端 */
    size_t up_pending = sh_buf_readable(&c->up_out);
    if (!c->read_paused && up_pending > PROXY_UP_HIGH_WATER) {
        c->read_paused = true;
        SH_LOGD("conn#%u 背压：up_out=%zu，暂停读客户端", c->id, up_pending);
    } else if (c->read_paused && up_pending <= PROXY_UP_LOW_WATER) {
        c->read_paused = false;
        SH_LOGD("conn#%u 背压解除：up_out=%zu，恢复读客户端", c->id, up_pending);
        (void)sh_conn_rearm(r, c, false);
    }
}

/* ==========================================================================
 * 上游响应头解析（仅用于日志/统计/keep-alive 判定）
 * 返回 0 成功，1 数据不足，-1 畸形
 * ========================================================================== */
int proxy_parse_upstream_response(sh_reactor *r, sh_conn *c,
                                  const uint8_t *data, size_t len,
                                  int *status_out, size_t *head_len_out)
{
    (void)r;
    (void)c;
    if (status_out != NULL) {
        *status_out = 0;
    }
    if (head_len_out != NULL) {
        *head_len_out = 0;
    }
    if (data == NULL || len < 12) {           /* 12 = "HTTP/1.1 200" */
        return 1;
    }
    if (memcmp(data, "HTTP/1.", 7) != 0 || data[8] != ' ') {
        return -1;
    }
    if (!isdigit(data[9]) || !isdigit(data[10]) || !isdigit(data[11])) {
        return -1;
    }
    int status = (data[9] - '0') * 100 + (data[10] - '0') * 10 + (data[11] - '0');
    size_t scan = len < SH_MAX_HEAD_BYTES ? len : SH_MAX_HEAD_BYTES;
    for (size_t i = 0; i + 3 < scan; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            if (status_out != NULL) {
                *status_out = status;
            }
            if (head_len_out != NULL) {
                *head_len_out = i + 4;
            }
            return 0;
        }
    }
    return len >= SH_MAX_HEAD_BYTES ? -1 : 1;
}

/* ==========================================================================
 * 组装上游请求
 * ========================================================================== */
int proxy_build_upstream_request(sh_reactor *r, sh_conn *c,
                                 const sh_http_head *req)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL || req == NULL || r->config == NULL) {
        return -1;
    }

    ctx->rewritten_target[0] = '\0';
    const char *target = NULL;
    const ncf_rewrite_rule *matched = NULL;
    if (ncf_rewrite_apply(r->config, req->path, req->path_len,
                          ctx->rewritten_target, sizeof ctx->rewritten_target,
                          &matched)) {
        target = ctx->rewritten_target;
        SH_LOGD("conn#%u 重写 %.*s -> %s（规则 %s）", c->id, (int)req->path_len,
                req->path, target, matched != NULL ? matched->name : "?");
    }

    char peer_ip[SH_INET_ADDR_STRLEN];
    (void)sh_addr_ip(&c->peer, peer_ip, sizeof peer_ip);

    /*
     * Host 头：sh_http_build_request() 会剔除原始 Host（防止转发伪造的
     * 绝对 URI/重复 Host），因此必须在这里显式补回，否则 HTTP/1.1 请求
     * 缺 Host，任何 name-based vhost 都会直接回 400 Bad Request。
     *
     * 取值策略（与 nginx `proxy_set_header Host $host` 一致）：
     *   1. 优先保留客户端 Host —— 反向代理后端的 vhost 路由依赖它；
     *   2. 客户端没带 Host（HTTP/1.0）时回落到上游地址（80 端口省略）。
     */
    char host_hdr[SH_MAX_HEAD_BYTES / 4];
    size_t client_host_len = 0;
    const char *client_host = sh_http_header(req, "host", &client_host_len);
    if (client_host != NULL && client_host_len > 0 &&
        client_host_len < sizeof host_hdr) {
        memcpy(host_hdr, client_host, client_host_len);
        host_hdr[client_host_len] = '\0';
    } else {
        const char *uh = r->settings.upstream_host != NULL
                             ? r->settings.upstream_host
                             : SH_DEFAULT_UPSTREAM_HOST;
        uint16_t up = r->settings.upstream_port != 0 ? r->settings.upstream_port
                                                     : SH_DEFAULT_UPSTREAM_PORT;
        if (up == 80) {
            snprintf(host_hdr, sizeof host_hdr, "%s", uh);
        } else {
            snprintf(host_hdr, sizeof host_hdr, "%s:%u", uh, (unsigned)up);
        }
    }

    sh_http_extra_header extras[6];
    size_t n = 0;
    extras[n].name = "Host";
    extras[n++].value = host_hdr;
    extras[n].name = "X-Real-IP";
    extras[n++].value = peer_ip;
    extras[n].name = "X-Forwarded-For";
    extras[n++].value = peer_ip;
    extras[n].name = "X-Forwarded-Proto";
    extras[n++].value = "http";
    extras[n].name = "X-Neura-S2S";
    extras[n++].value = (c->crypto == SH_CRYPTO_READY) ? "1" : "0";

    if (sh_http_build_request_ex(req, target, extras, n, ctx->keep_alive,
                                &c->up_out) < 0) {
        SH_LOGE("conn#%u 构造上游请求失败", c->id);
        return -1;
    }
    ctx->head_forwarded = true;
    ctx->upstream_keep_alive = ctx->keep_alive;   /* 与请求头保持一致 */
    ctx->requests++;
    r->stats.requests_total++;
    return 0;
}

/* ==========================================================================
 * 请求处理（明文）
 * ========================================================================== */
static waf_verdict inspect_waf(sh_reactor *r, sh_conn *c, sh_http_head *req)
{
    if (r->waf == NULL) {
        return WAF_ALLOW;
    }
    waf_request wreq;
    memset(&wreq, 0, sizeof wreq);
    wreq.peer = &c->peer;
    wreq.ip_str = c->ip_str;
    wreq.method = req->method_str;
    wreq.method_len = req->method_len;
    wreq.path = req->path;
    wreq.path_len = req->path_len;
    wreq.query = req->query;
    wreq.query_len = req->query_len;
    size_t ua_len = 0;
    wreq.user_agent = sh_http_header(req, "user-agent", &ua_len);
    wreq.user_agent_len = ua_len;
    wreq.now_ms = c->last_active_ms != 0 ? c->last_active_ms : 1;
    size_t host_len = 0;
    wreq.host = sh_http_header(req, "host", &host_len);
    wreq.host_len = host_len;
    size_t cookie_len = 0;
    wreq.cookie = sh_http_header(req, "cookie", &cookie_len);
    wreq.cookie_len = cookie_len;

    waf_hit hit;
    memset(&hit, 0, sizeof hit);
    waf_verdict v = waf_inspect(r->waf, &wreq, &hit);
    if (v != WAF_ALLOW && hit.rule != NULL) {
        SH_LOGW("conn#%u WAF 命中规则 \"%s\"（%s）", c->id, hit.rule->name,
                c->ip_str);
    }
    return v;
}

/* 把 plain 中可转发的字节搬进 up_out：返回 0 继续，-1 需关闭连接 */
static int proxy_pump_body(sh_reactor *r, sh_conn *c, proxy_ctx *ctx, sh_buf *plain)
{
    for (;;) {
        size_t avail = 0;
        const uint8_t *p = sh_buf_peek(plain, &avail);
        if (avail == 0) {
            break;
        }
        if (c->upstream_fd < 0) {
            /* 上游已死：丢弃剩余请求体（响应已由上层给出） */
            sh_buf_consume(plain, avail);
            break;
        }
        size_t pending = sh_buf_readable(&c->up_out);
        if (pending >= PROXY_UP_HIGH_WATER) {
            c->read_paused = true;             /* 等上游写穿再继续读客户端 */
            break;
        }
        size_t room = PROXY_UP_HIGH_WATER - pending;
        size_t n = avail < room ? avail : room;
        if (sh_buf_append(&c->up_out, p, n) != n) {
            return -1;
        }
        sh_buf_consume(plain, n);
        if (ctx->up_state != PROXY_UP_DIALING) {
            if (sh_conn_flush(r, c, c->upstream_fd, &c->up_out) < 0) {
                SH_LOGW("conn#%u 转发请求体失败: %s", c->id, strerror(errno));
                return -1;
            }
            (void)sh_conn_want_upstream(r, c, true,
                                        sh_buf_readable(&c->up_out) > 0);
        }
        if (n < avail) {
            c->read_paused = true;             /* 缓冲已满，下一轮再搬 */
            break;
        }
    }
    return 0;
}

static void proxy_resp_state_reset(proxy_ctx *ctx);

/* 客户端请求是否要求复用连接（HTTP/1.1 默认 keep-alive，显式 close 除外） */
static bool request_wants_keep_alive(const sh_http_head *req)
{
    size_t n = 0;
    const char *conn = sh_http_header(req, "connection", &n);
    if (conn != NULL && n >= 5 && memmem(conn, n, "close", 5) != NULL) {
        return false;
    }
    if (req->version_major > 1 ||
        (req->version_major == 1 && req->version_minor >= 1)) {
        return true;
    }
    return conn != NULL && n >= 10 && memmem(conn, n, "keep-alive", 10) != NULL;
}

/*
 * 复位「每请求」状态，让同一条加密通道继续处理下一个请求。
 * 上游连接仍是一请求一连接（靠上游 EOF 做响应分帧），但
 * Client↔Proxy 的 Neura-S2S 通道、AES-GCM 会话、KEM 棘轮全部复用。
 */
static void proxy_reset_request(sh_reactor *r, sh_conn *c, proxy_ctx *ctx)
{
    if (c->upstream_fd >= 0) {
        proxy_upstream_close(r, c, false);
    }
    ctx->head_forwarded = false;
    ctx->resp_head_seen = false;
    ctx->resp_status = 0;
    ctx->upstream_eof = false;
    ctx->up_shut_wr = false;
    ctx->up_state = PROXY_UP_IDLE;
    ctx->upstream_deadline_ms = 0;
    memset(&ctx->request, 0, sizeof ctx->request);
    sh_buf_reset(&c->up_in);
    sh_buf_reset(&c->up_out);
    c->read_paused = false;
    c->upstream_paused = false;
    c->state = SH_CONN_ACTIVE;
    SH_LOGD("conn#%u 复用加密通道，已处理 %u 个请求", c->id, ctx->served);
}

static int proxy_handle_plain(sh_reactor *r, sh_conn *c, sh_buf *plain)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL) {
        return -1;
    }
    while (sh_buf_readable(plain) > 0) {
        if (ctx->head_forwarded) {
            return proxy_pump_body(r, c, ctx, plain);
        }
        /* 上一个响应还没写穿客户端：先别接新请求（由 on_client_write 重入） */
        if (sh_buf_readable(&c->out) > 0) {
            return 0;
        }

        size_t avail = 0;
        const uint8_t *p = sh_buf_peek(plain, &avail);
        sh_http_parse_status st = sh_http_parse_head(p, avail, &ctx->request);
        if (st == SH_HTTP_INCOMPLETE) {
            return 0;                          /* 等更多数据 */
        }
        if (st != SH_HTTP_OK) {
            SH_LOGW("conn#%u 非法 HTTP 请求（%d）", c->id, (int)st);
            (void)send_plain_response(r, c, 400, "Bad Request");
            return 1;
        }
        /* 是否复用本通道（决定响应收完后是复位还是关闭） */
        ctx->keep_alive = request_wants_keep_alive(&ctx->request) && !ctx->client_eof;
        ctx->req_is_head = (ctx->request.method_len == 4 &&
                            strncasecmp(ctx->request.method_str, "HEAD", 4) == 0);
        proxy_resp_state_reset(ctx);

        /* 1) WAF */
        waf_verdict v = inspect_waf(r, c, &ctx->request);
        if (v == WAF_DROP) {
            sh_conn_drop(r, c);
            return 1;
        }
        if (v == WAF_RESPOND_403) {
            (void)send_plain_response(r, c, 403, "Forbidden");
            return 1;
        }
        if (v == WAF_THROTTLE) {
            (void)send_plain_response(r, c, 429, "Too Many Requests");
            return 1;
        }

        /* 2) 加密策略：按 Host + Path 判定（共享 IP 边缘代理必需）。
         *    未匹配任何 Encrypt 规则时由 ncf_config.plaintext 决定
         *    （默认 deny → enforce_neura_s2s，即全站加密）。 */
        size_t host_len = 0;
        const char *host = sh_http_header(&ctx->request, "host", &host_len);
        ncf_action_type act = ncf_effective_action_for(r->config, host, host_len,
                                                      ctx->request.path,
                                                      ctx->request.path_len);
        switch (act) {
        case NCF_ACTION_DROP_CONNECTION:
            SH_LOGW("conn#%u 路由策略 drop_connection（%.*s），断开", c->id,
                    (int)ctx->request.path_len, ctx->request.path);
            sh_conn_drop(r, c);
            return 1;
        case NCF_ACTION_RESPOND_403:
            SH_LOGW("conn#%u 路由策略 respond_403（%.*s），拒绝", c->id,
                    (int)ctx->request.path_len, ctx->request.path);
            (void)send_plain_response(r, c, 403, "Forbidden");
            return 1;
        case NCF_ACTION_ENFORCE_NEURA_S2S:
            if (c->crypto != SH_CRYPTO_READY) {
                SH_LOGW("conn#%u 明文访问加密路由（%.*s），拒绝", c->id,
                        (int)ctx->request.path_len, ctx->request.path);
                (void)send_plain_response(r, c, 403,
                                          "Neura-S2S encryption required");
                return 1;
            }
            break;
        case NCF_ACTION_LOG_ONLY:
            SH_LOGI("conn#%u 路由 %.*s 为 log_only，按明文放行", c->id,
                    (int)ctx->request.path_len, ctx->request.path);
            break;
        case NCF_ACTION_ALLOW_PLAIN:
        case NCF_ACTION_NONE:
        default:
            break;
        }

        /* 3) 构造上游请求（重写 + X-Forwarded-*） */
        if (proxy_build_upstream_request(r, c, &ctx->request) != 0) {
            (void)send_plain_response(r, c, 500, "Build request failed");
            return 1;
        }
        sh_buf_consume(plain, ctx->request.head_len);
        /* head 里的指针指向 plain_buf，consume 后可能失效：立刻清空，
         * 后续只用 ctx->head_forwarded 判断阶段 */
        memset(&ctx->request, 0, sizeof ctx->request);

        /* 4) 非阻塞连接上游（空闲的 keep-alive 上游连接优先复用） */
        const char *up_host = r->settings.upstream_host != NULL
                                  ? r->settings.upstream_host
                                  : SH_DEFAULT_UPSTREAM_HOST;
        uint16_t up_port = r->settings.upstream_port != 0
                               ? r->settings.upstream_port
                               : SH_DEFAULT_UPSTREAM_PORT;
        if (c->upstream_fd >= 0 && ctx->up_state == PROXY_UP_STREAMING) {
            SH_LOGD("conn#%u 复用空闲上游连接", c->id);
            if (proxy_upstream_start(r, c) != 0) {
                (void)send_plain_response(r, c, 502, "Upstream send failed");
                return 1;
            }
        } else if (proxy_upstream_connect(r, c, up_host, up_port) != 0) {
            (void)send_plain_response(r, c, 502, "Upstream connect failed");
            return 1;
        }
        /* 继续循环：把可能已在缓冲中的请求体搬过去 */
    }
    return 0;
}

/* ==========================================================================
 * 钩子：客户端
 * ========================================================================== */
int proxy_on_client_read(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_ensure(c);
    if (ctx == NULL) {
        return -1;
    }
    if (c->read_paused) {
        return 0;                              /* 背压：数据留在内核缓冲 */
    }

    bool drained = false;
    bool eof = false;
    ssize_t got = fill_from_fd(c->fd, &c->in, &r->stats.bytes_client_in,
                               PROXY_READ_LIMIT, &drained, &eof);
    if (got > 0) {
        c->bytes_in += (uint64_t)got;
        c->last_active_ms = proxy_now_ms();
        ctx_touch(c, ctx);
    }
    if (eof) {
        ctx->client_eof = true;
        c->half_closed = true;
    }

    /* 未启用加密：按首字节判别 Neura-S2S 握手还是明文 HTTP */
    if (c->crypto == SH_CRYPTO_PLAIN) {
        size_t avail = 0;
        const uint8_t *p = sh_buf_peek(&c->in, &avail);
        if (avail >= 4 && memcmp(p, "NS2H", 4) == 0) {
            if (sh_crypto_start(r, c, NS2S_ROLE_SERVER) != NS2S_OK) {
                SH_LOGW("conn#%u 启动 Neura-S2S 失败", c->id);
                return 1;
            }
            c->state = SH_CONN_HANDSHAKING;
        }
    }

    if (c->crypto == SH_CRYPTO_HANDSHAKE) {
        int rc = sh_crypto_pump(r, c);
        if (rc != NS2S_OK) {
            SH_LOGW("conn#%u 握手失败 rc=%d", c->id, rc);
            return 1;
        }
        if (sh_buf_readable(&c->out) > 0) {
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
        if (c->crypto != SH_CRYPTO_READY) {
            return ctx->client_eof ? 1 : 0;
        }
        c->state = SH_CONN_ACTIVE;
    }

    /* 明文来源：加密通道先解密，明文通道直接镜像 c->in */
    sh_buf *plain = &ctx->plain_buf;
    if (c->crypto == SH_CRYPTO_READY) {
        ssize_t n = sh_crypto_read(r, c, plain);
        if (n < 0) {
            SH_LOGW("conn#%u 解密失败", c->id);
            return 1;
        }
    } else {
        size_t avail = 0;
        const uint8_t *p = sh_buf_peek(&c->in, &avail);
        if (avail > 0) {
            if (sh_buf_append(plain, p, avail) != avail) {
                return -1;
            }
            sh_buf_consume(&c->in, avail);
        }
    }

    if (sh_buf_readable(plain) > 0) {
        int rc = proxy_handle_plain(r, c, plain);
        if (rc != 0) {
            return rc;
        }
    }

    /* 客户端已半关闭：请求体送完后通知上游不再有数据 */
    if (ctx->client_eof && !ctx->up_shut_wr && c->upstream_fd >= 0 &&
        sh_buf_readable(&c->up_out) == 0 &&
        c->upstream_events != 0 && ctx->up_state != PROXY_UP_DIALING) {
        if (shutdown(c->upstream_fd, SHUT_WR) == 0 ||
            errno == ENOTCONN || errno == EPIPE) {
            ctx->up_shut_wr = true;
            SH_LOGD("conn#%u 客户端半关闭 → shutdown(upstream, SHUT_WR)", c->id);
        }
    }

    /* 客户端直接断开且没有待处理数据：收尾 */
    if (ctx->client_eof && sh_buf_readable(plain) == 0 &&
        c->upstream_fd < 0 && sh_buf_readable(&c->out) == 0) {
        return 1;
    }

    /* ET：本次没读到 EAGAIN 说明内核里还有数据，但边沿不会再触发 → 重新 arm */
    if (!drained && !eof && !c->read_paused &&
        sh_buf_readable(&c->in) < PROXY_READ_LIMIT) {
        (void)sh_conn_rearm(r, c, false);
    }

    proxy_apply_backpressure(r, c);
    return 0;
}

int proxy_on_client_write(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    (void)sh_conn_flush(r, c, c->fd, &c->out);
    (void)sh_conn_want(r, c, true, false);
    proxy_apply_backpressure(r, c);

    if (ctx == NULL) {
        return 0;
    }

    /*
     * keep-alive 复用：响应已写穿，且上游连接收尾时没能复位
     * （当时 c->out 还有残留），这里补做复位并继续处理已缓冲的下一个请求。
     */
    if (ctx->keep_alive && ctx->upstream_eof && c->upstream_fd < 0 &&
        sh_buf_readable(&c->out) == 0) {
        proxy_reset_request(r, c, ctx);
        (void)sh_conn_want(r, c, true, false);
        if (sh_buf_readable(&ctx->plain_buf) > 0) {
            return proxy_handle_plain(r, c, &ctx->plain_buf);
        }
        return 0;
    }

    /* 上一个响应写完，之前被挡住的下一请求现在可以推进了 */
    if (!ctx->head_forwarded && sh_buf_readable(&c->out) == 0 &&
        sh_buf_readable(&ctx->plain_buf) > 0) {
        return proxy_handle_plain(r, c, &ctx->plain_buf);
    }

    /* 上游已收完 + 客户端缓冲冲净 + 不复用 → 关闭 */
    if (ctx->upstream_eof && c->upstream_fd < 0 &&
        sh_buf_readable(&c->out) == 0 && !ctx->keep_alive) {
        SH_LOGD("conn#%u 响应转发完成（status=%d），关闭连接", c->id,
                ctx->resp_status);
        return 1;
    }
    return 0;
}

/* ==========================================================================
 * 钩子：上游
 * ========================================================================== */
/* ==========================================================================
 * 响应分帧（HTTP/1.1 keep-alive 核心）
 *
 * 只在 up_in 上「扫描 + 计数」，不消耗缓冲区：
 *   - 先找 \r\n\r\n 拿到响应头，解析 Content-Length / Transfer-Encoding /
 *     Connection / 状态码；
 *   - 再按 Content-Length 或 chunked 状态机推进计数；
 *   - 返回 1 表示「本响应已完整」，0 表示还需更多字节，-1 表示协议错误。
 *   consumed 是本响应已扫过的字节数（即可以直接转发给客户端的部分）。
 * ========================================================================== */
static void proxy_resp_state_reset(proxy_ctx *ctx)
{
    ctx->resp_head_done = false;
    ctx->resp_chunked = false;
    ctx->resp_no_body = false;
    ctx->resp_complete = false;
    ctx->resp_keep_alive = true;
    ctx->resp_body_left = 0;
    ctx->resp_chunk_left = 0;
    ctx->resp_chunk_phase = 0;
    ctx->resp_line_len = 0;
    ctx->resp_bytes = 0;
    ctx->resp_head_seen = false;
    ctx->resp_status = 0;
}

static int hex_val(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

/* 解析响应头（p 至少 len 字节，len 是到 \r\n\r\n 为止的头长） */
static int proxy_resp_parse_head(proxy_ctx *ctx, const uint8_t *p, size_t len)
{
    const char *b = (const char *)p;
    if (len < 12 || memcmp(b, "HTTP/1.", 7) != 0 || b[8] != ' ' ||
        !isdigit((unsigned char)b[9]) || !isdigit((unsigned char)b[10]) ||
        !isdigit((unsigned char)b[11])) {
        return -1;
    }
    int status = (b[9] - '0') * 100 + (b[10] - '0') * 10 + (b[11] - '0');
    ctx->resp_status = status;

    long cl = -1;
    bool chunked = false;
    bool conn_close = false;

    size_t i = 0;
    while (i + 1 < len && !(b[i] == '\r' && b[i + 1] == '\n')) {
        i++;                                   /* 跳过状态行 */
    }
    if (i + 1 >= len) {
        return -1;
    }
    i += 2;
    while (i + 1 < len) {
        size_t eol = i;
        while (eol + 1 < len && !(b[eol] == '\r' && b[eol + 1] == '\n')) {
            eol++;
        }
        size_t line_len = eol - i;
        if (line_len == 0) {
            break;                             /* 头部结束 */
        }
        size_t colon = i;
        while (colon < eol && b[colon] != ':') {
            colon++;
        }
        if (colon >= eol) {
            i = eol + 2;
            continue;
        }
        size_t nlen = colon - i;
        size_t vs = colon + 1;
        while (vs < eol && (b[vs] == ' ' || b[vs] == '\t')) {
            vs++;
        }
        size_t vlen = eol - vs;

        if (nlen == 14 && strncasecmp(b + i, "content-length", 14) == 0) {
            cl = 0;
            for (size_t k = vs; k < eol && isdigit((unsigned char)b[k]); k++) {
                if (cl < (1L << 50)) {
                    cl = cl * 10 + (b[k] - '0');
                }
            }
        } else if (nlen == 17 &&
                   strncasecmp(b + i, "transfer-encoding", 17) == 0) {
            if (vlen >= 7 && memmem(b + vs, vlen, "chunked", 7) != NULL) {
                chunked = true;
            }
        } else if (nlen == 10 && strncasecmp(b + i, "connection", 10) == 0) {
            if (vlen >= 5 && memmem(b + vs, vlen, "close", 5) != NULL) {
                conn_close = true;
            }
        }
        i = eol + 2;
    }

    ctx->resp_keep_alive = !conn_close;
    ctx->resp_no_body = (status == 204 || status == 304 ||
                         (status >= 100 && status < 200) || ctx->req_is_head);
    ctx->resp_chunked = chunked && !ctx->resp_no_body;
    if (ctx->resp_no_body) {
        ctx->resp_body_left = 0;
    } else if (ctx->resp_chunked) {
        ctx->resp_chunk_phase = 0;
        ctx->resp_line_len = 0;
    } else if (cl >= 0) {
        ctx->resp_body_left = (uint64_t)cl;
    } else {
        /* 既无 Content-Length 也非 chunked：只能读到 EOF，无法复用上游 */
        ctx->resp_keep_alive = false;
        ctx->resp_body_left = UINT64_MAX;
    }
    return 0;
}

static int proxy_resp_frame(proxy_ctx *ctx, const uint8_t *p, size_t avail,
                            size_t *consumed)
{
    size_t i = 0;
    *consumed = 0;

    if (!ctx->resp_head_done) {
        size_t scan = avail < SH_MAX_HEAD_BYTES ? avail : SH_MAX_HEAD_BYTES;
        size_t k = 0;
        for (; k + 3 < scan; k++) {
            if (p[k] == '\r' && p[k + 1] == '\n' && p[k + 2] == '\r' &&
                p[k + 3] == '\n') {
                break;
            }
        }
        if (k + 3 >= scan) {
            if (avail >= SH_MAX_HEAD_BYTES) {
                return -1;                     /* 响应头超大 */
            }
            return 0;                          /* 等更多 */
        }
        size_t head_len = k + 4;
        if (proxy_resp_parse_head(ctx, p, head_len) != 0) {
            return -1;
        }
        ctx->resp_head_done = true;
        ctx->resp_head_seen = true;
        i = head_len;
        SH_LOGD("conn#%u 上游响应 %d（头 %zu 字节, chunked=%d, no_body=%d, "
                "keep_alive=%d, 待收 body=%s）",
                ctx->resp_status, head_len, (int)ctx->resp_chunked,
                (int)ctx->resp_no_body, (int)ctx->resp_keep_alive,
                ctx->resp_chunked ? "chunked"
                                  : (ctx->resp_body_left == UINT64_MAX
                                         ? "until-eof"
                                         : "content-length"));
        if (ctx->resp_status >= 100 && ctx->resp_status < 200) {
            /* 1xx 中间响应：转发后继续等最终响应 */
            ctx->resp_head_done = false;
            ctx->resp_no_body = false;
            *consumed = i;
            return 0;
        }
        if (ctx->resp_no_body) {
            *consumed = i;
            return 1;
        }
    }

    if (!ctx->resp_chunked) {
        if (ctx->resp_body_left == UINT64_MAX) {
            *consumed = avail;                 /* 读到 EOF 为止 */
            return 0;
        }
        size_t room = avail - i;
        size_t take = (uint64_t)room < ctx->resp_body_left ? room
                                                           : (size_t)ctx->resp_body_left;
        i += take;
        ctx->resp_body_left -= take;
        *consumed = i;
        return ctx->resp_body_left == 0 ? 1 : 0;
    }

    while (i < avail) {
        if (ctx->resp_chunk_phase == 0) {        /* chunk size 行 */
            bool got_line = false;
            while (i < avail) {
                char ch = (char)p[i++];
                if (ctx->resp_line_len < sizeof ctx->resp_line) {
                    ctx->resp_line[ctx->resp_line_len++] = ch;
                }
                if (ctx->resp_line_len >= 2 && ch == '\n' &&
                    ctx->resp_line[ctx->resp_line_len - 2] == '\r') {
                    got_line = true;
                    break;
                }
            }
            if (!got_line) {
                *consumed = i;
                return 0;
            }
            uint64_t sz = 0;
            for (size_t k = 0; k < ctx->resp_line_len; k++) {
                int hv = hex_val(ctx->resp_line[k]);
                if (hv < 0) {
                    break;
                }
                sz = sz * 16u + (uint64_t)hv;
            }
            ctx->resp_line_len = 0;
            if (sz == 0) {
                ctx->resp_chunk_phase = 3;       /* 末尾 trailer */
            } else {
                ctx->resp_chunk_left = sz;
                ctx->resp_chunk_phase = 1;
            }
        } else if (ctx->resp_chunk_phase == 1) { /* chunk 数据 */
            size_t room = avail - i;
            size_t take = (uint64_t)room < ctx->resp_chunk_left
                              ? room
                              : (size_t)ctx->resp_chunk_left;
            i += take;
            ctx->resp_chunk_left -= take;
            if (ctx->resp_chunk_left == 0) {
                ctx->resp_chunk_phase = 2;
            }
        } else if (ctx->resp_chunk_phase == 2) { /* chunk 结尾 CRLF */
            if (avail - i < 2) {
                *consumed = i;
                return 0;
            }
            i += 2;
            ctx->resp_chunk_phase = 0;
        } else {                                  /* trailer 直到空行 */
            bool got_line = false;
            while (i < avail) {
                char ch = (char)p[i++];
                if (ctx->resp_line_len < sizeof ctx->resp_line) {
                    ctx->resp_line[ctx->resp_line_len++] = ch;
                }
                if (ctx->resp_line_len >= 2 && ch == '\n' &&
                    ctx->resp_line[ctx->resp_line_len - 2] == '\r') {
                    got_line = true;
                    break;
                }
            }
            if (!got_line) {
                *consumed = i;
                return 0;
            }
            bool empty = (ctx->resp_line_len == 2);
            ctx->resp_line_len = 0;
            if (empty) {
                *consumed = i;
                return 1;
            }
        }
    }
    *consumed = i;
    return 0;
}

int proxy_on_upstream_read(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL || c->upstream_fd < 0) {
        return 0;
    }

    /* 空闲复用的上游连接被对端关闭：丢弃它，等下一个请求重连 */
    if (!ctx->head_forwarded) {
        bool drained = false;
        bool eof = false;
        (void)fill_from_fd(c->upstream_fd, &c->up_in,
                           &r->stats.bytes_upstream_in, 4096, &drained, &eof);
        sh_buf_reset(&c->up_in);
        if (eof) {
            SH_LOGD("conn#%u 空闲上游连接被关闭，下一个请求将重连", c->id);
            proxy_upstream_close(r, c, false);
        }
        return 0;
    }

    if (c->upstream_paused) {
        return 0;                              /* 背压：等客户端把数据收走 */
    }

    bool drained = false;
    bool eof = false;
    ssize_t got = fill_from_fd(c->upstream_fd, &c->up_in,
                               &r->stats.bytes_upstream_in, PROXY_READ_LIMIT,
                               &drained, &eof);
    if (got > 0) {
        c->bytes_out += (uint64_t)got;
        c->last_active_ms = proxy_now_ms();
        ctx_touch(c, ctx);

        size_t avail = 0;
        const uint8_t *p = sh_buf_peek(&c->up_in, &avail);
        size_t consumed = 0;
        int fr = proxy_resp_frame(ctx, p, avail, &consumed);
        if (fr < 0) {
            SH_LOGW("conn#%u 上游响应畸形（分帧失败）", c->id);
            return -1;
        }
        if (consumed > 0) {
            if (c->crypto == SH_CRYPTO_READY) {
                if (sh_crypto_write(r, c, p, consumed) != 0) {
                    SH_LOGW("conn#%u 加密回写失败", c->id);
                    return -1;
                }
            } else if (sh_buf_append(&c->out, p, consumed) != consumed) {
                return -1;
            }
            sh_buf_consume(&c->up_in, consumed);
            ctx->resp_bytes += consumed;
            r->stats.bytes_client_out += consumed;
            c->bytes_out += 0;                 /* 已计入 */
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
        if (fr == 1) {
            ctx->resp_complete = true;
        }
    }

    proxy_apply_backpressure(r, c);

    /* ---- 响应收满：转发完毕、清状态、socket 保持开启 ---- */
    if (ctx->resp_complete) {
        ctx->served++;
        SH_LOGD("conn#%u 响应分帧完成：status=%d 共 %llu 字节，"
                "keep_alive=%d upstream_keep_alive=%d",
                c->id, ctx->resp_status,
                (unsigned long long)ctx->resp_bytes, (int)ctx->keep_alive,
                (int)ctx->resp_keep_alive);

        bool can_reuse_upstream = ctx->resp_keep_alive && c->upstream_fd >= 0 &&
                                  sh_buf_readable(&c->up_out) == 0;
        proxy_resp_state_reset(ctx);
        ctx->head_forwarded = false;
        ctx->up_shut_wr = false;
        ctx->upstream_eof = false;
        memset(&ctx->request, 0, sizeof ctx->request);

        if (ctx->keep_alive && !ctx->client_eof) {
            if (can_reuse_upstream) {
                /* 上游连接保持：回到 STREAMING 空闲态等下一个请求 */
                sh_buf_reset(&c->up_in);
                ctx->up_state = PROXY_UP_STREAMING;
                c->state = SH_CONN_ACTIVE;
                (void)sh_conn_want_upstream(r, c, true, false);
            } else {
                proxy_upstream_close(r, c, false);
                sh_buf_reset(&c->up_in);
                ctx->up_state = PROXY_UP_IDLE;
                c->state = SH_CONN_ACTIVE;
            }
            (void)sh_conn_want(r, c, true, false);
            /* 客户端可能已经把下一个请求发过来了 */
            if (sh_buf_readable(&ctx->plain_buf) > 0 &&
                sh_buf_readable(&c->out) == 0) {
                return proxy_handle_plain(r, c, &ctx->plain_buf);
            }
            return 0;
        }
        /* 客户端不复用：关上游，客户端侧等缓冲写完再关 */
        proxy_upstream_close(r, c, false);
        return sh_buf_readable(&c->out) == 0 ? 1 : 0;
    }

    if (eof) {
        /* 上游提前关闭 */
        if (ctx->resp_body_left == UINT64_MAX && ctx->resp_head_done) {
            /* close-delimited：EOF 即响应结束 */
            ctx->resp_complete = true;
            ctx->resp_body_left = 0;
            SH_LOGD("conn#%u 上游 close-delimited 响应结束（%llu 字节）", c->id,
                    (unsigned long long)ctx->resp_bytes);
            proxy_upstream_close(r, c, true);
            if (ctx->keep_alive && !ctx->client_eof &&
                sh_buf_readable(&c->out) == 0) {
                proxy_reset_request(r, c, ctx);
                return 0;
            }
            return sh_buf_readable(&c->out) == 0 ? 1 : 0;
        }
        SH_LOGW("conn#%u 上游提前关闭（已收 %llu 字节，body 剩余 %llu）", c->id,
                (unsigned long long)ctx->resp_bytes,
                (unsigned long long)ctx->resp_body_left);
        proxy_upstream_close(r, c, true);
        return 1;
    }

    /* ET：命中单次读取上限时内核里还有数据，重新 arm */
    if (!drained && !c->upstream_paused) {
        (void)sh_conn_rearm(r, c, true);
    }
    return 0;
}

int proxy_on_upstream_write(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL || c->upstream_fd < 0) {
        return 0;
    }
    if (ctx->up_state == PROXY_UP_DIALING) {
        int done = sh_net_connect_result(c->upstream_fd);
        if (done < 0) {
            SH_LOGW("conn#%u 上游连接失败: %s", c->id, strerror(errno));
            proxy_upstream_close(r, c, false);
            (void)send_plain_response(r, c, 502, "Bad Gateway");
            r->stats.upstream_connect_failed++;
            return 1;
        }
        ctx->up_state = PROXY_UP_CONNECTED;
        c->state = SH_CONN_UPSTREAM_ACTIVE;
        SH_LOGD("conn#%u 上游已连接", c->id);
    }
    if (proxy_upstream_start(r, c) != 0) {
        /* 连上但发不出去（对端 RST/半关闭）：明确回 502，而不是静默断连 */
        SH_LOGW("conn#%u 上游请求发送失败，回 502", c->id);
        proxy_upstream_close(r, c, false);
        (void)send_plain_response(r, c, 502, "Bad Gateway");
        r->stats.upstream_connect_failed++;
        return 1;
    }
    if (ctx->client_eof && !ctx->up_shut_wr && c->upstream_fd >= 0 &&
        sh_buf_readable(&c->up_out) == 0) {
        if (shutdown(c->upstream_fd, SHUT_WR) == 0) {
            ctx->up_shut_wr = true;
        }
    }
    proxy_apply_backpressure(r, c);
    return 0;
}

/* ==========================================================================
 * tick / close
 * ========================================================================== */
int proxy_on_tick(sh_reactor *r, sh_conn *c)
{
    if (sh_crypto_tick(r, c) != 0) {
        return -1;
    }
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL) {
        return 0;
    }
    uint64_t now = c->last_active_ms;

    /* 非阻塞 connect 超时 */
    if (ctx->up_state == PROXY_UP_DIALING && ctx->upstream_deadline_ms != 0 &&
        now > ctx->upstream_deadline_ms) {
        SH_LOGW("conn#%u 上游连接超时", c->id);
        return -1;
    }
    /* 上游 IO 空闲超时（连上后长时间无数据） */
    if (c->upstream_fd >= 0 && ctx->last_io_ms != 0 &&
        now > ctx->last_io_ms + SH_UPSTREAM_IO_TIMEOUT_MS) {
        SH_LOGW("conn#%u 上游 IO 空闲超时（%u ms）", c->id,
                (unsigned)SH_UPSTREAM_IO_TIMEOUT_MS);
        r->stats.timeouts++;
        return -1;
    }
    return 0;
}

void proxy_on_close(sh_reactor *r, sh_conn *c)
{
    proxy_ctx *ctx = ctx_of(c);
    if (ctx == NULL) {
        return;
    }
    if (c->upstream_fd >= 0) {
        proxy_upstream_close(r, c, false);
    }
    sh_buf_free(&ctx->plain_buf);
    free(ctx);
    c->user = NULL;
}

const sh_conn_hooks sh_proxy_hooks = {
    .name = "proxy",
    .on_client_read = proxy_on_client_read,
    .on_client_write = proxy_on_client_write,
    .on_upstream_read = proxy_on_upstream_read,
    .on_upstream_write = proxy_on_upstream_write,
    .on_tick = proxy_on_tick,
    .on_close = proxy_on_close,
};

#endif /* SH_MODE_PROXY */
