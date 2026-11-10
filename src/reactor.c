// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 自建 epoll 边缘触发(ET) reactor
 *
 * 为什么不用 libs2s 自带的 reactor：
 *   1. 库内 reactor 是水平触发（EPOLLIN|EPOLLRDHUP，无 EPOLLET）；
 *   2. 它只暴露一个 listen_fd，无法同时听 80/443；
 *   3. 它不提供"把任意 fd 注册进事件循环"的接口，Proxy 模式的上游
 *      连接无法挂进来。
 * 因此本文件自建 ET 事件循环，只复用 libs2s 的 handshake/session/ring/
 * secure_mem 与 KEM worker pool（见 src/neura_conn.c）。
 *
 * ET 的三条铁律（本文件的实现约束）：
 *   A. 可读事件必须一次读到 EAGAIN，可写事件必须一次写到 EAGAIN；
 *   B. fd 一律 SOCK_NONBLOCK，且只在 EPOLL_CTL_MOD 里增删 EPOLLOUT；
 *   C. 连接释放延迟到"本批事件处理完"之后（sweep），避免遍历 events[]
 *      时 free 造成 UAF。
 *
 * KEM 回调映射：
 *   worker 完成后写 eventfd，epoll 唤醒主循环，
 *   reactor_drain_kem() 取回 job 列表，用 job->conn_id 在 id_map 中找回
 *   连接（id 单调递增、不复用；查找 O(1)），再按 phase 分发到
 *   sh_neura_kem_done()（握手）或 sh_neura_ratchet_apply()（棘轮）。
 *   epoll data 里只放 (id<<8 | kind)，不放裸指针，避免连接回收后误投。
 */
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "network.h"
#include "security.h"

#include "neura/s2s_handshake.h"
#include "neura/s2s_reactor.h"

#define SH_EP_KIND_CLIENT   1u
#define SH_EP_KIND_LISTEN   2u
#define SH_EP_KIND_KEM      3u
#define SH_EP_KIND_WAKE     4u
#define SH_EP_KIND_UPSTREAM 5u

#define SH_EP_TAG(id, kind) (((uint64_t)(id) << 8) | (uint64_t)(kind))
#define SH_EP_KIND(tag)     ((uint32_t)((tag) & 0xFFu))
#define SH_EP_ID(tag)       ((uint32_t)((tag) >> 8))

#define SH_TOMBSTONE ((sh_conn *)(uintptr_t)0x1)

/* 全进程唯一的退出标志（定义在此，声明在 include/network.h）。
 * 信号处理函数只做 g_stop = 1 + write(wake_fd)，其它一律不碰。 */
volatile sig_atomic_t g_stop = 0;

static uint64_t reactor_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

/* ==========================================================================
 * 1. 缓冲区
 * ========================================================================== */
int sh_buf_init(sh_buf *b, size_t cap)
{
    if (b == NULL) {
        return -1;
    }
    memset(b, 0, sizeof *b);
    if (cap == 0) {
        return 0;
    }
    b->data = malloc(cap);
    if (b->data == NULL) {
        return -1;
    }
    b->cap = cap;
    return 0;
}

void sh_buf_free(sh_buf *b)
{
    if (b == NULL) {
        return;
    }
    free(b->data);
    memset(b, 0, sizeof *b);
}

void sh_buf_reset(sh_buf *b)
{
    if (b != NULL) {
        b->rpos = 0;
        b->wpos = 0;
    }
}

size_t sh_buf_readable(const sh_buf *b)
{
    return b != NULL ? b->wpos - b->rpos : 0;
}

size_t sh_buf_writable(const sh_buf *b)
{
    return b != NULL ? b->cap - b->wpos : 0;
}

bool sh_buf_empty(const sh_buf *b)
{
    return sh_buf_readable(b) == 0;
}

void sh_buf_compact(sh_buf *b)
{
    if (b == NULL || b->rpos == 0) {
        return;
    }
    size_t n = b->wpos - b->rpos;
    if (n > 0) {
        memmove(b->data, b->data + b->rpos, n);
    }
    b->rpos = 0;
    b->wpos = n;
}

int sh_buf_reserve(sh_buf *b, size_t need)
{
    if (b == NULL) {
        return -1;
    }
    if (sh_buf_writable(b) >= need) {
        return 0;
    }
    sh_buf_compact(b);
    if (sh_buf_writable(b) >= need) {
        return 0;
    }
    size_t want = b->wpos + need;
    size_t cap = b->cap > 0 ? b->cap : 1024u;
    while (cap < want) {
        if (cap > (1u << 30)) {
            return -1;    /* 硬上限 1 GiB，防内存放大 */
        }
        cap *= 2u;
    }
    uint8_t *p = realloc(b->data, cap);
    if (p == NULL) {
        return -1;
    }
    b->data = p;
    b->cap = cap;
    return 0;
}

size_t sh_buf_append(sh_buf *b, const void *src, size_t len)
{
    if (b == NULL || (src == NULL && len > 0)) {
        return 0;
    }
    if (len == 0) {
        return 0;
    }
    if (sh_buf_reserve(b, len) != 0) {
        return 0;
    }
    memcpy(b->data + b->wpos, src, len);
    b->wpos += len;
    return len;
}

size_t sh_buf_append_str(sh_buf *b, const char *s)
{
    return (b != NULL && s != NULL) ? sh_buf_append(b, s, strlen(s)) : 0;
}

size_t sh_buf_appendf(sh_buf *b, const char *fmt, ...)
{
    if (b == NULL || fmt == NULL) {
        return 0;
    }
    char stack_buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stack_buf, sizeof stack_buf, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return 0;
    }
    if ((size_t)n < sizeof stack_buf) {
        return sh_buf_append(b, stack_buf, (size_t)n);
    }
    if (sh_buf_reserve(b, (size_t)n + 1u) != 0) {
        return 0;
    }
    va_start(ap, fmt);
    int n2 = vsnprintf((char *)b->data + b->wpos, b->cap - b->wpos, fmt, ap);
    va_end(ap);
    if (n2 < 0) {
        return 0;
    }
    b->wpos += (size_t)n2;
    return (size_t)n2;
}

const uint8_t *sh_buf_peek(const sh_buf *b, size_t *len)
{
    if (b == NULL || b->data == NULL) {
        if (len != NULL) {
            *len = 0;
        }
        return NULL;
    }
    if (len != NULL) {
        *len = b->wpos - b->rpos;
    }
    return b->data + b->rpos;
}

void sh_buf_consume(sh_buf *b, size_t n)
{
    if (b == NULL) {
        return;
    }
    if (n >= b->wpos - b->rpos) {
        b->rpos = 0;
        b->wpos = 0;
        return;
    }
    b->rpos += n;
    if (b->rpos == b->wpos) {
        b->rpos = 0;
        b->wpos = 0;
    }
}

/* ==========================================================================
 * 2. 地址
 * ========================================================================== */
const char *sh_addr_ip(const sh_addr *a, char *out, size_t cap)
{
    if (a == NULL || out == NULL || cap == 0) {
        return NULL;
    }
    out[0] = '\0';
    if (a->ss.ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)&a->ss;
        if (inet_ntop(AF_INET, &v4->sin_addr, out, (socklen_t)cap) == NULL) {
            out[0] = '\0';
        }
    } else if (a->ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&a->ss;
        if (inet_ntop(AF_INET6, &v6->sin6_addr, out, (socklen_t)cap) == NULL) {
            out[0] = '\0';
        }
    }
    return out;
}

uint16_t sh_addr_port(const sh_addr *a)
{
    if (a == NULL) {
        return 0;
    }
    if (a->ss.ss_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)&a->ss)->sin_port);
    }
    if (a->ss.ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&a->ss)->sin6_port);
    }
    return 0;
}

int sh_addr_from_string(sh_addr *a, const char *host, uint16_t port)
{
    if (a == NULL || host == NULL) {
        return -1;
    }
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    memset(a, 0, sizeof *a);
    memcpy(&a->ss, res->ai_addr, res->ai_addrlen);
    a->len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

bool sh_addr_equal(const sh_addr *a, const sh_addr *b)
{
    if (a == NULL || b == NULL || a->ss.ss_family != b->ss.ss_family) {
        return false;
    }
    if (a->ss.ss_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)&a->ss;
        const struct sockaddr_in *y = (const struct sockaddr_in *)&b->ss;
        return x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)&a->ss;
        const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)&b->ss;
        return memcmp(&x->sin6_addr, &y->sin6_addr, sizeof x->sin6_addr) == 0;
    }
    return false;
}

uint32_t sh_addr_hash(const sh_addr *a)
{
    if (a == NULL) {
        return 0;
    }
    uint32_t h = 2166136261u;
    if (a->ss.ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)&a->ss;
        const uint8_t *p = (const uint8_t *)&v4->sin_addr;
        for (size_t i = 0; i < sizeof v4->sin_addr; i++) {
            h = (h ^ p[i]) * 16777619u;
        }
    } else if (a->ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&a->ss;
        const uint8_t *p = (const uint8_t *)&v6->sin6_addr;
        for (size_t i = 0; i < sizeof v6->sin6_addr; i++) {
            h = (h ^ p[i]) * 16777619u;
        }
    }
    return h != 0 ? h : 1u;
}

bool sh_addr_is_loopback(const sh_addr *a)
{
    if (a == NULL) {
        return false;
    }
    if (a->ss.ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)&a->ss;
        return (ntohl(v4->sin_addr.s_addr) >> 24) == 127u;
    }
    if (a->ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&a->ss;
        return IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr) ||
               IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr);
    }
    return false;
}

/* ==========================================================================
 * 3. 定时器（按 expire_ms 升序的单链表）
 * ========================================================================== */
static void timer_unlink(sh_reactor *r, sh_timer *t)
{
    sh_timer **pp = &r->timers;
    while (*pp != NULL) {
        if (*pp == t) {
            *pp = t->next;
            t->next = NULL;
            t->armed = false;
            return;
        }
        pp = &(*pp)->next;
    }
}

int sh_reactor_timer_add(sh_reactor *r, sh_timer *t, uint32_t delay_ms,
                         sh_timer_cb cb, void *arg)
{
    if (r == NULL || t == NULL || cb == NULL) {
        return -1;
    }
    if (t->armed) {
        timer_unlink(r, t);
    }
    t->cb = cb;
    t->arg = arg;
    t->expire_ms = reactor_now_ms() + delay_ms;
    t->armed = true;

    sh_timer **pp = &r->timers;
    while (*pp != NULL && (*pp)->expire_ms <= t->expire_ms) {
        pp = &(*pp)->next;
    }
    t->next = *pp;
    *pp = t;
    return 0;
}

int sh_reactor_timer_arm(sh_reactor *r, sh_timer *t, uint32_t delay_ms)
{
    if (r == NULL || t == NULL || t->cb == NULL) {
        return -1;
    }
    return sh_reactor_timer_add(r, t, delay_ms, t->cb, t->arg);
}

void sh_reactor_timer_cancel(sh_reactor *r, sh_timer *t)
{
    if (r == NULL || t == NULL || !t->armed) {
        return;
    }
    timer_unlink(r, t);
}

size_t sh_reactor_timer_run(sh_reactor *r, uint64_t now_ms)
{
    if (r == NULL) {
        return 0;
    }
    size_t fired = 0;
    while (r->timers != NULL && r->timers->expire_ms <= now_ms) {
        sh_timer *t = r->timers;
        r->timers = t->next;
        t->next = NULL;
        t->armed = false;
        if (t->cb != NULL) {
            t->cb(r, t, t->arg);
        }
        fired++;
        if (fired > 10000u) {
            break;    /* 防御：回调里不断重新 arm 导致死循环 */
        }
    }
    return fired;
}

/* ==========================================================================
 * 4. socket 辅助
 * ========================================================================== */
static int set_flag(int fd, int level, int name, bool enable)
{
    int v = enable ? 1 : 0;
    return setsockopt(fd, level, name, &v, sizeof v);
}

int sh_net_set_nonblocking(int fd, bool enable)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags);
}

int sh_net_set_cloexec(int fd, bool enable)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) {
        return -1;
    }
    flags = enable ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC);
    return fcntl(fd, F_SETFD, flags);
}

int sh_net_set_nodelay(int fd, bool enable)
{
    return set_flag(fd, IPPROTO_TCP, TCP_NODELAY, enable);
}

int sh_net_set_keepalive(int fd, bool enable, int idle_s, int interval_s,
                         int probes)
{
    if (set_flag(fd, SOL_SOCKET, SO_KEEPALIVE, enable) != 0) {
        return -1;
    }
    if (!enable) {
        return 0;
    }
    int v = idle_s;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof v) != 0) {
        return -1;
    }
    v = interval_s;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof v) != 0) {
        return -1;
    }
    v = probes;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &v, sizeof v) != 0) {
        return -1;
    }
    return 0;
}

int sh_net_set_reuseaddr(int fd, bool enable)
{
    return set_flag(fd, SOL_SOCKET, SO_REUSEADDR, enable);
}

int sh_net_set_reuseport(int fd, bool enable)
{
#ifdef SO_REUSEPORT
    return set_flag(fd, SOL_SOCKET, SO_REUSEPORT, enable);
#else
    (void)fd;
    (void)enable;
    return 0;
#endif
}

int sh_net_set_recvbuf(int fd, int bytes)
{
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
}

int sh_net_set_sendbuf(int fd, int bytes)
{
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes);
}

int sh_net_listen(const char *host, uint16_t port, int backlog)
{
    /* port == 0 合法：由内核分配临时端口（测试/多实例） */
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
                    ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)sh_net_set_cloexec(fd, true);
        (void)sh_net_set_nonblocking(fd, true);
        /* SO_REUSEADDR 处理 TIME_WAIT；SO_REUSEPORT 让多 worker/多进程
         * 可以各自 bind 同一地址，由内核做四元组哈希分流。二者都必须在
         * bind() 之前设置，否则第二个进程会 EADDRINUSE。 */
        (void)sh_net_set_reuseaddr(fd, true);
        (void)sh_net_set_reuseport(fd, true);
#ifdef IPV6_V6ONLY
        if (ai->ai_family == AF_INET6) {
            int off = 0;
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
        }
#endif
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
            listen(fd, backlog) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int sh_net_accept(int listen_fd, sh_addr *peer)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    int fd = accept4(listen_fd, (struct sockaddr *)&ss, &slen,
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (peer != NULL) {
        memset(peer, 0, sizeof *peer);
        memcpy(&peer->ss, &ss, sizeof ss);
        peer->len = slen;
    }
    return fd;
}

int sh_net_connect(const char *host, uint16_t port, bool *in_progress)
{
    if (in_progress != NULL) {
        *in_progress = false;
    }
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            if (in_progress != NULL) {
                *in_progress = false;
            }
            break;
        }
        if (errno == EINPROGRESS || errno == EALREADY) {
            if (in_progress != NULL) {
                *in_progress = true;
            }
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int sh_net_connect_result(int fd)
{
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        return -1;
    }
    if (err != 0) {
        errno = err;
        return -1;
    }
    return 1;
}

/* ==========================================================================
 * 5. id -> conn 映射（open addressing + tombstone）
 * ========================================================================== */
static int id_map_init(sh_reactor *r, size_t cap)
{
    size_t want = 64;
    while (want < cap * 2u) {
        want *= 2u;
    }
    r->id_map = calloc(want, sizeof *r->id_map);
    if (r->id_map == NULL) {
        return -1;
    }
    r->id_map_cap = want;
    r->id_map_used = 0;
    return 0;
}

static size_t id_slot(const sh_reactor *r, uint32_t id)
{
    return ((size_t)id * 2654435761u) & (r->id_map_cap - 1u);
}

static void id_map_put(sh_reactor *r, sh_conn *c)
{
    if (r->id_map == NULL || r->id_map_cap == 0) {
        return;
    }
    size_t i = id_slot(r, c->id);
    for (size_t n = 0; n < r->id_map_cap; n++) {
        sh_conn *slot = r->id_map[i];
        if (slot == NULL || slot == SH_TOMBSTONE) {
            r->id_map[i] = c;
            r->id_map_used++;
            return;
        }
        i = (i + 1u) & (r->id_map_cap - 1u);
    }
}

static sh_conn *id_map_get(const sh_reactor *r, uint32_t id)
{
    if (r->id_map == NULL || r->id_map_cap == 0 || id == 0) {
        return NULL;
    }
    size_t i = id_slot(r, id);
    for (size_t n = 0; n < r->id_map_cap; n++) {
        sh_conn *c = r->id_map[i];
        if (c == NULL) {
            return NULL;
        }
        if (c != SH_TOMBSTONE && c->id == id) {
            return c;
        }
        i = (i + 1u) & (r->id_map_cap - 1u);
    }
    return NULL;
}

static void id_map_del(sh_reactor *r, uint32_t id)
{
    if (r->id_map == NULL || r->id_map_cap == 0) {
        return;
    }
    size_t i = id_slot(r, id);
    for (size_t n = 0; n < r->id_map_cap; n++) {
        sh_conn *c = r->id_map[i];
        if (c == NULL) {
            return;
        }
        if (c != SH_TOMBSTONE && c->id == id) {
            r->id_map[i] = SH_TOMBSTONE;
            return;
        }
        i = (i + 1u) & (r->id_map_cap - 1u);
    }
}

/* ==========================================================================
 * 6. 连接生命周期
 * ========================================================================== */
static void conn_list_unlink(sh_reactor *r, sh_conn *c)
{
    if (c->prev_all != NULL) {
        c->prev_all->next_all = c->next_all;
    } else {
        r->all_head = c->next_all;
    }
    if (c->next_all != NULL) {
        c->next_all->prev_all = c->prev_all;
    }
    c->prev_all = NULL;
    c->next_all = NULL;
}

static void conn_list_push(sh_reactor *r, sh_conn *c)
{
    c->prev_all = NULL;
    c->next_all = r->all_head;
    if (r->all_head != NULL) {
        r->all_head->prev_all = c;
    }
    r->all_head = c;
}

sh_conn *sh_conn_acquire(sh_reactor *r, int fd, const sh_addr *peer)
{
    if (r == NULL || fd < 0) {
        return NULL;
    }
    sh_conn *c = r->free_head;
    if (c != NULL) {
        r->free_head = c->next_free;
        memset(c, 0, sizeof *c);
    } else {
        c = calloc(1, sizeof *c);
        if (c == NULL) {
            return NULL;
        }
        r->conn_capacity++;
    }
    c->fd = fd;
    c->upstream_fd = -1;
    c->id = ++r->next_conn_id;
    if (c->id == 0) {
        c->id = ++r->next_conn_id;
    }
    c->state = SH_CONN_ACCEPTED;
    c->crypto = SH_CRYPTO_PLAIN;
    c->epoll_events = 0;
    c->upstream_events = 0;
    c->accepted_ms = reactor_now_ms();
    c->last_active_ms = c->accepted_ms;
    c->idle_timer.name = "idle";
    c->handshake_timer.name = "handshake";
    c->ratchet_timer.name = "ratchet";
    if (peer != NULL) {
        c->peer = *peer;
    }
    sh_addr_ip(&c->peer, c->ip_str, sizeof c->ip_str);
    c->ip_hash = sh_addr_hash(&c->peer);

    if (sh_buf_init(&c->in, SH_PREAUTH_CAP) != 0 ||
        sh_buf_init(&c->out, SH_PREAUTH_CAP) != 0) {
        sh_buf_free(&c->in);
        sh_buf_free(&c->out);
        free(c);
        r->conn_capacity--;
        return NULL;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    ev.data.u64 = SH_EP_TAG(c->id, SH_EP_KIND_CLIENT);
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        sh_buf_free(&c->in);
        sh_buf_free(&c->out);
        free(c);
        r->conn_capacity--;
        return NULL;
    }
    c->epoll_events = ev.events;
    c->hooks = r->hooks;
    id_map_put(r, c);
    conn_list_push(r, c);
    r->conn_count++;
    r->stats.conns_accepted++;
    r->stats.active_conns = r->conn_count;
    if (r->conn_count > r->stats.peak_conns) {
        r->stats.peak_conns = r->conn_count;
    }
    return c;
}

void sh_conn_release(sh_reactor *r, sh_conn *c)
{
    if (r == NULL || c == NULL || c->fd < 0) {
        return;
    }
    if (c->hooks != NULL && c->hooks->on_close != NULL) {
        c->hooks->on_close(r, c);
    }
    sh_crypto_close(r, c);

    sh_reactor_timer_cancel(r, &c->idle_timer);
    sh_reactor_timer_cancel(r, &c->handshake_timer);
    sh_reactor_timer_cancel(r, &c->ratchet_timer);

    epoll_ctl(r->epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    if (c->upstream_fd >= 0) {
        epoll_ctl(r->epfd, EPOLL_CTL_DEL, c->upstream_fd, NULL);
        close(c->upstream_fd);
        c->upstream_fd = -1;
    }
    id_map_del(r, c->id);

    sh_buf_free(&c->in);
    sh_buf_free(&c->out);
    sh_buf_free(&c->up_in);
    sh_buf_free(&c->up_out);

    conn_list_unlink(r, c);
    if (r->conn_count > 0) {
        r->conn_count--;
    }
    r->stats.conns_closed++;
    r->stats.active_conns = r->conn_count;

    c->fd = -1;
    c->state = SH_CONN_FREE;
    c->next_free = r->free_head;
    r->free_head = c;
}

int sh_conn_close(sh_reactor *r, sh_conn *c, bool graceful)
{
    if (r == NULL || c == NULL || c->fd < 0) {
        return -1;
    }
    if (graceful && sh_buf_readable(&c->out) > 0) {
        (void)sh_conn_flush(r, c, c->fd, &c->out);
    }
    if (!graceful) {
        struct linger lg;
        lg.l_onoff = 1;
        lg.l_linger = 0;
        (void)setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    }
    c->state = SH_CONN_CLOSING;
    return 0;
}

void sh_conn_drop(sh_reactor *r, sh_conn *c)
{
    if (r == NULL || c == NULL) {
        return;
    }
    (void)sh_conn_close(r, c, false);
    r->stats.waf_dropped++;
}

int sh_conn_want(sh_reactor *r, sh_conn *c, bool want_read, bool want_write)
{
    (void)want_read;    /* ET 下始终订阅 EPOLLIN */
    if (r == NULL || c == NULL || c->fd < 0) {
        return -1;
    }
    uint32_t ev = EPOLLIN | EPOLLRDHUP | EPOLLET;
    if (want_write || sh_buf_readable(&c->out) > 0) {
        ev |= EPOLLOUT;
    }
    if (ev == c->epoll_events) {
        return 0;
    }
    struct epoll_event e;
    memset(&e, 0, sizeof e);
    e.events = ev;
    e.data.u64 = SH_EP_TAG(c->id, SH_EP_KIND_CLIENT);
    if (epoll_ctl(r->epfd, EPOLL_CTL_MOD, c->fd, &e) != 0) {
        return -1;
    }
    c->epoll_events = ev;
    return 0;
}

int sh_conn_want_upstream(sh_reactor *r, sh_conn *c,
                          bool want_read, bool want_write)
{
    (void)want_read;
    if (r == NULL || c == NULL || c->upstream_fd < 0) {
        return -1;
    }
    uint32_t ev = EPOLLIN | EPOLLRDHUP | EPOLLET;
    if (want_write || sh_buf_readable(&c->up_out) > 0) {
        ev |= EPOLLOUT;
    }
    struct epoll_event e;
    memset(&e, 0, sizeof e);
    e.events = ev;
    e.data.u64 = SH_EP_TAG(c->id, SH_EP_KIND_UPSTREAM);
    int op = c->upstream_events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(r->epfd, op, c->upstream_fd, &e) != 0) {
        return -1;
    }
    c->upstream_events = ev;
    return 0;
}

int sh_conn_rearm(sh_reactor *r, sh_conn *c, bool upstream)
{
    if (r == NULL || c == NULL) {
        return -1;
    }
    struct epoll_event e;
    memset(&e, 0, sizeof e);
    if (upstream) {
        if (c->upstream_fd < 0) {
            return -1;
        }
        e.events = c->upstream_events != 0
                       ? c->upstream_events
                       : (uint32_t)(EPOLLIN | EPOLLRDHUP | EPOLLET);
        if (sh_buf_readable(&c->up_out) > 0) {
            e.events |= EPOLLOUT;
        }
        e.data.u64 = SH_EP_TAG(c->id, SH_EP_KIND_UPSTREAM);
        if (epoll_ctl(r->epfd, EPOLL_CTL_MOD, c->upstream_fd, &e) != 0) {
            return -1;
        }
        c->upstream_events = e.events;
    } else {
        if (c->fd < 0) {
            return -1;
        }
        e.events = c->epoll_events != 0
                       ? c->epoll_events
                       : (uint32_t)(EPOLLIN | EPOLLRDHUP | EPOLLET);
        if (sh_buf_readable(&c->out) > 0) {
            e.events |= EPOLLOUT;
        }
        e.data.u64 = SH_EP_TAG(c->id, SH_EP_KIND_CLIENT);
        if (epoll_ctl(r->epfd, EPOLL_CTL_MOD, c->fd, &e) != 0) {
            return -1;
        }
        c->epoll_events = e.events;
    }
    return 0;
}

ssize_t sh_conn_flush(sh_reactor *r, sh_conn *c, int fd, sh_buf *b)
{
    (void)r;
    if (c == NULL || b == NULL || fd < 0) {
        return -1;
    }
    ssize_t total = 0;
    for (;;) {
        size_t n = sh_buf_readable(b);
        if (n == 0) {
            break;
        }
        /* MSG_NOSIGNAL：对端已关时返回 EPIPE 而不是进程被 SIGPIPE 杀掉 */
        ssize_t w = send(fd, b->data + b->rpos, n, MSG_NOSIGNAL);
        if (w > 0) {
            sh_buf_consume(b, (size_t)w);
            total += w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;    /* ET：写不动就挂 EPOLLOUT，数据保留 */
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w == 0) {
            break;
        }
        return -1;
    }
    return total;
}

/* ==========================================================================
 * 7. KEM 提交与完成映射
 * ========================================================================== */
/* 微秒级单调时钟（用于 KEM 唤醒延迟统计） */
static uint64_t reactor_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

int sh_reactor_kem_submit(sh_reactor *r, sh_conn *c, struct ns2s_kem_job *job)
{
    if (r == NULL || c == NULL || job == NULL || r->kem_pool == NULL) {
        return -1;
    }
    job->conn_id = c->id;
    job->completion_fd = r->kem_eventfd;
    /* 记录提交时刻：worker 完成 → eventfd 唤醒 → reactor_drain_kem()
     * 之间的差值就是「唤醒延迟」，用于验证是否存在固定睡眠/轮询 */
    int rc = ns2s_kem_pool_submit((ns2s_kem_pool *)r->kem_pool, job);
    return rc == NS2S_OK ? 0 : -1;
}

static bool is_ratchet_phase(ns2s_kem_phase phase)
{
    return phase == NS2S_KEM_PHASE_RATCHET_OFFER ||
           phase == NS2S_KEM_PHASE_RATCHET_ENC ||
           phase == NS2S_KEM_PHASE_RATCHET_DEC;
}

static void reactor_drain_kem(sh_reactor *r)
{
    if (r->kem_pool == NULL) {
        return;
    }
    ns2s_kem_job *jobs = NULL;
    ns2s_kem_pool_take_done((ns2s_kem_pool *)r->kem_pool, &jobs);
    while (jobs != NULL) {
        ns2s_kem_job *next = jobs->next;
        sh_conn *c = id_map_get(r, (uint32_t)jobs->conn_id);
        SH_LOGD("kem done: conn_id=%llu phase=%d status=%d map=%p",
                (unsigned long long)jobs->conn_id, (int)jobs->phase,
                jobs->status, (void *)c);
        if (c != NULL && c->neura != NULL) {
            uint64_t now = reactor_now_ms();
            int rc;
            if (is_ratchet_phase(jobs->phase)) {
                rc = sh_neura_ratchet_apply(c->neura, jobs, now, &c->out);
            } else {
                rc = sh_neura_kem_done(c->neura, jobs, now, &c->out);
            }
            if (rc != NS2S_OK) {
                SH_LOGW("conn#%u KEM 结果处理失败 rc=%d phase=%d", c->id, rc,
                        (int)jobs->phase);
                (void)sh_conn_close(r, c, false);
            } else {
                (void)sh_conn_flush(r, c, c->fd, &c->out);
                (void)sh_conn_want(r, c, true, false);
            }
        }
        ns2s_kem_job_destroy(jobs);
        free(jobs);
        jobs = next;
    }
}

/* ==========================================================================
 * 8. reactor 主体
 * ========================================================================== */
int sh_reactor_init(sh_reactor *r, const sh_settings *settings,
                    ncf_config *config, waf *w)
{
    if (r == NULL || settings == NULL) {
        return -1;
    }
    memset(r, 0, sizeof *r);
    /*
     * g_stop 是进程级退出标志（信号处理函数也会置位）。init 必须复位它，
     * 否则同一进程内第二次 sh_reactor_run() 会在入口处直接退出：
     * 客户端网关这类"逐请求重建 reactor"的嵌入方会表现为第一条请求正常、
     * 之后全部静默超时。
     */
    g_stop = 0;
    r->settings = *settings;
    r->config = config;
    r->waf = w;
    r->listen_fd = -1;
    r->listen_tls_fd = -1;
    r->kem_eventfd = -1;
    r->wake_fd = -1;

    r->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (r->epfd < 0) {
        return -1;
    }
    r->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (r->wake_fd < 0) {
        goto fail;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = SH_EP_TAG(0, SH_EP_KIND_WAKE);
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, r->wake_fd, &ev) != 0) {
        goto fail;
    }

    r->kem_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (r->kem_eventfd < 0) {
        goto fail;
    }
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = SH_EP_TAG(0, SH_EP_KIND_KEM);
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, r->kem_eventfd, &ev) != 0) {
        goto fail;
    }

    size_t workers = settings->kem_workers > 0 ? settings->kem_workers : SH_KEM_WORKERS;
    ns2s_kem_pool *pool = calloc(1, sizeof *pool);
    if (pool == NULL) {
        goto fail;
    }
    if (ns2s_kem_pool_init(pool, workers, r->kem_eventfd) != NS2S_OK) {
        free(pool);
        goto fail;
    }
    r->kem_pool = pool;

    if (id_map_init(r, settings->max_connections > 0 ? settings->max_connections
                                                     : SH_MAX_CONNECTIONS) != 0) {
        goto fail;
    }
    r->hooks = NULL;
    r->running = false;
    r->next_conn_id = 0;
    return 0;

fail:
    sh_reactor_destroy(r);
    return -1;
}

void sh_reactor_destroy(sh_reactor *r)
{
    if (r == NULL) {
        return;
    }
    /* 先释放活跃连接（timer 链表节点在 conn 内部，先取消） */
    sh_conn *c = r->all_head;
    while (c != NULL) {
        sh_conn *next = c->next_all;
        sh_reactor_timer_cancel(r, &c->idle_timer);
        sh_reactor_timer_cancel(r, &c->handshake_timer);
        sh_reactor_timer_cancel(r, &c->ratchet_timer);
        if (c->fd >= 0) {
            epoll_ctl(r->epfd, EPOLL_CTL_DEL, c->fd, NULL);
            close(c->fd);
        }
        if (c->upstream_fd >= 0) {
            epoll_ctl(r->epfd, EPOLL_CTL_DEL, c->upstream_fd, NULL);
            close(c->upstream_fd);
        }
        sh_crypto_close(r, c);
        sh_buf_free(&c->in);
        sh_buf_free(&c->out);
        sh_buf_free(&c->up_in);
        sh_buf_free(&c->up_out);
        free(c);
        c = next;
    }
    r->all_head = NULL;
    while (r->free_head != NULL) {
        sh_conn *n = r->free_head;
        r->free_head = n->next_free;
        free(n);
    }
    r->timers = NULL;
    if (r->listen_fd >= 0) {
        close(r->listen_fd);
        r->listen_fd = -1;
    }
    if (r->listen_tls_fd >= 0) {
        close(r->listen_tls_fd);
        r->listen_tls_fd = -1;
    }
    if (r->kem_pool != NULL) {
        ns2s_kem_pool_destroy((ns2s_kem_pool *)r->kem_pool);
        free(r->kem_pool);
        r->kem_pool = NULL;
    }
    if (r->kem_eventfd >= 0) {
        close(r->kem_eventfd);
        r->kem_eventfd = -1;
    }
    if (r->wake_fd >= 0) {
        close(r->wake_fd);
        r->wake_fd = -1;
    }
    if (r->epfd >= 0) {
        close(r->epfd);
        r->epfd = -1;
    }
    free(r->id_map);
    r->id_map = NULL;
    r->id_map_cap = 0;
    r->conn_count = 0;
}

/*
 * 监听槽位编码：epoll data.u64 = (slot << 8) | SH_EP_KIND_LISTEN。
 * slot 必须非 0（0 留给 eventfd），这样两路监听（主端口 / 443）能各自
 * 触发 reactor_accept_batch()，而不会把 data.fd 的裸值误当成 kind。
 */
#define SH_LISTEN_SLOT_MAIN 1u
#define SH_LISTEN_SLOT_TLS  2u

static int reactor_listen_one(sh_reactor *r, const char *host, uint16_t port,
                              uint32_t slot, const char *label)
{
    if (host == NULL || host[0] == '\0') {
        host = SH_DEFAULT_LISTEN_HOST;
    }
    int fd = sh_net_listen(host, port, SH_ACCEPT_BACKLOG);
    if (fd < 0) {
        SH_LOGE("listen(%s:%u %s) 失败: %s", host, (unsigned)port, label,
                strerror(errno));
        return -1;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    /* ET：accept 循环必须读到 EAGAIN（见 reactor_accept_batch） */
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    ev.data.u64 = SH_EP_TAG(slot, SH_EP_KIND_LISTEN);
    if (epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        SH_LOGE("epoll_ctl(ADD listen %s:%u) 失败: %s", host, (unsigned)port,
                strerror(errno));
        close(fd);
        return -1;
    }
    SH_LOGI("监听 %s:%u（%s, fd=%d, ET epoll）", host, (unsigned)port, label, fd);
    return fd;
}

int sh_reactor_listen(sh_reactor *r)
{
    if (r == NULL || r->epfd < 0) {
        return -1;
    }

    const char *host = r->settings.listen_host != NULL
                           ? r->settings.listen_host
                           : SH_DEFAULT_LISTEN_HOST;
    uint16_t port = r->settings.listen_port != 0
                        ? r->settings.listen_port
                        : SH_DEFAULT_LISTEN_PORT;

    r->listen_fd = reactor_listen_one(r, host, port, SH_LISTEN_SLOT_MAIN, "main");
    if (r->listen_fd < 0) {
        return -1;
    }

    /*
     * 第二监听口（443 / --listen-tls）：
     *   - 端口为 0 或与主端口相同则不重复绑定；
     *   - 绑定失败只告警，不影响主端口继续服务（例如宿主机 Nginx 已占用
     *     443，此时 Safe-HTTP 仍应在 80/主端口上可用）。
     */
    uint16_t tls_port = r->settings.listen_tls_port;
    if (tls_port != 0 && tls_port != port) {
        const char *tls_host = r->settings.listen_tls_host != NULL
                                   ? r->settings.listen_tls_host
                                   : host;
        r->listen_tls_fd = reactor_listen_one(r, tls_host, tls_port,
                                              SH_LISTEN_SLOT_TLS, "tls/443");
        if (r->listen_tls_fd < 0) {
            SH_LOGW("第二监听口 %s:%u 不可用，继续使用 %s:%u",
                    tls_host, (unsigned)tls_port, host, (unsigned)port);
        }
    }
    return 0;
}

uint16_t sh_reactor_port(const sh_reactor *r)
{
    if (r == NULL || r->listen_fd < 0) {
        return 0;
    }
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;
    if (getsockname(r->listen_fd, (struct sockaddr *)&ss, &len) != 0) {
        return 0;
    }
    if (ss.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return 0;
}

void sh_reactor_wakeup(sh_reactor *r)
{
    if (r == NULL || r->wake_fd < 0) {
        return;
    }
    uint64_t one = 1;
    ssize_t n = write(r->wake_fd, &one, sizeof one);
    (void)n;
}

void sh_reactor_stop(sh_reactor *r)
{
    /*
     * 先置全局退出标志：即使随后 wake_fd 写失败（或 eventfd 已被关闭），
     * 主循环下一轮（最长 SH_TIMER_TICK_MS）也必定能看到并退出，不会卡死。
     */
    g_stop = 1;
    if (r == NULL) {
        return;
    }
    r->running = false;
    sh_reactor_wakeup(r);
}

/*
 * ET 下 accept 必须一直取到 EAGAIN。SH_EPOLL_BATCH_ACCEPT 只是"防饥饿
 * 预算"：连接风暴时单条边沿不能把整个事件循环卡死；达到预算后对同一个
 * listen fd 做 EPOLL_CTL_MOD 重新 arm，内核会再次投递可读边沿，未处理
 * 的连接仍在 accept 队列里，绝不会丢失。
 */
static void reactor_accept_batch(sh_reactor *r, int listen_fd, uint32_t slot)
{
    if (r == NULL || listen_fd < 0) {
        return;
    }

    uint32_t accepted = 0;
    bool budget_hit = false;

    for (;;) {
        if (accepted >= SH_EPOLL_BATCH_ACCEPT) {
            budget_hit = true;
            break;
        }

        sh_addr peer;
        int fd = sh_net_accept(listen_fd, &peer);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;    /* 队列已空：ET 下正确的收尾 */
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EMFILE || errno == ENFILE) {
                /*
                 * fd 耗尽：不要继续空转。把事件留给下一轮，并打印一次
                 * 明确告警，便于运维直接调整 LimitNOFILE。
                 */
                SH_LOGE("accept: fd 耗尽（%s），暂停接受；请提高 LimitNOFILE",
                        strerror(errno));
                break;
            }
            if (errno == ECONNABORTED || errno == EPROTO) {
                continue;     /* 对端在握手前放弃，继续取下一个 */
            }
            SH_LOGW("accept: %s", strerror(errno));
            break;
        }

        (void)sh_net_set_nonblocking(fd, true);
        (void)sh_net_set_cloexec(fd, true);
        (void)sh_net_set_nodelay(fd, true);
        (void)sh_net_set_keepalive(fd, true, 60, 10, 3);

        sh_conn *c = sh_conn_acquire(r, fd, &peer);
        if (c == NULL) {
            close(fd);
            continue;         /* 内存/注册失败不应影响其它连接 */
        }
        accepted++;
        SH_LOGD("conn#%u accepted from %s:%u (listen=%s)", c->id, c->ip_str,
                (unsigned)sh_addr_port(&peer),
                slot == SH_LISTEN_SLOT_TLS ? "443" : "main");
    }

    if (budget_hit) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof ev);
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
        ev.data.u64 = SH_EP_TAG(slot, SH_EP_KIND_LISTEN);
        /* MOD 会让内核重新评估就绪状态，等价于重新投递一次边沿 */
        (void)epoll_ctl(r->epfd, EPOLL_CTL_MOD, listen_fd, &ev);
        SH_LOGD("accept 达到单轮预算 %u，已重新 arm listen fd=%d",
                (unsigned)SH_EPOLL_BATCH_ACCEPT, listen_fd);
    }
}

static void conn_on_event(sh_reactor *r, sh_conn *c, uint32_t events,
                          bool upstream)
{
    const sh_conn_hooks *h = c->hooks;
    int rc = 0;
    bool err_ev = (events & EPOLLERR) != 0;

    SH_LOGD("conn#%u event=%#x upstream=%d state=%d crypto=%d", c->id, events,
            (int)upstream, (int)c->state, (int)c->crypto);
    if (h == NULL) {
        if (err_ev || (events & EPOLLHUP)) {
            (void)sh_conn_close(r, c, false);
        }
        return;
    }

    /*
     * 上游「非阻塞 connect 失败」会以 EPOLLERR 直接投递：必须先把控制权
     * 交给模式钩子，否则客户端只会看到静默断连而不是 502。
     * 用 c->state 区分是否仍在 connecting 阶段。
     */
    if (upstream && err_ev && c->state == SH_CONN_UPSTREAM_CONNECT &&
        h->on_upstream_write != NULL) {
        int hrc = h->on_upstream_write(r, c);
        if (hrc == 0) {
            return;
        }
        (void)sh_conn_close(r, c, hrc > 0);   /* >0：先冲净错误响应 */
        return;
    }
    if (err_ev) {
        int err = 0;
        socklen_t len = sizeof err;
        int fd = upstream ? c->upstream_fd : c->fd;
        if (fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 &&
            err != 0) {
            SH_LOGD("conn#%u fd=%d 事件错误: %s", c->id, fd, strerror(err));
        }
    }

    /* 1) 可写优先：先把缓冲推出去（非阻塞 connect 完成也由 EPOLLOUT 体现） */
    if (events & EPOLLOUT) {
        rc = upstream ? (h->on_upstream_write ? h->on_upstream_write(r, c) : 0)
                      : (h->on_client_write ? h->on_client_write(r, c) : 0);
    }
    /*
     * 2) 可读 / 对端关闭：ET 下必须先把内核里的数据读干净。
     *    EPOLLHUP/EPOLLRDHUP 与 EPOLLIN 常常在同一次事件里到达，
     *    若像旧实现那样先判 HUP 直接 close，就会丢掉对端"回完即关"
     *    场景下的最后一个响应包（表现为客户端收到 0 字节 / 半截响应）。
     */
    if (rc == 0 && (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))) {
        rc = upstream ? (h->on_upstream_read ? h->on_upstream_read(r, c) : 0)
                      : (h->on_client_read ? h->on_client_read(r, c) : 0);
    }
    /* 3) 硬错误且钩子没给出结论 → 关闭 */
    if (rc == 0 && err_ev) {
        rc = -1;
    }
    if (rc != 0) {
        (void)sh_conn_close(r, c, rc > 0);
    }
}

int sh_reactor_run(sh_reactor *r)
{
    if (r == NULL || r->epfd < 0) {
        return -1;
    }
    r->running = true;
    struct epoll_event events[SH_MAX_EVENTS];

    while (r->running) {
        /* 检查点 1/3：每轮开始先看全局退出标志（信号可能在任意时刻到达，
         * 甚至在 sh_reactor_run 把 running 置 true 之前，因此不能只靠
         * r->running，否则会出现"stop 先到、循环后开"的永久卡死）。 */
        if (g_stop != 0) {
            SH_LOGI("检测到退出标志 g_stop，退出事件循环");
            r->running = false;
            break;
        }
        uint64_t now = reactor_now_ms();
        int timeout = (int)SH_TIMER_TICK_MS;
        if (r->timers != NULL && r->timers->expire_ms > now) {
            uint64_t delta = r->timers->expire_ms - now;
            if (delta < (uint64_t)timeout) {
                timeout = (int)delta;
            }
        } else if (r->timers != NULL) {
            timeout = 0;
        }

        int n = epoll_wait(r->epfd, events, SH_MAX_EVENTS, timeout);
        if (n < 0) {
            if (errno == EINTR) {
                /*
                 * 检查点 2/3：epoll_wait 被信号打断。
                 * 旧实现无条件 continue → 若信号处理函数只是置标志/写 eventfd
                 * 而未让 r->running 归零，就会在这里无限重试，进程"卡死"。
                 * 现在：g_stop 已置位就立刻 break 退出，绝不重试等待。
                 */
                if (g_stop != 0) {
                    SH_LOGI("epoll_wait 被信号中断（EINTR）且 g_stop 已置位，立即退出");
                    r->running = false;
                    break;
                }
                continue;
            }
            SH_LOGE("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < n; i++) {
            uint64_t tag = events[i].data.u64;
            uint32_t kind = SH_EP_KIND(tag);
            uint32_t id = SH_EP_ID(tag);

            switch (kind) {
            case SH_EP_KIND_LISTEN: {
                int lfd = (id == SH_LISTEN_SLOT_TLS) ? r->listen_tls_fd
                                                     : r->listen_fd;
                reactor_accept_batch(r, lfd, id != 0 ? id : SH_LISTEN_SLOT_MAIN);
                break;
            }
            case SH_EP_KIND_KEM:
                for (;;) {
                    uint64_t v = 0;
                    ssize_t got = read(r->kem_eventfd, &v, sizeof v);
                    if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    }
                    if (got <= 0) {
                        break;
                    }
                }
                reactor_drain_kem(r);
                break;
            case SH_EP_KIND_WAKE:
                for (;;) {
                    uint64_t v = 0;
                    ssize_t got = read(r->wake_fd, &v, sizeof v);
                    if (got <= 0) {
                        break;
                    }
                }
                break;
            case SH_EP_KIND_CLIENT:
            case SH_EP_KIND_UPSTREAM: {
                sh_conn *c = id_map_get(r, id);
                if (c != NULL) {
                    conn_on_event(r, c, events[i].events,
                                  kind == SH_EP_KIND_UPSTREAM);
                }
                break;
            }
            default:
                break;
            }
        }

        /* 检查点 3/3：本批事件处理完之后再看一次退出标志。
         * 覆盖"信号在 epoll_wait 返回之后、处理事件期间到达"的情况：
         * 此时 WAKE 事件已被 drain，指针也不会再被丢弃。 */
        if (g_stop != 0) {
            SH_LOGI("处理完本批事件后检测到 g_stop，退出事件循环");
            r->running = false;
            break;
        }

        /* 本批事件处理完之后：定时器 → 每连接 tick → 回收 */
        now = reactor_now_ms();
        sh_reactor_timer_run(r, now);
        for (sh_conn *c = r->all_head; c != NULL; ) {
            sh_conn *next = c->next_all;
            if (c->fd >= 0 && c->state != SH_CONN_CLOSING && c->hooks != NULL &&
                c->hooks->on_tick != NULL) {
                if (c->hooks->on_tick(r, c) != 0) {
                    (void)sh_conn_close(r, c, false);
                }
            }
            c = next;
        }
        /* 统一回收：绝不在遍历 events[] 时释放 */
        for (sh_conn *c = r->all_head; c != NULL; ) {
            sh_conn *next = c->next_all;
            if (c->state == SH_CONN_CLOSING) {
                sh_conn_release(r, c);
            }
            c = next;
        }
    }
    return 0;
}
