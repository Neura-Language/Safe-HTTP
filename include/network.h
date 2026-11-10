// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 网络层（epoll 边缘触发）
 *
 * 设计要点（REQUIREMENTS.md §3.3）：
 *   1. 全部监听/连接 fd 均为非阻塞 + EPOLLET，读写循环必须一次读空/写尽；
 *   2. 连接对象集中分配（free list + 全量链表），避免每连接多次 malloc；
 *   3. 定时器为最小堆/有序链表（实现可选），支撑空闲超时、握手超时、
 *      0.3s 棘轮与 WAF 窗口清扫；
 *   4. Standalone 与 Proxy 通过 sh_conn_hooks 注入不同 IO 处理器，
 *      两种模式共用同一 reactor，零冗余。
 */
#ifndef SAFE_HTTP_NETWORK_H
#define SAFE_HTTP_NETWORK_H

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"

/* 前向声明：避免头文件互相包含 */
typedef struct sh_conn     sh_conn;
typedef struct sh_reactor  sh_reactor;
typedef struct sh_timer    sh_timer;
typedef struct sh_neura_conn sh_neura_conn; /* security.h：libs2s 会话封装 */
struct ns2s_kem_job;                        /* neura/s2s_handshake.h 的 KEM 任务 */
struct sh_anchor;                           /* security.h：DNS TXT 信任锚 */

typedef struct waf         waf;
typedef struct ncf_config  ncf_config;

/* ==========================================================================
 * 0. 全局退出标志（"stop requested"）
 *
 * 规则（不可破坏）：
 *   A. 信号处理函数里只允许做两件异步安全的事：
 *        g_stop = 1;  write(eventfd, ...);
 *      —— 不 malloc、不 printf、不碰 reactor 内部状态；
 *   B. 主循环 sh_reactor_run() 在三处检查 g_stop：
 *        1) 每轮循环开始；
 *        2) epoll_wait() 返回 EINTR（被信号打断）时 —— 立刻 break，不 continue；
 *        3) 一批事件处理完之后；
 *      一旦置位立刻退出，绝不会在 epoll_wait 上无限重试而"卡死"。
 *   C. sig_atomic_t 保证信号处理函数里的读写不会被撕裂。
 * ========================================================================== */
extern volatile sig_atomic_t g_stop;

/* ==========================================================================
 * 1. 缓冲区
 *
 * 线性缓冲 + 读写下标；数据被消费后由 sh_buf_compact() 前移。
 * 单连接读缓冲固定为 SH_READ_BUF_SIZE，写缓冲按需增长（上限写回压）。
 * ========================================================================== */
typedef struct sh_buf {
    uint8_t *data;
    size_t   cap;
    size_t   rpos;   /* 读位置 */
    size_t   wpos;   /* 写位置 */
} sh_buf;

int     sh_buf_init(sh_buf *b, size_t cap);
void    sh_buf_free(sh_buf *b);
void    sh_buf_reset(sh_buf *b);
size_t  sh_buf_readable(const sh_buf *b);
size_t  sh_buf_writable(const sh_buf *b);
bool    sh_buf_empty(const sh_buf *b);
/* 将剩余数据搬到头部，腾出尾部空间 */
void    sh_buf_compact(sh_buf *b);
/* 确保尾部可写 need 字节（必要时 compact / 扩容）；成功 0，-1 失败 */
int     sh_buf_reserve(sh_buf *b, size_t need);
/* 追加数据，返回写入字节数（0 表示空间不足） */
size_t  sh_buf_append(sh_buf *b, const void *src, size_t len);
size_t  sh_buf_append_str(sh_buf *b, const char *s);
/* printf 风格追加，返回写入字节数 */
size_t  sh_buf_appendf(sh_buf *b, const char *fmt, ...) SH_PRINTF(2, 3);
/* 只读视图：返回指针，*len 输出可读长度 */
const uint8_t *sh_buf_peek(const sh_buf *b, size_t *len);
/* 消费 n 字节 */
void    sh_buf_consume(sh_buf *b, size_t n);

/* ==========================================================================
 * 2. 地址
 * ========================================================================== */
typedef struct sh_addr {
    struct sockaddr_storage ss;
    socklen_t               len;
} sh_addr;

/* 输出 IP 字符串（IPv6 带方括号或不带由参数决定）；返回 out */
const char *sh_addr_ip(const sh_addr *a, char *out, size_t cap);
uint16_t    sh_addr_port(const sh_addr *a);
/* 支持 "1.2.3.4" / "example.com" / "[::1]"；DNS 解析由 getaddrinfo 完成 */
int         sh_addr_from_string(sh_addr *a, const char *host, uint16_t port);
bool        sh_addr_equal(const sh_addr *a, const sh_addr *b);
/* 仅按 IP 计算哈希（Ban 规则的 key 不包含端口） */
uint32_t    sh_addr_hash(const sh_addr *a);
bool        sh_addr_is_loopback(const sh_addr *a);

/* ==========================================================================
 * 3. 定时器
 * ========================================================================== */
typedef void (*sh_timer_cb)(sh_reactor *r, sh_timer *t, void *arg);

struct sh_timer {
    uint64_t      expire_ms;
    sh_timer_cb   cb;
    void         *arg;
    sh_timer     *next;
    bool          armed;
    const char   *name;   /* 静态字符串，便于调试 */
};

/* 添加并启动一次性定时器（delay_ms 后触发一次） */
int  sh_reactor_timer_add(sh_reactor *r, sh_timer *t, uint32_t delay_ms,
                          sh_timer_cb cb, void *arg);
/* 重新计时（已启动则不重复入队） */
int  sh_reactor_timer_arm(sh_reactor *r, sh_timer *t, uint32_t delay_ms);
void sh_reactor_timer_cancel(sh_reactor *r, sh_timer *t);
/* 由事件循环每轮调用：触发所有到期定时器，返回触发个数 */
size_t sh_reactor_timer_run(sh_reactor *r, uint64_t now_ms);

/* ==========================================================================
 * 4. 连接
 * ========================================================================== */
typedef enum sh_conn_state {
    SH_CONN_FREE = 0,
    SH_CONN_ACCEPTED,          /* 刚 accept，等待请求 */
    SH_CONN_HANDSHAKING,       /* Neura-S2S 握手进行中 */
    SH_CONN_ACTIVE,            /* 明文业务流 */
    SH_CONN_UPSTREAM_CONNECT,  /* Proxy：正在非阻塞连接上游 */
    SH_CONN_UPSTREAM_ACTIVE,   /* Proxy：双向转发中 */
    SH_CONN_DRAINING,          /* 半关闭，等待对端 FIN */
    SH_CONN_CLOSING
} sh_conn_state;

typedef enum sh_crypto_state {
    SH_CRYPTO_PLAIN = 0,       /* 未启用加密（HTTP 明文直通） */
    SH_CRYPTO_HANDSHAKE,       /* 握手进行中 */
    SH_CRYPTO_READY,           /* 已建立，可收发应用数据 */
    SH_CRYPTO_FAILED
} sh_crypto_state;

/* 连接 IO 钩子：由 Standalone / Proxy 模块各自提供实现 */
typedef int (*sh_conn_io_cb)(sh_reactor *r, sh_conn *c);

typedef struct sh_conn_hooks {
    const char *name;
    sh_conn_io_cb on_client_read;      /* 客户端可读（EPOLLIN） */
    sh_conn_io_cb on_client_write;     /* 客户端可写（EPOLLOUT） */
    sh_conn_io_cb on_upstream_read;    /* 上游可读 */
    sh_conn_io_cb on_upstream_write;   /* 上游可写 */
    sh_conn_io_cb on_tick;             /* 每轮事件循环（可 NULL） */
    void (*on_close)(sh_reactor *r, sh_conn *c);
} sh_conn_hooks;

struct sh_conn {
    int             fd;                 /* 客户端 fd，-1 表示空槽 */
    int             upstream_fd;        /* Proxy 模式上游 fd，否则 -1 */
    sh_conn_state   state;
    sh_crypto_state crypto;
    uint32_t        id;                 /* 单调递增，用于日志追踪 */
    uint32_t        epoll_events;       /* 当前注册的 EPOLL* 位 */
    uint32_t        upstream_events;    /* 上游 fd 注册的事件 */

    sh_addr         peer;               /* 客户端地址 */
    sh_addr         upstream_peer;      /* 上游地址（Proxy） */

    /* 数据通路：out 是待发给客户端的字节流，up_out 是待发给上游的字节流 */
    sh_buf          in;                 /* 客户端 -> 服务端（密文或明文） */
    sh_buf          out;                /* 服务端 -> 客户端 */
    sh_buf          up_in;              /* 上游 -> 服务端 */
    sh_buf          up_out;             /* 服务端 -> 上游 */

    sh_neura_conn  *neura;              /* Neura-S2S 会话（NULL = 明文直通） */
    void           *http;               /* sh_http_state*，由 http.c 管理 */
    void           *user;               /* 模式私有数据（静态文件上下文等） */

    const sh_conn_hooks *hooks;

    /* 定时器内嵌，避免额外分配 */
    sh_timer        idle_timer;
    sh_timer        handshake_timer;
    sh_timer        ratchet_timer;

    uint64_t        accepted_ms;
    uint64_t        last_active_ms;
    uint64_t        next_ratchet_ms;
    uint64_t        bytes_in;
    uint64_t        bytes_out;
    uint32_t        requests_served;

    /* Ban 规则 key 缓存（IP 字符串 + 哈希），避免每次检查重复 inet_ntop */
    char            ip_str[SH_INET_ADDR_STRLEN];
    uint32_t        ip_hash;

    bool            read_paused;        /* 背压：暂停读客户端 */
    bool            upstream_paused;
    bool            half_closed;
    bool            keep_alive;

    sh_conn        *prev_all;           /* reactor 全量链表 */
    sh_conn        *next_all;
    sh_conn        *next_free;          /* 空闲链表 */
};

/* 取连接 fd，安全处理 -1 */
SH_INLINE int sh_conn_fd(const sh_conn *c) { return c ? c->fd : -1; }

/* ==========================================================================
 * 5. 事件循环（reactor）
 * ========================================================================== */
typedef struct sh_reactor_stats {
    uint64_t conns_accepted;
    uint64_t conns_closed;
    uint64_t requests_total;
    uint64_t bytes_client_in;
    uint64_t bytes_client_out;
    uint64_t bytes_upstream_in;
    uint64_t bytes_upstream_out;
    uint64_t handshakes_ok;
    uint64_t handshakes_failed;
    uint64_t ratchets;
    uint64_t waf_dropped;
    uint64_t waf_throttled;
    uint64_t upstream_connect_failed;
    uint64_t timeouts;
    uint32_t active_conns;
    uint32_t peak_conns;
} sh_reactor_stats;

struct sh_reactor {
    int              epfd;
    int              wake_fd;        /* eventfd，用于异步唤醒（信号处理） */
    int              listen_fd;      /* 明文/Neura 监听 */
    int              listen_tls_fd;  /* Standalone 的 443，未启用为 -1 */
    bool             running;
    bool             in_callback;    /* 回调期间禁止释放连接 */

    sh_settings      settings;       /* 值拷贝，避免默认值被意外修改 */
    ncf_config      *config;
    waf             *waf;

    /* KEM worker pool（libs2s 提供）：X-Wing 运算绝不在 reactor 线程执行，
     * worker 完成后写 kem_eventfd 唤醒 epoll，由 reactor 在主循环里 apply。 */
    void            *kem_pool;       /* ns2s_kem_pool*，本 reactor 独占 */
    int              kem_eventfd;    /* eventfd，-1 表示未启用加密 */

    /* 加密层身份：RootKey 必须在 accept 之前加载（无 RootKey 不降级明文） */
    uint8_t          root_key[SH_ROOTKEY_BYTES];
    bool             have_root_key;
    struct sh_anchor *anchor;        /* 启动时取回的 TXT 锚点（可为 NULL） */

    const sh_conn_hooks *hooks;      /* 新连接使用的钩子 */

    sh_conn         *all_head;       /* 活跃连接链表 */
    sh_conn         *free_head;      /* 空闲连接链表 */

    /* id -> conn 映射：KEM 完成时按 job->conn_id 找回连接（open addressing） */
    sh_conn        **id_map;
    size_t           id_map_cap;
    size_t           id_map_used;
    uint32_t         conn_count;
    uint32_t         conn_capacity;
    uint32_t         next_conn_id;

    sh_timer        *timers;         /* 有序（expire_ms 升序）定时器链表 */
    sh_timer        *timer_free;

    sh_reactor_stats stats;
    void            *user;
};

/*
 * 初始化 reactor：创建 epoll、eventfd、预分配连接池、注册信号管道。
 * settings 会被值拷贝；config / waf 由调用方持有，reactor 不负责释放。
 * 成功 0，失败 -1（errno 已设置）。
 */
int  sh_reactor_init(sh_reactor *r, const sh_settings *settings,
                     ncf_config *config, waf *w);
void sh_reactor_destroy(sh_reactor *r);

/* 按 settings 打开监听 fd（Standalone 会同时尝试 80 与 443） */
int  sh_reactor_listen(sh_reactor *r);

/* 实际监听端口（端口传 0 时由内核分配，用于测试与日志） */
uint16_t sh_reactor_port(const sh_reactor *r);

int  sh_reactor_run(sh_reactor *r);      /* 阻塞直到 sh_reactor_stop / g_stop 置位 */
void sh_reactor_stop(sh_reactor *r);     /* 线程/信号安全：置 g_stop + 写 eventfd */
void sh_reactor_wakeup(sh_reactor *r);

/*
 * 提交 KEM 任务到 reactor 的 worker pool（X-Wing keypair/Encaps/Decaps）。
 * job 的所有权转交 reactor；worker 完成后通过 kem_eventfd 唤醒，
 * reactor 依据 job->conn_id 找回连接并调用 sh_neura_kem_done()/棘轮 apply。
 * 返回 0 成功，-1 失败（pool 未初始化或队列满）。
 */
int sh_reactor_kem_submit(sh_reactor *r, sh_conn *c, struct ns2s_kem_job *job);


/* 连接池 */
sh_conn *sh_conn_acquire(sh_reactor *r, int fd, const sh_addr *peer);
void     sh_conn_release(sh_reactor *r, sh_conn *c);
/* 优雅关闭：先把 out 缓冲冲干净（最多 SH_LINGER_MS），再真正 close */
int      sh_conn_close(sh_reactor *r, sh_conn *c, bool graceful);
/* 立即 RST/drop_connection（WAF 封禁使用，不留 TIME_WAIT 负担） */
void     sh_conn_drop(sh_reactor *r, sh_conn *c);

/* epoll 注册：want_read/want_write 只影响客户端 fd；ET 模式下始终注册 EPOLLIN */
int  sh_conn_want(sh_reactor *r, sh_conn *c, bool want_read, bool want_write);
int  sh_conn_want_upstream(sh_reactor *r, sh_conn *c,
                           bool want_read, bool want_write);
/*
 * ET 下「暂停读取 → 恢复读取」的必要手段：
 * 背压期间我们不再 read()，内核里剩余数据不会产生新的事件边沿，
 * 单靠 sh_conn_want()（事件位没变时会短路）无法恢复。
 * EPOLL_CTL_MOD 会让内核重新评估就绪状态，从而再投递一次事件。
 * upstream 为 true 表示重新 arm 上游 fd，否则 arm 客户端 fd。
 */
int  sh_conn_rearm(sh_reactor *r, sh_conn *c, bool upstream);
/* 把 b 中数据尽量写入 fd；返回写出的字节数，-1 表示致命错误 */
ssize_t sh_conn_flush(sh_reactor *r, sh_conn *c, int fd, sh_buf *b);

/* ==========================================================================
 * 6. socket 辅助函数（全部返回 0 成功 / -1 失败并设置 errno）
 * ========================================================================== */
int sh_net_set_nonblocking(int fd, bool enable);
int sh_net_set_cloexec(int fd, bool enable);
int sh_net_set_nodelay(int fd, bool enable);
int sh_net_set_keepalive(int fd, bool enable, int idle_s, int interval_s,
                         int probes);
int sh_net_set_reuseaddr(int fd, bool enable);
int sh_net_set_reuseport(int fd, bool enable);
int sh_net_set_recvbuf(int fd, int bytes);
int sh_net_set_sendbuf(int fd, int bytes);
/* 监听：host 为 NULL 时按模式取默认值；port 为 0 时跳过 */
int sh_net_listen(const char *host, uint16_t port, int backlog);
/* accept 一个连接；返回 fd（非阻塞），无连接返回 -1 且 errno=EAGAIN */
int sh_net_accept(int listen_fd, sh_addr *peer);
/* 非阻塞 connect：返回 fd，*in_progress 表示是否仍在连接中 */
int sh_net_connect(const char *host, uint16_t port, bool *in_progress);
/* 检查非阻塞 connect 结果：1 成功，0 进行中，-1 失败 */
int sh_net_connect_result(int fd);

#endif /* SAFE_HTTP_NETWORK_H */
