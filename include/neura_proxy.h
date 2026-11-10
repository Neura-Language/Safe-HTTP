// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Proxy 模式：Neura-S2S 解密 + WAF + 上游转发
 *
 * 链路（REQUIREMENTS.md §2）：
 *   Client --(Neura-S2S 密文)--> [127.0.0.1:5362] Safe-HTTP
 *          --(明文 HTTP)--> 现有 Nginx/Apache (127.0.0.1:8080)
 *
 * 全部 IO 非阻塞、epoll ET；上游连接使用非阻塞 connect，
 * 由 reactor 监听 EPOLLOUT 判断完成，绝不阻塞事件循环。
 *
 * 本头文件仅在 make MODE=PROXY 时参与编译。
 */
#ifndef SAFE_HTTP_NEURA_PROXY_H
#define SAFE_HTTP_NEURA_PROXY_H

#if SH_MODE_PROXY

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "http.h"
#include "network.h"
#include "security.h"

/* 上游连接子状态机 */
typedef enum proxy_upstream_state {
    PROXY_UP_IDLE = 0,
    PROXY_UP_DIALING,      /* 非阻塞 connect 进行中 */
    PROXY_UP_CONNECTED,    /* 已连接，可发送请求 */
    PROXY_UP_STREAMING,    /* 双向流式转发 */
    PROXY_UP_DRAINING,     /* 请求体/响应体未结束，等待对端关闭 */
    PROXY_UP_CLOSED
} proxy_upstream_state;

typedef struct proxy_ctx {
    proxy_upstream_state up_state;
    sh_http_head         request;      /* 当前请求头（指向 plain_buf，用完即清零）*/
    uint8_t             *plain;        /* 解密后的明文缓冲（in 的镜像）*/
    sh_buf               plain_buf;
    uint64_t             upstream_deadline_ms;   /* 非阻塞 connect 超时点 */
    uint32_t             inflight;     /* 已发送但未收到响应的请求数 */
    uint32_t             requests;
    bool                 head_forwarded;
    bool                 upstream_keep_alive;
    bool                 keep_alive;        /* 客户端要求复用本通道 */
    uint32_t             served;            /* 本通道已完成请求数 */

    /* ---- HTTP/1.1 响应分帧状态（keep-alive 必需） ---- */
    bool                 req_is_head;       /* 请求是 HEAD：响应无 body */
    bool                 resp_head_done;    /* 响应头已收全 */
    bool                 resp_chunked;      /* Transfer-Encoding: chunked */
    bool                 resp_no_body;      /* 1xx/204/304/HEAD */
    bool                 resp_complete;     /* 本响应已收满 */
    bool                 resp_keep_alive;   /* 上游未声明 Connection: close */
    uint64_t             resp_body_left;    /* Content-Length 剩余 */
    uint64_t             resp_chunk_left;   /* 当前 chunk 剩余 */
    int                  resp_chunk_phase;  /* 0=size 行 1=数据 2=chunk 尾 CRLF 3=trailer */
    char                 resp_line[24];     /* chunk 行/trailer 行缓冲 */
    size_t               resp_line_len;
    uint64_t             resp_bytes;        /* 本响应已转发字节数（统计/调试） */
    char                 rewritten_target[SH_MAX_TARGET_LEN];

    /* ---- 非阻塞转发的收尾/半关闭状态（缺一不可）---- */
    bool                 resp_head_seen;  /* 上游响应头是否已解析 */
    int                  resp_status;     /* 上游状态码（仅记录/统计） */
    bool                 client_eof;      /* 客户端已半关闭/断开 */
    bool                 upstream_eof;    /* 上游已断开 */
    bool                 up_shut_wr;      /* 已对上游 shutdown(SHUT_WR) */
    uint64_t             last_io_ms;      /* 最近一次双向 IO 时间（空闲超时用） */
} proxy_ctx;

/* ==========================================================================
 * 钩子实现（注册到 reactor）
 * ========================================================================== */
int  proxy_on_client_read(sh_reactor *r, sh_conn *c);
int  proxy_on_client_write(sh_reactor *r, sh_conn *c);
int  proxy_on_upstream_read(sh_reactor *r, sh_conn *c);
int  proxy_on_upstream_write(sh_reactor *r, sh_conn *c);
int  proxy_on_tick(sh_reactor *r, sh_conn *c);
void proxy_on_close(sh_reactor *r, sh_conn *c);

extern const sh_conn_hooks sh_proxy_hooks;

/* ==========================================================================
 * 上游
 * ========================================================================== */
/* 发起非阻塞连接（host/port 来自 settings 或规则覆盖） */
int  proxy_upstream_connect(sh_reactor *r, sh_conn *c,
                            const char *host, uint16_t port);
/* connect 完成后调用：把 c->up_out 中的请求头刷给上游 */
int  proxy_upstream_start(sh_reactor *r, sh_conn *c);
/* 关闭上游（graceful 为 true 时先冲净 up_out） */
void proxy_upstream_close(sh_reactor *r, sh_conn *c, bool graceful);

/*
 * 组装转发到上游的请求：
 *   1. 应用 MatchLang Rewrite 规则得到新 target；
 *   2. 注入 X-Forwarded-For / X-Forwarded-Proto / X-Neura-Epoch；
 *   3. 保留 Content-Length / Transfer-Encoding，剔除 hop-by-hop 头；
 * 结果写入 c->up_out。
 */
int  proxy_build_upstream_request(sh_reactor *r, sh_conn *c,
                                  const sh_http_head *req);

/* 解析上游响应头（仅用于记录状态码与 keep-alive 判定） */
int  proxy_parse_upstream_response(sh_reactor *r, sh_conn *c,
                                   const uint8_t *data, size_t len,
                                   int *status_out, size_t *head_len_out);

/* 背压：当客户端 out 缓冲超过阈值时暂停读取上游，反之亦然 */
void proxy_apply_backpressure(sh_reactor *r, sh_conn *c);

#endif /* SH_MODE_PROXY */

#endif /* SAFE_HTTP_NEURA_PROXY_H */
