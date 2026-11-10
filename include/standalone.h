// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Standalone 模式：直接对外提供服务
 *
 * 链路（REQUIREMENTS.md §2）：
 *   Client --(Neura-S2S 密文 / 可选 TLS)--> [0.0.0.0:80, :443] Safe-HTTP
 *          --> 内部静态文件服务 + API 路由（无上游）
 *
 * 本头文件仅在 make MODE=STANDALONE 时参与编译。
 */
#ifndef SAFE_HTTP_STANDALONE_H
#define SAFE_HTTP_STANDALONE_H

#if SH_MODE_STANDALONE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#include "http.h"
#include "network.h"

/* 静态文件上下文（每连接可选，或全局共享只读） */
typedef struct sh_static_ctx {
    char     root[4096];             /* 规范化后的站点根目录 */
    char     index_file[64];
    bool     directory_listing;
    bool     etag_enabled;
    bool     sendfile_enabled;
    uint32_t cache_max_age;
} sh_static_ctx;

typedef struct standalone_ctx {
    sh_http_head request;            /* 当前请求头（指向 c->in） */
    uint8_t     *plain;              /* Neura-S2S 解密后的明文镜像 */
    sh_buf       plain_buf;
    int          file_fd;            /* 正在 sendfile 的文件 */
    off_t        file_offset;
    off_t        file_size;
    int          status;             /* 响应状态码（日志用）*/
    bool         head_only;
    bool         headers_sent;
} standalone_ctx;

/* ==========================================================================
 * 钩子实现
 * ========================================================================== */
int  standalone_on_client_read(sh_reactor *r, sh_conn *c);
int  standalone_on_client_write(sh_reactor *r, sh_conn *c);
int  standalone_on_tick(sh_reactor *r, sh_conn *c);
void standalone_on_close(sh_reactor *r, sh_conn *c);

extern const sh_conn_hooks sh_standalone_hooks;

/* ==========================================================================
 * 静态文件与路由
 * ========================================================================== */
void sh_static_ctx_defaults(sh_static_ctx *ctx);
int  sh_static_ctx_init(sh_static_ctx *ctx, const sh_settings *s);

/*
 * 处理一个完整请求：
 *   1. MatchLang Rewrite 改写路径；
 *   2. 规范化并做目录穿越校验；
 *   3. 静态文件（sendfile）或内置 404/403。
 * 成功返回 0，失败 -1（已生成错误响应）。
 */
int  standalone_serve(sh_reactor *r, sh_conn *c, const sh_http_head *req);
int  standalone_serve_file(sh_reactor *r, sh_conn *c, const char *fs_path,
                           bool head_only);
int  standalone_serve_directory(sh_reactor *r, sh_conn *c,
                               const char *fs_path, const char *uri);

/* 内置管理端点：/__safe_http/health、/__safe_http/stats、/__safe_http/fingerprint */
int  standalone_serve_admin(sh_reactor *r, sh_conn *c, const char *uri);

#endif /* SH_MODE_STANDALONE */

#endif /* SAFE_HTTP_STANDALONE_H */
