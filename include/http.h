// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - HTTP/1.1 解析与构造
 *
 * 约束：解析器为手写状态机（零拷贝、无正则），不依赖 PCRE；
 * 与 MatchLang 的"禁止使用 PCRE 正则"要求保持一致。
 * 只解析请求头（Standalone 内部路由 + Proxy 改写都需要），
 * 请求体按 Content-Length / chunked 原样转发。
 */
#ifndef SAFE_HTTP_HTTP_H
#define SAFE_HTTP_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "network.h"

typedef enum sh_http_method {
    SH_METHOD_GET = 0,
    SH_METHOD_HEAD,
    SH_METHOD_POST,
    SH_METHOD_PUT,
    SH_METHOD_DELETE,
    SH_METHOD_OPTIONS,
    SH_METHOD_PATCH,
    SH_METHOD_CONNECT,
    SH_METHOD_TRACE,
    SH_METHOD_UNKNOWN
} sh_http_method;

typedef enum sh_http_parse_status {
    SH_HTTP_INCOMPLETE   =  0,   /* 需要更多字节 */
    SH_HTTP_OK           =  1,
    SH_HTTP_TOO_LARGE    = -1,   /* 超过 SH_MAX_HEAD_BYTES */
    SH_HTTP_MALFORMED    = -2,   /* 语法错误 */
    SH_HTTP_UNSUPPORTED  = -3    /* 非 HTTP/1.x 或非法方法 */
} sh_http_parse_status;

/*
 * 解析结果：所有指针都指向调用方传入的原始缓冲区（零拷贝），
 * 因此缓冲区在 head 使用期间必须保持有效、不得移动。
 */
typedef struct sh_http_head {
    sh_http_method method;
    char           method_str[8];
    uint8_t        method_len;

    const char    *target;        /* 原始 request-target */
    size_t         target_len;
    const char    *path;          /* target 中 '?' 之前部分（已解码前） */
    size_t         path_len;
    const char    *query;         /* target 中 '?' 之后部分，可为 NULL */
    size_t         query_len;

    int            version_major;
    int            version_minor;

    const uint8_t *raw;           /* 指向头起始位置 */
    size_t         head_len;      /* 含结尾 CRLFCRLF */
    size_t         body_offset;   /* == head_len，语法糖 */

    uint64_t       content_length;
    bool           chunked;
    bool           keep_alive;
    bool           expect_continue;
    bool           has_host;
    uint32_t       header_count;
} sh_http_head;

/* 解析请求头。data/len 为缓冲区当前可读内容。 */
sh_http_parse_status sh_http_parse_head(const uint8_t *data, size_t len,
                                        sh_http_head *out);
/* 重新扫描以填充 path/query 之外的信息（内部使用） */
sh_http_parse_status sh_http_parse_complete(const uint8_t *data, size_t len,
                                            sh_http_head *out);

/* 大小写无关地取头部值；未找到返回 NULL，*value_len 输出长度 */
const char *sh_http_header(const sh_http_head *h, const char *name,
                           size_t *value_len);
const char *sh_http_method_name(sh_http_method m);
sh_http_method sh_http_method_from_string(const char *s, size_t len);

/*
 * 逐条遍历头部：从 *cursor（初始为 0）开始，返回下一个头部名/值。
 * 遍历结束返回 false。
 */
bool sh_http_header_next(const sh_http_head *h, size_t *cursor,
                         const char **name, size_t *name_len,
                         const char **value, size_t *value_len);

/* ==========================================================================
 * 构造
 * ========================================================================== */
typedef struct sh_http_extra_header {
    const char *name;
    const char *value;
} sh_http_extra_header;

/*
 * 构造上游请求头：
 *   - 使用原始 target 或 new_target（NULL 表示沿用原值）
 *   - 追加 hdrs（X-Forwarded-For、X-Neura-Session 等）
 *   - 追加 Connection: keep-alive / 覆盖 Host
 *   - 跳过 hop-by-hop 头部
 * 成功返回写入字节数，失败 -1。
 */
ssize_t sh_http_build_request(const sh_http_head *h, const char *new_target,
                              const sh_http_extra_header *hdrs, size_t nhdrs,
                              sh_buf *out);
/*
 * 同上，但由调用方决定上游连接是否复用：
 *   keep_alive=true  → 追加 "Connection: keep-alive"（可复用到上游）
 *   keep_alive=false → 追加 "Connection: close"（回完即关，首版行为）
 * 分帧由调用方（Proxy）负责，这里只影响请求头。
 */
ssize_t sh_http_build_request_ex(const sh_http_head *h, const char *new_target,
                                 const sh_http_extra_header *hdrs, size_t nhdrs,
                                 bool keep_alive, sh_buf *out);

/* 构造响应：code + reason + 头部 + 可选 body（body 可为 NULL） */
int sh_http_build_response(int code, const char *reason,
                           const sh_http_extra_header *hdrs, size_t nhdrs,
                           const void *body, size_t body_len, sh_buf *out);
/* 便捷：纯文本响应 */
int sh_http_send_error(sh_buf *out, int code, const char *message);
int sh_http_send_redirect(sh_buf *out, int code, const char *location);

/* 状态码 -> 原因短语（返回静态字符串，未知返回 "Unknown"） */
const char *sh_http_reason(int code);

/* ==========================================================================
 * URL 处理
 * ========================================================================== */
/* 百分号解码到 out；返回解码后长度，-1 失败 */
ssize_t sh_url_decode(const char *in, size_t in_len, char *out, size_t cap);
/* 百分号编码（path 模式：不编码 '/'；query 模式：编码 '&','=' 等） */
int     sh_url_encode(const char *in, size_t in_len, bool for_query,
                      char *out, size_t cap);
/* 去掉 query、折叠重复 '/'、拒绝 ".."；返回规范化后的长度，-1 非法 */
ssize_t sh_url_normalize_path(const char *in, size_t in_len,
                              char *out, size_t cap);
/* 取查询参数值（大小写敏感）；未找到返回 NULL */
const char *sh_url_query_get(const char *query, size_t query_len,
                             const char *key, size_t *value_len);

/* ==========================================================================
 * Standalone 静态文件支持
 * ========================================================================== */
const char *sh_mime_type(const char *path);
/* 根据扩展名决定是否需要压缩/缓存头（返回 max-age 秒，0 表示不缓存） */
uint32_t    sh_cache_max_age(const char *path);

#endif /* SAFE_HTTP_HTTP_H */
