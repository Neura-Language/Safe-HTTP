// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - HTTP/1.1 解析与构造（手写状态机，零拷贝，无 PCRE）
 *
 * 只实现首版 Proxy 通道必需的部分：请求头解析、头部查找、上游请求构造、
 * 响应构造、URL 规范化。静态文件/MIME 相关接口留给 Standalone 阶段。
 */
#include "http.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

static const struct {
    const char *name;
    sh_http_method m;
} k_methods[] = {
    {"GET", SH_METHOD_GET},       {"HEAD", SH_METHOD_HEAD},
    {"POST", SH_METHOD_POST},     {"PUT", SH_METHOD_PUT},
    {"DELETE", SH_METHOD_DELETE}, {"OPTIONS", SH_METHOD_OPTIONS},
    {"PATCH", SH_METHOD_PATCH},   {"CONNECT", SH_METHOD_CONNECT},
    {"TRACE", SH_METHOD_TRACE},
};

const char *sh_http_method_name(sh_http_method m)
{
    for (size_t i = 0; i < SH_ARRAY_LEN(k_methods); i++) {
        if (k_methods[i].m == m) {
            return k_methods[i].name;
        }
    }
    return "UNKNOWN";
}

sh_http_method sh_http_method_from_string(const char *s, size_t len)
{
    if (s == NULL) {
        return SH_METHOD_UNKNOWN;
    }
    for (size_t i = 0; i < SH_ARRAY_LEN(k_methods); i++) {
        if (strlen(k_methods[i].name) == len &&
            memcmp(k_methods[i].name, s, len) == 0) {
            return k_methods[i].m;
        }
    }
    return SH_METHOD_UNKNOWN;
}

const char *sh_http_reason(int code)
{
    switch (code) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 413: return "Payload Too Large";
    case 414: return "URI Too Long";
    case 421: return "Misdirected Request";
    case 426: return "Upgrade Required";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default:  return "Unknown";
    }
}

/* 大小写无关的"行内是否以 name: 开头"，返回值的起点与长度 */
static const char *header_value(const char *line, size_t line_len,
                                const char *name, size_t name_len,
                                size_t *value_len)
{
    if (line_len <= name_len || line[name_len] != ':') {
        return NULL;
    }
    for (size_t i = 0; i < name_len; i++) {
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i])) {
            return NULL;
        }
    }
    const char *v = line + name_len + 1;
    const char *end = line + line_len;
    while (v < end && (*v == ' ' || *v == '\t')) {
        v++;
    }
    while (end > v && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    if (value_len != NULL) {
        *value_len = (size_t)(end - v);
    }
    return v;
}

/* 返回第一行的长度（不含 CRLF），*next 指向下一行起点 */
static size_t line_span(const char *data, size_t len, size_t pos, size_t *next)
{
    size_t i = pos;
    while (i < len && data[i] != '\n') {
        i++;
    }
    size_t content_end = i;
    if (content_end > pos && data[content_end - 1] == '\r') {
        content_end--;
    }
    if (next != NULL) {
        *next = (i < len) ? i + 1 : len;
    }
    return content_end - pos;
}

sh_http_parse_status sh_http_parse_head(const uint8_t *data, size_t len,
                                        sh_http_head *out)
{
    if (data == NULL || out == NULL) {
        return SH_HTTP_MALFORMED;
    }
    if (len > SH_MAX_HEAD_BYTES) {
        return SH_HTTP_TOO_LARGE;
    }

    size_t head_end = 0;
    bool found = false;
    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            head_end = i + 4;
            found = true;
            break;
        }
    }
    if (!found) {
        return SH_HTTP_INCOMPLETE;
    }

    memset(out, 0, sizeof *out);
    out->raw = data;
    out->head_len = head_end;
    out->body_offset = head_end;

    const char *p = (const char *)data;

    /* ---- request line: METHOD SP target SP HTTP/x.y ---- */
    size_t pos = 0;
    while (pos < head_end && p[pos] != ' ') {
        pos++;
    }
    if (pos == 0 || pos > 7) {
        return SH_HTTP_MALFORMED;
    }
    memcpy(out->method_str, p, pos);
    out->method_str[pos] = '\0';
    out->method_len = (uint8_t)pos;
    out->method = sh_http_method_from_string(out->method_str, pos);
    if (out->method == SH_METHOD_UNKNOWN) {
        return SH_HTTP_UNSUPPORTED;
    }
    pos++;

    size_t tstart = pos;
    while (pos < head_end && p[pos] != ' ') {
        pos++;
    }
    if (pos == tstart || pos >= head_end) {
        return SH_HTTP_MALFORMED;
    }
    out->target = p + tstart;
    out->target_len = pos - tstart;
    if (out->target_len > SH_MAX_TARGET_LEN) {
        return SH_HTTP_MALFORMED;
    }

    const char *qmark = memchr(out->target, '?', out->target_len);
    if (qmark != NULL) {
        out->path = out->target;
        out->path_len = (size_t)(qmark - out->target);
        out->query = qmark + 1;
        out->query_len = out->target_len - out->path_len - 1u;
    } else {
        out->path = out->target;
        out->path_len = out->target_len;
        out->query = NULL;
        out->query_len = 0;
    }

    pos++;
    if (pos + 8 > head_end || memcmp(p + pos, "HTTP/", 5) != 0) {
        return SH_HTTP_MALFORMED;
    }
    if (p[pos + 6] != '.' || !isdigit((unsigned char)p[pos + 5]) ||
        !isdigit((unsigned char)p[pos + 7])) {
        return SH_HTTP_MALFORMED;
    }
    out->version_major = p[pos + 5] - '0';
    out->version_minor = p[pos + 7] - '0';
    if (out->version_major != 1) {
        return SH_HTTP_UNSUPPORTED;
    }

    /* ---- headers ---- */
    size_t cursor = 0;
    size_t first_len = line_span(p, head_end, 0, &cursor);
    (void)first_len;
    out->keep_alive = (out->version_minor >= 1);

    while (cursor < head_end) {
        size_t next = 0;
        size_t llen = line_span(p, head_end, cursor, &next);
        const char *line = p + cursor;
        if (llen == 0) {
            break;    /* 头部结束 */
        }
        if (++out->header_count > SH_MAX_HEADER_COUNT) {
            return SH_HTTP_TOO_LARGE;
        }
        size_t vlen = 0;
        if (header_value(line, llen, "content-length", 14, &vlen) != NULL) {
            const char *v = header_value(line, llen, "content-length", 14, &vlen);
            uint64_t n = 0;
            for (size_t i = 0; i < vlen; i++) {
                if (!isdigit((unsigned char)v[i])) {
                    return SH_HTTP_MALFORMED;
                }
                n = n * 10u + (uint64_t)(v[i] - '0');
                if (n > (1ull << 40)) {
                    return SH_HTTP_TOO_LARGE;
                }
            }
            out->content_length = n;
        } else if (header_value(line, llen, "transfer-encoding", 17, &vlen) != NULL) {
            const char *v = header_value(line, llen, "transfer-encoding", 17, &vlen);
            if (vlen >= 7 && strncasecmp(v, "chunked", 7) == 0) {
                out->chunked = true;
            }
        } else if (header_value(line, llen, "connection", 10, &vlen) != NULL) {
            const char *v = header_value(line, llen, "connection", 10, &vlen);
            if (vlen >= 5 && strncasecmp(v, "close", 5) == 0) {
                out->keep_alive = false;
            } else if (vlen >= 10 && strncasecmp(v, "keep-alive", 10) == 0) {
                out->keep_alive = true;
            }
        } else if (header_value(line, llen, "host", 4, &vlen) != NULL) {
            out->has_host = true;
        } else if (header_value(line, llen, "expect", 6, &vlen) != NULL) {
            const char *v = header_value(line, llen, "expect", 6, &vlen);
            if (vlen >= 12 && strncasecmp(v, "100-continue", 12) == 0) {
                out->expect_continue = true;
            }
        }
        cursor = next;
    }
    return SH_HTTP_OK;
}

sh_http_parse_status sh_http_parse_complete(const uint8_t *data, size_t len,
                                            sh_http_head *out)
{
    return sh_http_parse_head(data, len, out);
}

const char *sh_http_header(const sh_http_head *h, const char *name,
                           size_t *value_len)
{
    if (h == NULL || h->raw == NULL || name == NULL) {
        return NULL;
    }
    size_t name_len = strlen(name);
    size_t cursor = 0;
    size_t first_len = line_span((const char *)h->raw, h->head_len, 0, &cursor);
    (void)first_len;
    while (cursor < h->head_len) {
        size_t next = 0;
        size_t llen = line_span((const char *)h->raw, h->head_len, cursor, &next);
        if (llen == 0) {
            break;
        }
        const char *v = header_value((const char *)h->raw + cursor, llen,
                                     name, name_len, value_len);
        if (v != NULL) {
            return v;
        }
        cursor = next;
    }
    return NULL;
}

bool sh_http_header_next(const sh_http_head *h, size_t *cursor,
                         const char **name, size_t *name_len,
                         const char **value, size_t *value_len)
{
    if (h == NULL || h->raw == NULL || cursor == NULL) {
        return false;
    }
    if (*cursor == 0) {
        size_t next = 0;
        (void)line_span((const char *)h->raw, h->head_len, 0, &next);
        *cursor = next;
    }
    while (*cursor < h->head_len) {
        size_t next = 0;
        size_t llen = line_span((const char *)h->raw, h->head_len, *cursor, &next);
        const char *line = (const char *)h->raw + *cursor;
        if (llen == 0) {
            return false;
        }
        const char *colon = memchr(line, ':', llen);
        if (colon != NULL) {
            *name = line;
            *name_len = (size_t)(colon - line);
            const char *v = colon + 1;
            const char *end = line + llen;
            while (v < end && (*v == ' ' || *v == '\t')) {
                v++;
            }
            *value = v;
            *value_len = (size_t)(end - v);
            *cursor = next;
            return true;
        }
        *cursor = next;
    }
    return false;
}

static bool is_hop_by_hop(const char *name, size_t len)
{
    static const char *const names[] = {
        "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
        "proxy-authorization", "te", "trailer", "upgrade"
    };
    for (size_t i = 0; i < SH_ARRAY_LEN(names); i++) {
        if (strlen(names[i]) == len && strncasecmp(name, names[i], len) == 0) {
            return true;
        }
    }
    return false;
}

ssize_t sh_http_build_request(const sh_http_head *h, const char *new_target,
                              const sh_http_extra_header *hdrs, size_t nhdrs,
                              sh_buf *out)
{
    return sh_http_build_request_ex(h, new_target, hdrs, nhdrs, false, out);
}

ssize_t sh_http_build_request_ex(const sh_http_head *h, const char *new_target,
                                 const sh_http_extra_header *hdrs, size_t nhdrs,
                                 bool keep_alive, sh_buf *out)
{
    if (h == NULL || out == NULL) {
        return -1;
    }
    size_t before = sh_buf_readable(out);
    const char *target = new_target != NULL ? new_target : h->target;
    size_t target_len = new_target != NULL ? strlen(new_target) : h->target_len;

    sh_buf_appendf(out, "%s %.*s HTTP/%d.%d\r\n",
                   h->method_str, (int)target_len, target,
                   h->version_major, h->version_minor);

    /* 透传端到端头部，剔除 hop-by-hop 与 Host（由我们重写） */
    size_t cursor = 0;
    const char *name = NULL;
    const char *value = NULL;
    size_t name_len = 0;
    size_t value_len = 0;
    while (sh_http_header_next(h, &cursor, &name, &name_len, &value, &value_len)) {
        if (is_hop_by_hop(name, name_len)) {
            continue;
        }
        if (name_len == 4 && strncasecmp(name, "host", 4) == 0) {
            continue;
        }
        sh_buf_append(out, name, name_len);
        sh_buf_append(out, ": ", 2);
        sh_buf_append(out, value, value_len);
        sh_buf_append(out, "\r\n", 2);
    }
    for (size_t i = 0; i < nhdrs; i++) {
        if (hdrs[i].name == NULL || hdrs[i].value == NULL) {
            continue;
        }
        sh_buf_appendf(out, "%s: %s\r\n", hdrs[i].name, hdrs[i].value);
    }
    /* 上游连接是否复用由 Proxy 的分帧状态决定 */
    if (keep_alive) {
        sh_buf_append(out, "Connection: keep-alive\r\n\r\n", 26);
    } else {
        sh_buf_append(out, "Connection: close\r\n\r\n", 21);
    }

    if (sh_buf_readable(out) == before) {
        return -1;
    }
    return (ssize_t)(sh_buf_readable(out) - before);
}

int sh_http_build_response(int code, const char *reason,
                           const sh_http_extra_header *hdrs, size_t nhdrs,
                           const void *body, size_t body_len, sh_buf *out)
{
    if (out == NULL) {
        return -1;
    }
    const char *r = reason != NULL ? reason : sh_http_reason(code);
    sh_buf_appendf(out, "HTTP/1.1 %d %s\r\n", code, r);
    for (size_t i = 0; i < nhdrs; i++) {
        if (hdrs[i].name != NULL && hdrs[i].value != NULL) {
            sh_buf_appendf(out, "%s: %s\r\n", hdrs[i].name, hdrs[i].value);
        }
    }
    sh_buf_appendf(out, "Content-Length: %zu\r\n\r\n", body_len);
    if (body != NULL && body_len > 0) {
        sh_buf_append(out, body, body_len);
    }
    return 0;
}

int sh_http_send_error(sh_buf *out, int code, const char *message)
{
    if (out == NULL) {
        return -1;
    }
    char body[512];
    int n = snprintf(body, sizeof body,
                     "<html><head><title>%d %s</title></head>"
                     "<body><h1>%d %s</h1><p>%s</p><hr><i>Safe-HTTP</i></body></html>\n",
                     code, sh_http_reason(code), code, sh_http_reason(code),
                     message != NULL ? message : "");
    if (n < 0) {
        return -1;
    }
    sh_http_extra_header hdrs[2] = {
        {"Content-Type", "text/html; charset=utf-8"},
        {"Server", "Safe-HTTP/1.0.0"},
    };
    return sh_http_build_response(code, NULL, hdrs, SH_ARRAY_LEN(hdrs),
                                  body, (size_t)n, out);
}

int sh_http_send_redirect(sh_buf *out, int code, const char *location)
{
    if (out == NULL || location == NULL) {
        return -1;
    }
    sh_http_extra_header hdrs[2] = {
        {"Location", location},
        {"Server", "Safe-HTTP/1.0.0"},
    };
    return sh_http_build_response(code, NULL, hdrs, SH_ARRAY_LEN(hdrs), NULL, 0, out);
}

ssize_t sh_url_decode(const char *in, size_t in_len, char *out, size_t cap)
{
    if (in == NULL || out == NULL || cap == 0) {
        return -1;
    }
    size_t w = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= in_len) {
                return -1;
            }
            int hi = 0;
            int lo = 0;
            for (int k = 0; k < 2; k++) {
                char h = in[i + 1 + (size_t)k];
                int v;
                if (h >= '0' && h <= '9') {
                    v = h - '0';
                } else if (h >= 'a' && h <= 'f') {
                    v = h - 'a' + 10;
                } else if (h >= 'A' && h <= 'F') {
                    v = h - 'A' + 10;
                } else {
                    return -1;
                }
                if (k == 0) {
                    hi = v;
                } else {
                    lo = v;
                }
            }
            c = (char)((hi << 4) | lo);
            i += 2;
        }
        if (w + 1u >= cap) {
            return -1;
        }
        out[w++] = c;
    }
    out[w] = '\0';
    return (ssize_t)w;
}

ssize_t sh_url_normalize_path(const char *in, size_t in_len,
                              char *out, size_t cap)
{
    if (in == NULL || out == NULL || cap < 2) {
        return -1;
    }
    size_t w = 0;
    out[w++] = '/';
    size_t i = 0;
    while (i < in_len && in[i] == '/') {
        i++;    /* 折叠开头的重复 '/' */
    }
    while (i < in_len) {
        size_t start = i;
        while (i < in_len && in[i] != '/') {
            i++;
        }
        size_t seg = i - start;
        if (seg == 0) {
            i++;
            continue;
        }
        if (seg == 1 && in[start] == '.') {
            i++;
            continue;    /* '.' 段丢弃 */
        }
        if (seg == 2 && in[start] == '.' && in[start + 1] == '.') {
            return -1;   /* 目录穿越：直接拒绝 */
        }
        if (w > 1 && out[w - 1] != '/') {
            if (w + 1 >= cap) {
                return -1;
            }
            out[w++] = '/';
        }
        if (w + seg >= cap) {
            return -1;
        }
        memcpy(out + w, in + start, seg);
        w += seg;
        i++;
    }
    out[w] = '\0';
    return (ssize_t)w;
}
