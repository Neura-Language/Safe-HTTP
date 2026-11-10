// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 纯 C 上游测试桩（替代 /tmp/up.py，用于压测/联调）
 *
 * 为什么不用 Python http.server：
 *   BaseHTTPRequestHandler 先 end_headers() 发头、再 wfile.write(body) 发体，
 *   两次小写 + 未关 Nagle → 触发 TCP 延迟 ACK，稳定出现 ~40ms 尖峰，
 *   把 P90 从亚毫秒级污染到 40ms+，完全掩盖真实的代理/加密开销。
 *
 * 本桩的做法：
 *   1. 每个连接 fork 一个子进程（测试桩无需高并发模型，简单即正确）；
 *   2. 子进程设置 TCP_NODELAY；
 *   3. 响应头 + 正文 **拼成一次 write()** 发出（单段，天然规避 Nagle）；
 *   4. 支持 HTTP/1.1 keep-alive 与多请求复用；
 *   5. /echo 返回 JSON（{"ok","path","host","neura","method"}）；
 *      其它 GET 路径从 --webroot 目录读真实静态文件（用于"真实页面"场景）。
 *
 * 用法：
 *   build/proxy/upstream-stub [--listen 127.0.0.1:19080] [--webroot DIR]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define STUB_REQ_MAX   (64u * 1024u)
#define STUB_BODY_MAX  (1024u * 1024u)

static char g_webroot[512] = "";

/* 在头部区域内做大小写无关的取值，返回长度（0 表示没有该头） */
static size_t head_value(const char *head, size_t head_len, const char *name,
                         const char **val_out)
{
    size_t nlen = strlen(name);
    size_t i = 0;
    while (i + 1 < head_len && !(head[i] == '\r' && head[i + 1] == '\n')) {
        i++;
    }
    i += 2;
    while (i + 1 < head_len) {
        size_t eol = i;
        while (eol + 1 < head_len && !(head[eol] == '\r' && head[eol + 1] == '\n')) {
            eol++;
        }
        if (eol == i) {
            break;
        }
        if (eol - i > nlen && head[i + nlen] == ':') {
            size_t k = 0;
            while (k < nlen) {
                char a = head[i + k];
                char b = name[k];
                if (a >= 'A' && a <= 'Z') {
                    a = (char)(a + 32);
                }
                if (b >= 'A' && b <= 'Z') {
                    b = (char)(b + 32);
                }
                if (a != b) {
                    break;
                }
                k++;
            }
            if (k == nlen) {
                size_t vs = i + nlen + 1;
                while (vs < eol && (head[vs] == ' ' || head[vs] == '\t')) {
                    vs++;
                }
                size_t ve = eol;
                while (ve > vs && (head[ve - 1] == ' ' || head[ve - 1] == '\t')) {
                    ve--;
                }
                if (val_out != NULL) {
                    *val_out = head + vs;
                }
                return ve - vs;
            }
        }
        i = eol + 2;
    }
    return 0;
}

/* JSON 字符串转义（只处理必要的引号/反斜杠/控制字符） */
static size_t json_escape(char *dst, size_t cap, const char *src, size_t len)
{
    size_t o = 0;
    for (size_t i = 0; i < len && o + 8 < cap; i++) {
        unsigned char ch = (unsigned char)src[i];
        if (ch == '"' || ch == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char)ch;
        } else if (ch < 0x20) {
            o += (size_t)snprintf(dst + o, cap - o, "\\u%04x", ch);
        } else {
            dst[o++] = (char)ch;
        }
    }
    dst[o] = '\0';
    return o;
}

/* 从 webroot 读真实页面；返回 0 成功 */
static int read_web(const char *path, char *body, size_t cap, size_t *len_out,
                    const char **ctype)
{
    if (g_webroot[0] == '\0') {
        return -1;
    }
    char rel[512];
    if (strcmp(path, "/") == 0) {
        snprintf(rel, sizeof rel, "/index.html");
    } else {
        snprintf(rel, sizeof rel, "%s", path);
    }
    if (strstr(rel, "..") != NULL) {
        return -1;
    }
    char full[1100];
    snprintf(full, sizeof full, "%s%s", g_webroot, rel);

    FILE *fp = fopen(full, "rb");
    if (fp == NULL) {
        return -1;
    }
    size_t n = fread(body, 1, cap - 1, fp);
    fclose(fp);
    body[n] = '\0';
    *len_out = n;
    const char *ext = strrchr(rel, '.');
    if (ext != NULL && strcasecmp(ext, ".css") == 0) {
        *ctype = "text/css; charset=utf-8";
    } else if (ext != NULL && strcasecmp(ext, ".js") == 0) {
        *ctype = "application/javascript; charset=utf-8";
    } else if (ext != NULL && strcasecmp(ext, ".png") == 0) {
        *ctype = "image/png";
    } else {
        *ctype = "text/html; charset=utf-8";
    }
    return 0;
}

static void serve_conn(int fd)
{
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    char *buf = (char *)malloc(STUB_REQ_MAX);
    if (buf == NULL) {
        return;
    }
    size_t used = 0;

    for (;;) {
        size_t head_len = 0;
        while (head_len == 0) {
            for (size_t i = 0; i + 3 < used; i++) {
                if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
                    buf[i + 3] == '\n') {
                    head_len = i + 4;
                    break;
                }
            }
            if (head_len > 0) {
                break;
            }
            if (used >= STUB_REQ_MAX) {
                goto done;
            }
            ssize_t n = read(fd, buf + used, STUB_REQ_MAX - used);
            if (n <= 0) {
                goto done;
            }
            used += (size_t)n;
        }

        const char *method = buf;
        size_t mlen = 0;
        while (mlen < head_len && buf[mlen] != ' ') {
            mlen++;
        }
        const char *target = buf + mlen + 1;
        size_t tlen = 0;
        while (mlen + 1 + tlen < head_len && target[tlen] != ' ') {
            tlen++;
        }
        if (mlen == 0 || tlen == 0) {
            goto done;
        }

        const char *host = "";
        size_t host_len = head_value(buf, head_len, "Host", &host);
        const char *neura = "";
        size_t neura_len = head_value(buf, head_len, "X-Neura-S2S", &neura);
        const char *conn_h = NULL;
        size_t conn_len = head_value(buf, head_len, "Connection", &conn_h);
        int wants_close = 0;
        if (conn_len >= 5) {
            for (size_t i = 0; i + 5 <= conn_len; i++) {
                if (strncasecmp(conn_h + i, "close", 5) == 0) {
                    wants_close = 1;
                    break;
                }
            }
        }

        char path[2048];
        size_t pl = tlen < sizeof path - 1 ? tlen : sizeof path - 1;
        memcpy(path, target, pl);
        path[pl] = '\0';
        char *qm = strchr(path, '?');
        if (qm != NULL) {
            *qm = '\0';
        }

        char *body = (char *)malloc(STUB_BODY_MAX);
        if (body == NULL) {
            goto done;
        }
        size_t blen = 0;
        const char *ctype = "application/json";

        if (strncmp(path, "/echo", 5) == 0) {
            char path_j[2 * 2048 + 16];
            char host_j[2 * 512 + 16];
            char neura_j[2 * 128 + 16];
            json_escape(path_j, sizeof path_j, target, tlen > 2048 ? 2048 : tlen);
            json_escape(host_j, sizeof host_j, host, host_len > 512 ? 512 : host_len);
            json_escape(neura_j, sizeof neura_j, neura,
                        neura_len > 128 ? 128 : neura_len);
            int n = snprintf(body, STUB_BODY_MAX,
                             "{\"ok\": true, \"path\": \"%s\", \"host\": \"%s\", "
                             "\"neura\": \"%s\", \"method\": \"%.*s\"}\n",
                             path_j, host_j, neura_j,
                             (int)(mlen > 16 ? 16 : mlen), method);
            blen = n > 0 ? (size_t)n : 0;
        } else if (read_web(path, body, STUB_BODY_MAX, &blen, &ctype) != 0) {
            free(body);
            body = NULL;
            static const char nf[] =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n"
                "Connection: close\r\n\r\nnot found\n";
            (void)write(fd, nf, sizeof nf - 1);
            goto done;
        }

        char resp_hdr[512];
        int rlen = snprintf(resp_hdr, sizeof resp_hdr,
                            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
                            "Content-Length: %zu\r\nServer: safe-http-upstream-stub/2\r\n"
                            "Connection: %s\r\n\r\n",
                            ctype, blen, wants_close ? "close" : "keep-alive");
        size_t total = (size_t)rlen + blen;
        char *out = (char *)malloc(total);
        if (out == NULL) {
            free(body);
            goto done;
        }
        memcpy(out, resp_hdr, (size_t)rlen);
        memcpy(out + rlen, body, blen);
        free(body);

        size_t off = 0;
        while (off < total) {
            ssize_t w = write(fd, out + off, total - off);
            if (w <= 0) {
                if (errno == EINTR) {
                    continue;
                }
                free(out);
                goto done;
            }
            off += (size_t)w;
        }
        free(out);

        memmove(buf, buf + head_len, used - head_len);
        used -= head_len;

        if (wants_close) {
            goto done;
        }
    }

done:
    free(buf);
    close(fd);
}

int main(int argc, char **argv)
{
    const char *listen_addr = "127.0.0.1:19080";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            listen_addr = argv[++i];
        } else if (strcmp(argv[i], "--webroot") == 0 && i + 1 < argc) {
            snprintf(g_webroot, sizeof g_webroot, "%s", argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("用法: %s [--listen 127.0.0.1:19080] [--webroot DIR]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "未知参数 %s\n", argv[i]);
            return 2;
        }
    }

    char host[128];
    snprintf(host, sizeof host, "%s", listen_addr);
    char *colon = strrchr(host, ':');
    if (colon == NULL) {
        fprintf(stderr, "--listen 需要 host:port\n");
        return 2;
    }
    *colon = '\0';
    unsigned port = (unsigned)atoi(colon + 1);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

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
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "非法监听地址 %s\n", host);
        return 2;
    }
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(lfd, 1024) != 0) {
        perror("listen");
        return 1;
    }
    printf("[upstream-stub] listening on %s:%u (pure C, single-write, nodelay, "
           "webroot=%s)\n", host, port, g_webroot[0] != '\0' ? g_webroot : "-");
    fflush(stdout);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(lfd);
            serve_conn(cfd);
            _exit(0);
        }
        if (pid < 0) {
            serve_conn(cfd);
        } else {
            close(cfd);
        }
    }
}
