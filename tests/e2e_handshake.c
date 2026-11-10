// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 端到端握手/回显测试（真实 epoll + TCP + KEM worker）
 *
 * 验证目标（对应本轮两个新文件的职责）：
 *   1. 自建 ET epoll reactor 能 accept / 读 / 写；
 *   2. 握手胶水在当前线程推进，X-Wing 运算在 KEM worker 中完成，
 *      通过 eventfd 唤醒主循环并用 conn_id 找回连接（不串连接）；
 *   3. 会话建立后明文双向收发正确（ping → pong）；
 *   4. 服务端 0.3s 棘轮至少发生一次（RATCHET_PERIOD_MS=300）。
 *
 * 两个 reactor 分别跑在独立线程，客户端主动 connect。
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "network.h"
#include "security.h"

#define TEST_MSG "ping"
#define TEST_REPLY "pong"

static sh_reactor g_server;
static sh_reactor g_client;

static volatile int g_server_ready;   /* 服务端收到 ping 并回 pong */
static volatile int g_client_ready;   /* 客户端收到 pong */
static volatile int g_failed;

static void mark_fail(const char *who, const char *why)
{
    if (!g_failed) {
        printf("FAIL: %s: %s\n", who, why);
        g_failed = 1;
    }
}

/* ------------------------------------------------------------------ 服务端 */
static int server_on_read(sh_reactor *r, sh_conn *c)
{
    for (;;) {
        /* ET：把 socket 读到 EAGAIN */
        size_t before = sh_buf_readable(&c->in);
        if (sh_buf_reserve(&c->in, SH_PREAUTH_CAP) != 0) {
            return -1;
        }
        ssize_t n = read(c->fd, c->in.data + c->in.wpos, sh_buf_writable(&c->in));
        if (n > 0) {
            c->in.wpos += (size_t)n;
            r->stats.bytes_client_in += (uint64_t)n;
            continue;
        }
        if (n == 0) {
            return -1;    /* 对端关闭 */
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (sh_buf_readable(&c->in) == before && before == 0) {
                return 0;
            }
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }

    if (c->crypto == SH_CRYPTO_PLAIN) {
        if (sh_crypto_start(r, c, NS2S_ROLE_SERVER) != NS2S_OK) {
            mark_fail("server", "sh_crypto_start");
            return -1;
        }
    }
    if (c->crypto == SH_CRYPTO_HANDSHAKE) {
        int rc = sh_crypto_pump(r, c);
        if (rc != NS2S_OK) {
            mark_fail("server", "handshake pump");
            return -1;
        }
        if (sh_buf_readable(&c->out) > 0) {
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
    }
    if (c->crypto != SH_CRYPTO_READY) {
        return 0;
    }

    sh_buf plain;
    sh_buf_init(&plain, 4096);
    ssize_t got = sh_crypto_read(r, c, &plain);
    if (got < 0) {
        sh_buf_free(&plain);
        mark_fail("server", "decrypt");
        return -1;
    }
    if (got > 0) {
        size_t len = 0;
        const uint8_t *p = sh_buf_peek(&plain, &len);
        if (len == strlen(TEST_MSG) && memcmp(p, TEST_MSG, len) == 0) {
            if (sh_crypto_write(r, c, (const uint8_t *)TEST_REPLY,
                                strlen(TEST_REPLY)) != NS2S_OK) {
                mark_fail("server", "encrypt reply");
                sh_buf_free(&plain);
                return -1;
            }
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
            g_server_ready = 1;
        } else {
            mark_fail("server", "明文内容不符");
        }
    }
    sh_buf_free(&plain);
    return 0;
}

static int server_on_write(sh_reactor *r, sh_conn *c)
{
    (void)sh_conn_flush(r, c, c->fd, &c->out);
    (void)sh_conn_want(r, c, true, false);
    return 0;
}

static int server_on_tick(sh_reactor *r, sh_conn *c)
{
    return sh_crypto_tick(r, c);
}

static void server_on_close(sh_reactor *r, sh_conn *c)
{
    (void)r;
    (void)c;
}

static const sh_conn_hooks k_server_hooks = {
    .name = "server",
    .on_client_read = server_on_read,
    .on_client_write = server_on_write,
    .on_tick = server_on_tick,
    .on_close = server_on_close,
};

/* ------------------------------------------------------------------ 客户端 */
static volatile int g_connect_done;
static volatile int g_client_started;

static int client_on_read(sh_reactor *r, sh_conn *c)
{
    for (;;) {
        if (sh_buf_reserve(&c->in, SH_PREAUTH_CAP) != 0) {
            return -1;
        }
        ssize_t n = read(c->fd, c->in.data + c->in.wpos, sh_buf_writable(&c->in));
        if (n > 0) {
            c->in.wpos += (size_t)n;
            continue;
        }
        if (n == 0) {
            return -1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }

    if (c->crypto == SH_CRYPTO_HANDSHAKE) {
        int rc = sh_crypto_pump(r, c);
        if (rc != NS2S_OK) {
            mark_fail("client", "handshake pump");
            return -1;
        }
        if (sh_buf_readable(&c->out) > 0) {
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
        if (c->crypto == SH_CRYPTO_READY && !g_client_started) {
            g_client_started = 1;
            if (sh_crypto_write(r, c, (const uint8_t *)TEST_MSG,
                                strlen(TEST_MSG)) != NS2S_OK) {
                mark_fail("client", "encrypt ping");
                return -1;
            }
            (void)sh_conn_flush(r, c, c->fd, &c->out);
            (void)sh_conn_want(r, c, true, false);
        }
    }
    if (c->crypto != SH_CRYPTO_READY) {
        return 0;
    }
    sh_buf plain;
    sh_buf_init(&plain, 4096);
    ssize_t got = sh_crypto_read(r, c, &plain);
    if (got < 0) {
        sh_buf_free(&plain);
        mark_fail("client", "decrypt");
        return -1;
    }
    if (got > 0) {
        size_t len = 0;
        const uint8_t *p = sh_buf_peek(&plain, &len);
        if (len == strlen(TEST_REPLY) && memcmp(p, TEST_REPLY, len) == 0) {
            g_client_ready = 1;
        }
    }
    sh_buf_free(&plain);
    return 0;
}

static int client_on_write(sh_reactor *r, sh_conn *c)
{
    if (!g_connect_done) {
        int done = sh_net_connect_result(c->fd);
        if (done < 0) {
            mark_fail("client", "connect failed");
            return -1;
        }
        g_connect_done = 1;
        sh_net_set_nodelay(c->fd, true);
        if (sh_crypto_start(r, c, NS2S_ROLE_CLIENT) != NS2S_OK) {
            mark_fail("client", "crypto start");
            return -1;
        }
    }
    (void)sh_conn_flush(r, c, c->fd, &c->out);
    (void)sh_conn_want(r, c, true, false);
    return 0;
}

static int client_on_tick(sh_reactor *r, sh_conn *c)
{
    return sh_crypto_tick(r, c);
}

static const sh_conn_hooks k_client_hooks = {
    .name = "client",
    .on_client_read = client_on_read,
    .on_client_write = client_on_write,
    .on_tick = client_on_tick,
    .on_close = server_on_close,
};

static void *server_thread(void *arg)
{
    (void)arg;
    sh_reactor_run(&g_server);
    return NULL;
}

static void *client_thread(void *arg)
{
    (void)arg;
    sh_reactor_run(&g_client);
    return NULL;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    sh_log_init(stderr, SH_LOG_WARN);
    if (sh_neura_global_init() != NS2S_OK) {
        printf("FAIL: crypto init\n");
        return 1;
    }

    uint8_t rootkey[SH_ROOTKEY_BYTES];
    sh_rootkey_generate(rootkey);

    sh_settings ss;
    sh_settings_defaults(&ss);
    ss.listen_host = "127.0.0.1";
    ss.listen_port = 0;             /* 内核分配端口 */
    ss.max_frame = 4096;
    ss.kem_workers = 2;
    ss.trust_anchor_required = false;   /* 本测试只验握手/收发/棘轮 */

    if (sh_reactor_init(&g_server, &ss, NULL, NULL) != 0 ||
        sh_reactor_init(&g_client, &ss, NULL, NULL) != 0) {
        printf("FAIL: reactor init\n");
        return 1;
    }
    g_server.root_key[0] = 0;
    memcpy(g_server.root_key, rootkey, sizeof rootkey);
    g_server.have_root_key = true;
    memcpy(g_client.root_key, rootkey, sizeof rootkey);
    g_client.have_root_key = true;
    g_server.hooks = &k_server_hooks;
    g_client.hooks = &k_client_hooks;

    if (sh_reactor_listen(&g_server) != 0) {
        printf("FAIL: listen\n");
        return 1;
    }
    uint16_t port = sh_reactor_port(&g_server);
    if (port == 0) {
        printf("FAIL: no port\n");
        return 1;
    }
    printf("server listening on 127.0.0.1:%u\n", (unsigned)port);

    pthread_t ts, tc;
    pthread_create(&ts, NULL, server_thread, NULL);
    pthread_create(&tc, NULL, client_thread, NULL);

    bool in_progress = false;
    int fd = sh_net_connect("127.0.0.1", port, &in_progress);
    if (fd < 0) {
        printf("FAIL: connect fd\n");
        return 1;
    }
    g_connect_done = !in_progress;    /* 立即连上则无需等 EPOLLOUT */

    sh_addr peer;
    memset(&peer, 0, sizeof peer);
    sh_conn *cc = sh_conn_acquire(&g_client, fd, &peer);
    if (cc == NULL) {
        printf("FAIL: client conn\n");
        return 1;
    }
    if (g_connect_done) {
        if (sh_crypto_start(&g_client, cc, NS2S_ROLE_CLIENT) != NS2S_OK) {
            printf("FAIL: client crypto start\n");
            return 1;
        }
        sh_conn_want(&g_client, cc, true, in_progress);
    } else {
        sh_conn_want(&g_client, cc, true, true);
    }
    sh_reactor_wakeup(&g_client);

    for (int i = 0; i < 200 && !g_failed && !(g_server_ready && g_client_ready); i++) {
        usleep(50 * 1000);            /* 最多 10s */
    }

    /* 握手+回显成功后，再跑 1.4s 观测 0.3s KEM 棘轮是否真的发生 */
    uint64_t ratchets_after_msg = 0;
    if (!g_failed && g_server_ready && g_client_ready) {
        ratchets_after_msg = g_server.stats.ratchets + g_client.stats.ratchets;
        for (int i = 0; i < 28 && !g_failed; i++) {
            usleep(50 * 1000);        /* 1.4s ≈ 4 个棘轮周期 */
        }
    }

    sh_reactor_stop(&g_server);
    sh_reactor_stop(&g_client);
    pthread_join(ts, NULL);
    pthread_join(tc, NULL);

    uint64_t ratchets = g_server.stats.ratchets + g_client.stats.ratchets;
    printf("stats: accepted_s=%llu ok_s=%llu ok_c=%llu ratchets=%llu\n",
           (unsigned long long)g_server.stats.conns_accepted,
           (unsigned long long)g_server.stats.handshakes_ok,
           (unsigned long long)g_client.stats.handshakes_ok,
           (unsigned long long)ratchets);
    printf("server_ready=%d client_ready=%d\n", g_server_ready, g_client_ready);

    sh_reactor_destroy(&g_server);
    sh_reactor_destroy(&g_client);

    if (g_failed || !g_server_ready || !g_client_ready) {
        printf("RESULT = FAIL\n");
        return 1;
    }
    if (ratchets == 0) {
        printf("RESULT = FAIL (0.3s 棘轮未发生)\n");
        return 1;
    }
    printf("RESULT = PASS (握手 + 明文回显 + 棘轮 %llu 次)\n",
           (unsigned long long)(ratchets - ratchets_after_msg));
    return 0;
}
