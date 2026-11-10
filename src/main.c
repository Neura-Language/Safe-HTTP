// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 进程入口
 *
 * 职责：
 *   1. 完整 CLI 解析（--check-config / --dump-config / --print-fingerprint）；
 *   2. 启动装配：日志 → 加密库 → RootKey → config.ncf → WAF →
 *      reactor（ET epoll + KEM pool）→ 监听（主端口 + 可选 443）→ 运行；
 *   3. systemd 友好：前台运行、SIGTERM/SIGINT 优雅退出、PID 文件；
 *   4. 装配失败 fail-close；但配置文件缺失时回落到"普通访客可访问"的内建
 *      策略，并显式告警（避免一个空目录把整个网关变成全站 403）。
 *
 * 进程模型：单进程 + 单 epoll + KEM worker 线程池。不再 fork 多个 worker：
 *   - systemd Type=simple 只跟踪一个 PID；
 *   - 单进程内 ET accept 已能轻松处理高并发；
 *   - 避免多 worker 各自绑定端口时依赖 SO_REUSEPORT 的可用性。
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "network.h"
#include "safe_http.h"
#include "security.h"
#include "waf.h"

#if SH_MODE_PROXY
#  include "neura_proxy.h"
#endif

typedef enum sh_cmd {
    SH_CMD_RUN = 0,
    SH_CMD_CHECK_CONFIG,
    SH_CMD_DUMP_CONFIG,
    SH_CMD_PRINT_FINGERPRINT
} sh_cmd;

typedef struct sh_cli {
    sh_cmd      cmd;
    const char *cmd_path;
    bool        show_help;
    bool        show_version;
    bool        log_file_explicit;
} sh_cli;

static volatile sig_atomic_t g_wake_fd = -1;

/* ==========================================================================
 * 信号处理（systemd: ExecStop 发 SIGTERM）
 *
 * 信号处理函数里只做两件异步信号安全的事：
 *   1. g_stop = 1;
 *   2. write(g_wake_fd, ...) 唤醒 epoll。
 * 真正的退出由 sh_reactor_run() 的三个检查点完成。
 * ========================================================================== */
static void on_terminate(int sig)
{
    (void)sig;
    g_stop = 1;
    int fd = (int)g_wake_fd;
    if (fd >= 0) {
        uint64_t one = 1;
        ssize_t n = write(fd, &one, sizeof one);
        (void)n;
    }
}

static void on_hangup(int sig)
{
    (void)sig;
    /* v1.0 不做配置热重载：避免半更新配置带来的策略不一致 */
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = on_terminate;
    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGINT, &sa, NULL) != 0) {
        return -1;
    }
    sa.sa_handler = on_hangup;
    if (sigaction(SIGHUP, &sa, NULL) != 0) {
        return -1;
    }
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

/* ==========================================================================
 * CLI
 * ========================================================================== */
static void print_version(void)
{
    printf("%s %s (%s 模式, ET epoll)\n", SH_NAME, SH_VERSION_STRING,
           SH_MODE_NAME);
    printf("crypto: Neura-S2S (X25519 + ML-KEM-768 / X-Wing), libsodium %s\n",
           sh_neura_crypto_version());
}

static void print_help(const char *argv0)
{
    printf("用法: %s [选项]\n\n", argv0);
    printf("运行模式（编译期决定）: %s\n\n", SH_MODE_UP_NAME);
    printf("通用选项:\n");
    printf("  --config PATH            配置文件（默认 %s）\n", SH_DEFAULT_CONFIG_PATH);
    printf("  --root-key PATH          RootKey 文件（默认 %s）\n", SH_DEFAULT_ROOTKEY_PATH);
    printf("  --listen HOST:PORT       主监听地址（默认 %s:%u）\n",
           SH_DEFAULT_LISTEN_HOST, (unsigned)SH_DEFAULT_LISTEN_PORT);
    printf("                           也接受裸端口: --listen 443\n");
    printf("  --listen-tls HOST:PORT   额外监听口（如 0.0.0.0:443）\n");
    printf("  --https HOST:PORT        --listen-tls 的别名\n");
    printf("  --anchor-host HOST       信任锚域名（TXT 记录所在域）\n");
    printf("  --require-trust-anchor   强制校验 DNS TXT 指纹（DoH 未实现时拒绝启动）\n");
    printf("  --no-trust-anchor       关闭 TXT 校验（默认，仅内网/调试）\n");
    printf("  --log-level LEVEL        fatal|error|warn|info|debug|trace（默认 info）\n");
    printf("  --log-file PATH          日志文件（默认 stderr）\n");
    printf("  --pid-file PATH          PID 文件（默认 %s）\n", SH_DEFAULT_PID_PATH);
    printf("  --max-connections N      单进程连接上限（默认 %u）\n", SH_MAX_CONNECTIONS);
    printf("  --max-frame BYTES        单帧明文上限（默认 %u）\n", SH_DEFAULT_MAX_FRAME);
    printf("  --kem-workers N          KEM worker 线程数（默认 %u）\n", SH_KEM_WORKERS);
    printf("  --foreground             前台运行（默认行为）\n");
#if SH_MODE_PROXY
    printf("  --upstream HOST:PORT     上游地址（默认 %s:%u）\n",
           SH_DEFAULT_UPSTREAM_HOST, (unsigned)SH_DEFAULT_UPSTREAM_PORT);
#else
    printf("  --static-root PATH       静态站点根目录（默认 %s）\n", SH_DEFAULT_STATIC_ROOT);
#endif
    printf("\n诊断:\n");
    printf("  --check-config [PATH]    只校验配置语法后退出\n");
    printf("  --dump-config [PATH]     解析并打印规则后退出\n");
    printf("  --print-fingerprint [PATH]  打印 RootKey 的信任锚指纹后退出\n");
    printf("  -v, --version            版本信息\n");
    printf("  -h, --help               本帮助\n");
}

/* 静态缓冲区托管解析出的 host；进程启动期只会写一次 */
static char g_listen_host[256];
static char g_tls_host[256];
static char g_upstream_host[256];

/*
 * 解析监听地址，支持：
 *   1.2.3.4:443      [::1]:443      :443      443
 */
static bool parse_hostport(const char *s, char *host, size_t host_cap,
                           uint16_t *port)
{
    if (s == NULL || s[0] == '\0' || host == NULL || host_cap == 0 ||
        port == NULL) {
        return false;
    }

    const char *colon = strrchr(s, ':');
    const char *port_str = NULL;
    size_t host_len = 0;

    if (colon == NULL) {
        /* 裸端口 */
        port_str = s;
        host_len = 0;
    } else {
        port_str = colon + 1;
        host_len = (size_t)(colon - s);
    }

    char *end = NULL;
    long p = strtol(port_str, &end, 10);
    if (end == port_str || *end != '\0' || p < 0 || p > 65535) {
        return false;
    }

    host[0] = '\0';
    if (host_len > 0) {
        if (host_len >= host_cap) {
            return false;
        }
        memcpy(host, s, host_len);
        host[host_len] = '\0';
        /* 去掉 IPv6 字面量方括号：[::1] -> ::1 */
        if (host[0] == '[' && host[host_len - 1] == ']') {
            memmove(host, host + 1, host_len - 2);
            host[host_len - 2] = '\0';
        }
    }
    *port = (uint16_t)p;
    return true;
}

static int parse_cli(sh_settings *s, sh_cli *cli, int argc, char **argv,
                     char *err, size_t errcap)
{
    memset(cli, 0, sizeof *cli);
    cli->cmd = SH_CMD_RUN;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *next = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            cli->show_help = true;
            return 0;
        }
        if (strcmp(a, "-v") == 0 || strcmp(a, "--version") == 0) {
            cli->show_version = true;
            return 0;
        }
        if (strcmp(a, "--check-config") == 0) {
            cli->cmd = SH_CMD_CHECK_CONFIG;
            if (next != NULL && next[0] != '-') {
                cli->cmd_path = next;
                i++;
            }
            continue;
        }
        if (strcmp(a, "--dump-config") == 0) {
            cli->cmd = SH_CMD_DUMP_CONFIG;
            if (next != NULL && next[0] != '-') {
                cli->cmd_path = next;
                i++;
            }
            continue;
        }
        if (strcmp(a, "--print-fingerprint") == 0) {
            cli->cmd = SH_CMD_PRINT_FINGERPRINT;
            if (next != NULL && next[0] != '-') {
                cli->cmd_path = next;
                i++;
            }
            continue;
        }
        if (strcmp(a, "--foreground") == 0) {
            s->foreground = true;
            continue;
        }
        if (strcmp(a, "--require-trust-anchor") == 0) {
            s->trust_anchor_required = true;
            continue;
        }
        if (strcmp(a, "--no-trust-anchor") == 0) {
            s->trust_anchor_required = false;
            continue;
        }

        if (next == NULL) {
            snprintf(err, errcap, "选项 %s 缺少参数", a);
            return -1;
        }
        if (strcmp(a, "--config") == 0) {
            s->config_path = next;
        } else if (strcmp(a, "--root-key") == 0) {
            s->root_key_path = next;
        } else if (strcmp(a, "--anchor-host") == 0) {
            s->anchor_host = next;
        } else if (strcmp(a, "--doh") == 0) {
            s->doh_url = next;
        } else if (strcmp(a, "--log-level") == 0) {
            int lvl = sh_log_level_from_string(next);
            if (lvl < 0) {
                snprintf(err, errcap, "非法日志级别 '%s'", next);
                return -1;
            }
            s->log_level = lvl;
        } else if (strcmp(a, "--log-file") == 0) {
            s->log_path = next;
            cli->log_file_explicit = true;
        } else if (strcmp(a, "--pid-file") == 0) {
            s->pid_path = next;
        } else if (strcmp(a, "--listen") == 0) {
            uint16_t port = 0;
            if (!parse_hostport(next, g_listen_host, sizeof g_listen_host,
                                &port)) {
                snprintf(err, errcap, "--listen 需要 HOST:PORT（收到 '%s'）", next);
                return -1;
            }
            if (g_listen_host[0] != '\0') {
                s->listen_host = g_listen_host;
            }
            s->listen_port = port;
        } else if (strcmp(a, "--listen-tls") == 0 ||
                   strcmp(a, "--https") == 0) {
            uint16_t port = 0;
            if (!parse_hostport(next, g_tls_host, sizeof g_tls_host, &port) ||
                port == 0) {
                snprintf(err, errcap, "%s 需要 HOST:PORT（收到 '%s'）", a, next);
                return -1;
            }
            s->listen_tls_port = port;
            if (g_tls_host[0] != '\0') {
                s->listen_tls_host = g_tls_host;
            }
#if SH_MODE_PROXY
        } else if (strcmp(a, "--upstream") == 0) {
            uint16_t port = 0;
            if (!parse_hostport(next, g_upstream_host, sizeof g_upstream_host,
                                &port) || port == 0) {
                snprintf(err, errcap, "--upstream 需要 HOST:PORT（收到 '%s'）",
                         next);
                return -1;
            }
            s->upstream_host = g_upstream_host;
            s->upstream_port = port;
#else
        } else if (strcmp(a, "--static-root") == 0) {
            s->static_root = next;
#endif
        } else if (strcmp(a, "--max-connections") == 0) {
            char *end = NULL;
            unsigned long v = strtoul(next, &end, 10);
            if (end == next || *end != '\0' || v < 16 || v > 1000000ul) {
                snprintf(err, errcap, "--max-connections 取值需在 16..1000000");
                return -1;
            }
            s->max_connections = (uint32_t)v;
        } else if (strcmp(a, "--max-frame") == 0) {
            char *end = NULL;
            unsigned long v = strtoul(next, &end, 10);
            if (end == next || *end != '\0' || v < 4096 || v > (16u << 20)) {
                snprintf(err, errcap, "--max-frame 取值需在 4096..16777216");
                return -1;
            }
            s->max_frame = (uint32_t)v;
        } else if (strcmp(a, "--kem-workers") == 0) {
            char *end = NULL;
            unsigned long v = strtoul(next, &end, 10);
            if (end == next || *end != '\0' || v < 1 || v > 32) {
                snprintf(err, errcap, "--kem-workers 取值需在 1..32");
                return -1;
            }
            s->kem_workers = (uint32_t)v;
        } else {
            snprintf(err, errcap, "未知选项 '%s'（--help 查看用法）", a);
            return -1;
        }
        i++;
    }
    return 0;
}

/* ==========================================================================
 * PID 文件
 * ========================================================================== */
static int write_pid_file(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        SH_LOGW("无法写入 PID 文件 %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(fp, "%ld\n", (long)getpid());
    fclose(fp);
    return 0;
}

/* ==========================================================================
 * 子命令
 * ========================================================================== */
static int cmd_print_fingerprint(const sh_settings *s, const char *path)
{
    const char *key_path = path != NULL ? path : s->root_key_path;
    uint8_t key[SH_ROOTKEY_BYTES];
    char err[192] = {0};
    bool created = false;

    if (sh_rootkey_load_or_create(key_path, 0600, &created, key, err,
                                  sizeof err) != NS2S_OK) {
        fprintf(stderr, "错误: %s\n", err);
        return 1;
    }
    if (created) {
        fprintf(stderr, "已生成新的 RootKey: %s\n", key_path);
    }
    char fp[SH_FINGERPRINT_HEX_LEN];
    char hex[SH_ROOTKEY_HEX_LEN];
    if (sh_anchor_fingerprint_hex(key, fp) != NS2S_OK ||
        sh_rootkey_hex(key, hex) != NS2S_OK) {
        fprintf(stderr, "错误: 指纹计算失败\n");
        return 1;
    }
    char txt[200];
    sh_anchor_format_txt(key, txt, sizeof txt);
    printf("%s\n", fp);
    fprintf(stderr, "rootkey = %s\n", hex);
    fprintf(stderr, "txt     = %s\n", txt);
    return 0;
}

static int cmd_check_or_dump(const sh_settings *s, const char *path, bool dump)
{
    const char *cfg_path = path != NULL ? path : s->config_path;
    char err[256] = {0};
    ncf_config *cfg = ncf_parse_file(cfg_path, err, sizeof err);
    if (cfg == NULL) {
        fprintf(stderr, "配置非法: %s\n", err[0] != '\0' ? err : "解析失败");
        return 1;
    }
    if (dump) {
        ncf_config_dump(cfg, stdout);
    } else {
        printf("OK: %s（Encrypt %zu / Rewrite %zu / Ban %zu | "
               "Preset %zu / Include %zu / Defined Ban %zu）\n",
               cfg_path, cfg->enc_count, cfg->rw_count, cfg->ban_count,
               cfg->preset_count, cfg->include_count, cfg->ban_assert_count);
    }
    ncf_config_free(cfg);
    return 0;
}

/* 配置缺失时的内建策略：普通访客可访问，/api/ 仍强制 Neura-S2S。 */
static ncf_config *load_fallback_config(char *err, size_t errcap)
{
    static const char k_fallback[] =
        "Policy {\n"
        "    Plaintext: allow;\n"
        "}\n"
        "Encrypt API {\n"
        "    Path Match: starts_with \"/api/\";\n"
        "    Action: enforce_neura_s2s;\n"
        "}\n";
    return ncf_parse_string(k_fallback, sizeof k_fallback - 1,
                            "<builtin>", err, errcap);
}

/* ==========================================================================
 * 主流程
 * ========================================================================== */
static int run_server(sh_settings *s)
{
    char err[256] = {0};
    int rc = 1;
    ncf_config *cfg = NULL;
    waf *w = NULL;
    sh_reactor *r = NULL;

    /* 1. 加密库 */
    if (sh_neura_global_init() != NS2S_OK) {
        SH_LOGE("Neura-S2S 初始化失败（libsodium %s）", sh_neura_crypto_version());
        return 1;
    }

    /* 2. RootKey（不存在则生成，0600） */
    uint8_t root_key[SH_ROOTKEY_BYTES];
    bool created = false;
    if (sh_rootkey_load_or_create(s->root_key_path, 0600, &created, root_key,
                                  err, sizeof err) != NS2S_OK) {
        SH_LOGE("RootKey 加载失败: %s", err);
        return 1;
    }
    char fp_hex[SH_FINGERPRINT_HEX_LEN];
    if (sh_anchor_fingerprint_hex(root_key, fp_hex) != NS2S_OK) {
        SH_LOGE("RootKey 指纹计算失败");
        return 1;
    }
    if (created) {
        SH_LOGW("已生成新的 RootKey: %s（请通过安全渠道分发给客户端）",
                s->root_key_path);
    }

    /* 3. 配置；文件不存在时回落到内建"普通访客 + API 强制加密"策略 */
    cfg = ncf_parse_file(s->config_path, err, sizeof err);
    if (cfg == NULL) {
        if (access(s->config_path, F_OK) != 0) {
            SH_LOGW("配置文件 %s 不存在，使用内建策略（Plaintext: allow + API 加密）",
                    s->config_path);
            cfg = load_fallback_config(err, sizeof err);
        }
        if (cfg == NULL) {
            SH_LOGE("配置解析失败: %s", err[0] != '\0' ? err : "未知错误");
            goto cleanup;
        }
    }
    SH_LOGI("配置已加载: %s（Encrypt %zu / Rewrite %zu / Ban %zu | "
            "Preset %zu / Include %zu）预设目录=%s",
            s->config_path, cfg->enc_count, cfg->rw_count, cfg->ban_count,
            cfg->preset_count, cfg->include_count, ncf_get_preset_dir());

    /* 4. 信任锚（默认关闭；DoH 客户端尚未实现，显式打开即 fail-close） */
    sh_anchor anchor;
    memset(&anchor, 0, sizeof anchor);
    if (s->trust_anchor_required) {
        sh_doh_config doh;
        memset(&doh, 0, sizeof doh);
        doh.url = s->doh_url;
        doh.timeout_ms = SH_DOH_TIMEOUT_MS;
        doh.dnssec = SH_DNSSEC_AD_TRUSTED;
        if (sh_anchor_fetch(&doh, s->anchor_host, true, &anchor, err,
                            sizeof err) != NS2S_OK) {
            SH_LOGE("信任锚校验失败，拒绝启动: %s", err);
            SH_LOGE("（如确需启动，请显式加 --no-trust-anchor）");
            goto cleanup;
        }
    }

    /* 5. WAF */
    w = waf_new(cfg, s->waf_lru_capacity, 0);
    if (w == NULL) {
        SH_LOGE("WAF 初始化失败");
        goto cleanup;
    }

    /* 6. reactor（自建 ET epoll + KEM pool） */
    r = calloc(1, sizeof *r);
    if (r == NULL) {
        SH_LOGE("reactor 分配失败");
        goto cleanup;
    }
    if (sh_reactor_init(r, s, cfg, w) != 0) {
        SH_LOGE("reactor 初始化失败: %s", strerror(errno));
        goto cleanup;
    }
    memcpy(r->root_key, root_key, sizeof root_key);
    r->have_root_key = true;
    r->anchor = s->trust_anchor_required ? &anchor : NULL;
#if SH_MODE_PROXY
    r->hooks = &sh_proxy_hooks;
#else
    /*
     * Standalone 的静态文件/路由钩子尚未实现；保持监听与握手基础设施
     * 可用，便于后续接入。
     */
    r->hooks = NULL;
    SH_LOGW("Standalone 处理钩子尚未实现：当前仅完成监听与加密握手基础设施");
#endif

    if (sh_reactor_listen(r) != 0) {
        SH_LOGE("监听失败（%s:%u）: %s", s->listen_host,
                (unsigned)s->listen_port, strerror(errno));
        goto cleanup;
    }

    /* 7. 运行 */
    g_stop = 0;
    if (install_signal_handlers() != 0) {
        SH_LOGE("信号处理安装失败: %s", strerror(errno));
        goto cleanup;
    }
    if (write_pid_file(s->pid_path) != 0) {
        SH_LOGW("PID 文件不可用，继续运行");
    }
    g_wake_fd = (volatile sig_atomic_t)r->wake_fd;

    printf("\n");
    printf("  %s %s\n", SH_NAME, SH_VERSION_STRING);
    printf("  模式        : %s\n", SH_MODE_NAME);
    printf("  监听        : %s:%u", s->listen_host, (unsigned)s->listen_port);
    if (r->listen_tls_fd >= 0) {
        printf("  +  %s:%u", s->listen_tls_host != NULL ? s->listen_tls_host
                                                        : s->listen_host,
               (unsigned)s->listen_tls_port);
    }
    printf("\n");
#if SH_MODE_PROXY
    printf("  上游        : %s:%u\n", s->upstream_host, (unsigned)s->upstream_port);
#else
    printf("  静态根目录  : %s\n", s->static_root != NULL ? s->static_root : "-");
#endif
    printf("  配置        : %s\n", s->config_path);
    printf("  RootKey     : %s\n", s->root_key_path);
    printf("  信任锚指纹  : %s\n", fp_hex);
    printf("  明文策略    : %s（未匹配路径）\n",
           ncf_allows_unmatched_plaintext(cfg) ? "allow（普通访客可访问）"
                                               : "deny（全站强制 Neura-S2S）");
    printf("  WAF 规则    : %zu 条\n", cfg->ban_count);
    printf("  KEM workers : %u\n", s->kem_workers);
    printf("\n按 Ctrl-C 或发送 SIGTERM 退出。\n\n");
    fflush(stdout);

    SH_LOGI("启动完成，进入事件循环");
    if (sh_reactor_run(r) != 0) {
        SH_LOGE("事件循环异常退出");
        goto cleanup;
    }
    SH_LOGI("收到退出信号，正在优雅关闭");
    rc = 0;

cleanup:
    g_wake_fd = -1;
    if (r != NULL) {
        sh_reactor_destroy(r);
        free(r);
    }
    if (w != NULL) {
        waf_free(w);
    }
    if (cfg != NULL) {
        ncf_config_free(cfg);
    }
    if (s->pid_path != NULL) {
        unlink(s->pid_path);
    }
    return rc;
}

int sh_server_main(int argc, char **argv)
{
    sh_settings settings;
    sh_settings_defaults(&settings);

    sh_cli cli;
    char err[256] = {0};
    if (parse_cli(&settings, &cli, argc, argv, err, sizeof err) != 0) {
        fprintf(stderr, "参数错误: %s\n", err);
        return 2;
    }
    if (cli.show_help) {
        print_help(argv[0]);
        return 0;
    }
    if (cli.show_version) {
        print_version();
        return 0;
    }

    if (sh_log_init(stderr, (sh_log_level)settings.log_level) != 0) {
        return 1;
    }
    if (cli.log_file_explicit && settings.log_path != NULL) {
        if (sh_log_open_file(settings.log_path,
                             (sh_log_level)settings.log_level) != 0) {
            SH_LOGW("无法打开日志文件 %s，回退 stderr", settings.log_path);
        }
    }

    switch (cli.cmd) {
    case SH_CMD_PRINT_FINGERPRINT:
        return cmd_print_fingerprint(&settings, cli.cmd_path);
    case SH_CMD_CHECK_CONFIG:
        return cmd_check_or_dump(&settings, cli.cmd_path, false);
    case SH_CMD_DUMP_CONFIG:
        return cmd_check_or_dump(&settings, cli.cmd_path, true);
    case SH_CMD_RUN:
    default:
        break;
    }
    return run_server(&settings);
}

int main(int argc, char **argv)
{
    return sh_server_main(argc, argv);
}
