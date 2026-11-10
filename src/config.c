// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 运行时设置默认值
 *
 * 只填充编译期可见的默认值，不做任何内存分配；
 * 所有 const char * 指向静态字符串字面量，进程生命周期内有效。
 */
#include <string.h>

#include "config.h"

void sh_settings_defaults(sh_settings *s)
{
    if (s == NULL) {
        return;
    }
    memset(s, 0, sizeof *s);

    s->config_path = SH_DEFAULT_CONFIG_PATH;
    s->root_key_path = SH_DEFAULT_ROOTKEY_PATH;
    s->anchor_host = NULL;              /* 未指定则取监听主机名 */
    s->doh_url = SH_DOH_DEFAULT_URL;
    s->dnssec_mode = 1;                 /* SH_DNSSEC_AD_TRUSTED（首版策略） */
    s->pid_path = SH_DEFAULT_PID_PATH;
    s->log_path = SH_DEFAULT_LOG_PATH;
    s->user = SH_SERVICE_USER;

    s->listen_host = SH_DEFAULT_LISTEN_HOST;
    s->listen_port = SH_DEFAULT_LISTEN_PORT;
    s->listen_tls_host = NULL;
    s->listen_tls_port = SH_DEFAULT_TLS_PORT;
#if SH_MODE_PROXY
    s->upstream_host = SH_DEFAULT_UPSTREAM_HOST;
    s->upstream_port = SH_DEFAULT_UPSTREAM_PORT;
#else
    s->upstream_host = NULL;
    s->upstream_port = 0;
#endif

#if SH_WITH_TLS_TERMINATION
    s->tls_cert_path = SH_DEFAULT_TLS_CERT_PATH;
    s->tls_key_path = SH_DEFAULT_TLS_KEY_PATH;
#else
    s->tls_cert_path = NULL;
    s->tls_key_path = NULL;
#endif

#if SH_HAS_STATIC_FILE
    s->static_root = SH_DEFAULT_STATIC_ROOT;
    s->index_file = SH_DEFAULT_INDEX_FILE;
    s->static_listing = false;
#else
    s->static_root = NULL;
    s->index_file = NULL;
    s->static_listing = false;
#endif

    s->max_connections = SH_MAX_CONNECTIONS;
    s->read_buf_size = SH_READ_BUF_SIZE;
    s->write_buf_size = SH_WRITE_BUF_SIZE;
    s->idle_timeout_ms = SH_IDLE_TIMEOUT_MS;
    s->handshake_timeout_ms = SH_HANDSHAKE_TIMEOUT_MS;
    s->upstream_timeout_ms = SH_UPSTREAM_CONNECT_TIMEOUT_MS;
    s->ratchet_interval_ms = SH_RATCHET_INTERVAL_MS;
    s->waf_lru_capacity = SH_WAF_LRU_CAPACITY;
    s->max_frame = SH_DEFAULT_MAX_FRAME;
    s->kem_workers = SH_KEM_WORKERS;

    s->log_level = 3;                   /* SH_LOG_INFO */
    /*
     * 信任锚默认关闭：DoH/DNSSEC 客户端在 v1.0 仍是 fail-close 占位实现，
     * 默认打开会导致进程永远无法启动。需要严格身份校验的部署用
     * --require-trust-anchor 显式开启。
     */
    s->trust_anchor_required = false;
    s->daemonize = false;
    s->foreground = false;
}
