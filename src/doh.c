// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 信任锚 DoH 客户端（占位实现）
 *
 * 首版策略（已与需求确认）：
 *   - DNSSEC 采用 AD_TRUSTED：信任 DoH 响应的 AD 位（由验证型递归解析器背书），
 *     本地 RRSIG/DNSKEY 全链校验列为 v1.1 TODO；
 *   - 当前版本**尚未接入 TLS/HTTP2 客户端**，因此本文件只返回明确错误，
 *     绝不做"静默放行"。启动时若要求信任锚校验，会因取不到 TXT 而拒绝启动，
 *     这是刻意的 fail-close 行为。
 */
#include "security.h"

#include <stdio.h>
#include <string.h>

#include "log.h"

#if SH_WITH_TRUST_ANCHOR

static void set_err(char *err, size_t cap, const char *msg)
{
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
}

int sh_doh_query_txt(const sh_doh_config *cfg, const char *name,
                     sh_dns_answer *out, char *err, size_t errcap)
{
    (void)cfg;
    (void)name;
    (void)out;
    set_err(err, errcap,
            "DoH 客户端尚未实现（v1.0 计划：OpenSSL + application/dns-message，"
            "DNSSEC 采用 AD 位校验）");
    SH_LOGW("trust-anchor: DoH 查询 %s 失败（功能未实现）",
            name != NULL ? name : "?");
    return SH_ERR_DNS;
}

int sh_anchor_fetch(const sh_doh_config *cfg, const char *host,
                    bool require_dnssec, sh_anchor *out,
                    char *err, size_t errcap)
{
    (void)cfg;
    (void)require_dnssec;
    if (out != NULL) {
        memset(out, 0, sizeof *out);
        if (host != NULL) {
            snprintf(out->host, sizeof out->host, "%s", host);
        }
    }
    set_err(err, errcap,
            "信任锚拉取尚未实现：DoH/DNSSEC 客户端待 v1.0 补齐；"
            "可用 --no-trust-anchor 显式降级（不推荐用于生产）");
    return SH_ERR_DNS;
}

#endif /* SH_WITH_TRUST_ANCHOR */
