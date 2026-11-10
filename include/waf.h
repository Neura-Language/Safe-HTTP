// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - WAF / 防 CC
 *
 * 数据结构（REQUIREMENTS.md §3.3）：
 *   1. LRU 哈希表：容量固定，O(1) 查找/插入，淘汰最久未使用项，
 *      用于保存 IP/UA 的滑动窗口计数与封禁状态；
 *   2. 滑动窗口：环形桶数组（默认 100ms/桶 ×64 桶 ≈ 6.4s 精度窗口），
 *      计数按时间片衰减，避免固定窗口的边界突刺；
 *   3. 与 MatchLang 的 Ban 规则一一对应，命中的 Action 由规则决定
 *      （drop_connection / respond_403 / log_only）。
 *
 * 全部实现为单线程无锁（每个 worker 独立 WAF 实例），
 * 多 worker 共享封禁状态时由上层通过共享内存/管理接口同步。
 */
#ifndef SAFE_HTTP_WAF_H
#define SAFE_HTTP_WAF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "config_parser.h"
#include "network.h"

typedef struct waf         waf;
typedef struct waf_entry   waf_entry;
typedef struct waf_lru     waf_lru;

/* 检查结论 */
typedef enum waf_verdict {
    WAF_ALLOW = 0,
    WAF_DROP,        /* 断连接（drop_connection） */
    WAF_RESPOND_403,
    WAF_THROTTLE,    /* 暂缓处理（本实现即将连接延后/丢弃读取） */
    WAF_LOG          /* 仅记录 */
} waf_verdict;

/* 单次请求的检查上下文（全部指向已解析缓冲区，零拷贝） */
typedef struct waf_request {
    const sh_addr *peer;
    const char    *ip_str;         /* 预先格式化好的 IP，可为 NULL */
    const char    *method;
    size_t         method_len;
    const char    *path;
    size_t         path_len;
    const char    *query;
    size_t         query_len;
    const char    *user_agent;
    size_t         user_agent_len;
    const char    *host;
    size_t         host_len;
    const char    *cookie;
    size_t         cookie_len;
    uint64_t       now_ms;
} waf_request;

/* 命中信息：用于日志与响应头（Retry-After） */
typedef struct waf_hit {
    const ncf_ban_rule *rule;
    const char         *key;        /* 触发封禁的 key（IP/UA/...） */
    uint32_t            hits;       /* 窗口内命中次数 */
    uint32_t            window_ms;
    uint32_t            retry_after_s;
} waf_hit;

/* ==========================================================================
 * 1. 滑动窗口（环形桶）
 * ========================================================================== */
typedef struct waf_window {
    uint64_t bucket_ms;                     /* 每桶时长 */
    uint32_t bucket_count;                  /* 桶数量（<= SH_WAF_MAX_BUCKETS） */
    uint32_t counts[SH_WAF_MAX_BUCKETS];    /* 每桶计数 */
    uint64_t stamps[SH_WAF_MAX_BUCKETS];    /* 每桶起始时间（ms） */
    uint32_t head;                          /* 当前桶下标 */
    uint64_t last_ms;
    uint32_t total;                         /* 窗口内总计数（近似/精确） */
} waf_window;

void     waf_window_init(waf_window *w, uint32_t bucket_count, uint64_t bucket_ms);
/* 推进到 now_ms（按时间差清零过期桶），返回窗口内总数 */
uint32_t waf_window_advance(waf_window *w, uint64_t now_ms);
uint32_t waf_window_hit(waf_window *w, uint64_t now_ms);      /* 计数 +1 */
uint32_t waf_window_total(const waf_window *w);

/* ==========================================================================
 * 2. LRU 哈希表
 * ========================================================================== */
typedef enum waf_entry_state {
    WAF_ENTRY_IDLE = 0,
    WAF_ENTRY_TRACKED,   /* 正在窗口计数 */
    WAF_ENTRY_BANNED
} waf_entry_state;

struct waf_entry {
    char            key[SH_WAF_KEY_MAX];
    uint16_t        key_len;
    uint32_t        hash;
    waf_entry_state state;
    waf_window      window;
    uint64_t        banned_until_ms;
    uint64_t        last_seen_ms;
    uint64_t        created_ms;
    uint32_t        total_hits;
    uint16_t        last_rule_id;     /* 触发封禁的规则索引+1，0 表示无 */
    waf_entry      *lru_prev;         /* 最近使用链表 */
    waf_entry      *lru_next;
    waf_entry      *hnext;            /* 哈希桶链 */
};

struct waf_lru {
    waf_entry **buckets;
    uint32_t    bucket_count;   /* 2 的幂 */
    uint32_t    capacity;
    uint32_t    size;
    waf_entry  *head;           /* 最新使用 */
    waf_entry  *tail;           /* 最旧使用，淘汰目标 */
    waf_entry  *pool;           /* 预分配数组 */
    waf_entry  *free_list;
    uint32_t    evictions;
};

int  waf_lru_init(waf_lru *lru, uint32_t capacity);
void waf_lru_free(waf_lru *lru);
waf_entry *waf_lru_get(waf_lru *lru, const char *key, size_t key_len);
waf_entry *waf_lru_get_or_create(waf_lru *lru, const char *key, size_t key_len);
void waf_lru_touch(waf_lru *lru, waf_entry *e);
void waf_lru_remove(waf_lru *lru, waf_entry *e);
/* 释放已过期条目（封禁到期且窗口静默），返回释放数量 */
uint32_t waf_lru_sweep(waf_lru *lru, uint64_t now_ms, uint64_t idle_ms);

/* ==========================================================================
 * 3. WAF 主体
 * ========================================================================== */
/*
 * 创建 WAF：
 *   cfg           - MatchLang 配置（内部只读引用，不拥有）
 *   lru_capacity  - 0 表示使用 SH_WAF_LRU_CAPACITY
 *   bucket_ms     - 0 表示使用 SH_WAF_BUCKET_MS
 */
waf  *waf_new(const ncf_config *cfg, uint32_t lru_capacity, uint32_t bucket_ms);
void  waf_free(waf *w);

/*
 * 检查请求：遍历 Ban 规则，返回处置结论。
 * hit 可为 NULL；非 NULL 时在命中时填充。
 * 注意：即使返回 WAF_DROP，封禁状态也已写入（后续请求直接短路）。
 */
waf_verdict waf_inspect(waf *w, const waf_request *req, waf_hit *hit);

/* 手工封禁/解封（管理接口与 install.sh 巡检使用） */
int  waf_ban_ip(waf *w, const char *ip, uint32_t duration_ms, const char *reason);
int  waf_unban_ip(waf *w, const char *ip);
bool waf_is_banned(const waf *w, const char *ip);
/* 当前封禁列表导出（最多 max 条），返回实际条数 */
size_t waf_list_bans(const waf *w, char (*out)[SH_INET_ADDR_STRLEN],
                     uint64_t *until_ms, size_t max);

/* 周期性清扫（由 reactor 定时器每 SH_TIMER_TICK_MS * N 调用） */
void waf_sweep(waf *w, uint64_t now_ms);

/* 统计 */
typedef struct waf_stats {
    uint64_t inspected;
    uint64_t dropped;
    uint64_t throttled;
    uint64_t banned_total;
    uint64_t evictions;
    uint32_t tracked_entries;
    uint32_t active_bans;
} waf_stats;

void waf_get_stats(const waf *w, waf_stats *out);
/* 导出 Prometheus 文本格式（可选管理端点使用） */
void waf_format_stats(const waf *w, char *out, size_t cap);

#endif /* SAFE_HTTP_WAF_H */
