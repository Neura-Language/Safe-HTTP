// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - WAF / 防 CC 实现
 *
 * 结构：
 *   waf_lru  : 固定容量 LRU 哈希表（桶数组 + 双向使用链表），O(1) 查找/淘汰；
 *   waf_window: 环形桶滑动窗口，按 100ms 精度统计频率；
 *   规则来自 MatchLang 的 Ban 块，命中后按 Action 返回处置结论。
 *
 * 单线程使用（每个 reactor 一个实例），无需加锁。
 */
#include "waf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

/* ==========================================================================
 * 滑动窗口
 * ========================================================================== */
void waf_window_init(waf_window *w, uint32_t bucket_count, uint64_t bucket_ms)
{
    if (w == NULL) {
        return;
    }
    memset(w, 0, sizeof *w);
    if (bucket_count == 0) {
        bucket_count = 1;
    }
    if (bucket_count > SH_WAF_MAX_BUCKETS) {
        bucket_count = SH_WAF_MAX_BUCKETS;
    }
    w->bucket_count = bucket_count;
    w->bucket_ms = bucket_ms != 0 ? bucket_ms : SH_WAF_BUCKET_MS;
}

uint32_t waf_window_advance(waf_window *w, uint64_t now_ms)
{
    if (w == NULL || w->bucket_count == 0) {
        return 0;
    }
    if (now_ms < w->last_ms) {
        /* 时钟回退：整体清零，避免负索引 */
        memset(w->counts, 0, sizeof w->counts);
        memset(w->stamps, 0, sizeof w->stamps);
        w->total = 0;
        w->last_ms = now_ms;
        return 0;
    }
    uint64_t delta = now_ms - w->last_ms;
    uint64_t steps = delta / w->bucket_ms;
    if (steps >= w->bucket_count) {
        memset(w->counts, 0, sizeof w->counts);
        memset(w->stamps, 0, sizeof w->stamps);
        w->total = 0;
        w->head = 0;
        w->last_ms = now_ms;
        return 0;
    }
    while (steps-- > 0) {
        w->head = (w->head + 1u) % w->bucket_count;
        w->total -= w->counts[w->head];
        w->counts[w->head] = 0;
        w->stamps[w->head] = 0;
        w->last_ms += w->bucket_ms;
    }
    return w->total;
}

uint32_t waf_window_hit(waf_window *w, uint64_t now_ms)
{
    if (w == NULL || w->bucket_count == 0) {
        return 0;
    }
    (void)waf_window_advance(w, now_ms);
    w->counts[w->head]++;
    w->total++;
    w->stamps[w->head] = now_ms;
    return w->total;
}

uint32_t waf_window_total(const waf_window *w)
{
    return w != NULL ? w->total : 0;
}

/* ==========================================================================
 * LRU
 * ========================================================================== */
static uint32_t lru_hash(const char *key, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h = (h ^ (uint8_t)key[i]) * 16777619u;
    }
    return h == 0 ? 1u : h;
}

int waf_lru_init(waf_lru *lru, uint32_t capacity)
{
    if (lru == NULL) {
        return -1;
    }
    memset(lru, 0, sizeof *lru);
    if (capacity == 0) {
        capacity = SH_WAF_LRU_CAPACITY;
    }
    uint32_t buckets = 64;
    while (buckets < capacity * 2u) {
        buckets *= 2u;
    }
    lru->buckets = calloc(buckets, sizeof *lru->buckets);
    lru->pool = calloc(capacity, sizeof *lru->pool);
    if (lru->buckets == NULL || lru->pool == NULL) {
        free(lru->buckets);
        free(lru->pool);
        memset(lru, 0, sizeof *lru);
        return -1;
    }
    lru->bucket_count = buckets;
    lru->capacity = capacity;
    lru->free_list = NULL;
    for (uint32_t i = capacity; i > 0; i--) {
        waf_entry *e = &lru->pool[i - 1u];
        e->hnext = lru->free_list;
        lru->free_list = e;
    }
    return 0;
}

void waf_lru_free(waf_lru *lru)
{
    if (lru == NULL) {
        return;
    }
    free(lru->buckets);
    free(lru->pool);
    memset(lru, 0, sizeof *lru);
}

static waf_entry *lru_lookup(waf_lru *lru, const char *key, size_t len,
                             uint32_t hash)
{
    uint32_t idx = hash & (lru->bucket_count - 1u);
    for (waf_entry *e = lru->buckets[idx]; e != NULL; e = e->hnext) {
        if (e->hash == hash && e->key_len == len &&
            memcmp(e->key, key, len) == 0) {
            return e;
        }
    }
    return NULL;
}

void waf_lru_touch(waf_lru *lru, waf_entry *e)
{
    if (lru == NULL || e == NULL || lru->head == e) {
        return;
    }
    /* 从使用链表摘除 */
    if (e->lru_prev != NULL) {
        e->lru_prev->lru_next = e->lru_next;
    }
    if (e->lru_next != NULL) {
        e->lru_next->lru_prev = e->lru_prev;
    }
    if (lru->tail == e) {
        lru->tail = e->lru_prev;
    }
    /* 插到表头 */
    e->lru_prev = NULL;
    e->lru_next = lru->head;
    if (lru->head != NULL) {
        lru->head->lru_prev = e;
    }
    lru->head = e;
    if (lru->tail == NULL) {
        lru->tail = e;
    }
}

waf_entry *waf_lru_get(waf_lru *lru, const char *key, size_t key_len)
{
    if (lru == NULL || key == NULL || key_len == 0 ||
        key_len >= SH_WAF_KEY_MAX) {
        return NULL;
    }
    uint32_t hash = lru_hash(key, key_len);
    waf_entry *e = lru_lookup(lru, key, key_len, hash);
    if (e != NULL) {
        waf_lru_touch(lru, e);
    }
    return e;
}

static void lru_evict_tail(waf_lru *lru)
{
    waf_entry *e = lru->tail;
    if (e == NULL) {
        return;
    }
    lru->tail = e->lru_prev;
    if (lru->tail != NULL) {
        lru->tail->lru_next = NULL;
    } else {
        lru->head = NULL;
    }
    /* 从哈希链摘除 */
    uint32_t idx = e->hash & (lru->bucket_count - 1u);
    waf_entry **pp = &lru->buckets[idx];
    while (*pp != NULL) {
        if (*pp == e) {
            *pp = e->hnext;
            break;
        }
        pp = &(*pp)->hnext;
    }
    e->hnext = lru->free_list;
    lru->free_list = e;
    if (lru->size > 0) {
        lru->size--;
    }
    lru->evictions++;
}

waf_entry *waf_lru_get_or_create(waf_lru *lru, const char *key, size_t key_len)
{
    waf_entry *e = waf_lru_get(lru, key, key_len);
    if (e != NULL) {
        return e;
    }
    if (lru->free_list == NULL) {
        lru_evict_tail(lru);
    }
    if (lru->free_list == NULL) {
        return NULL;
    }
    e = lru->free_list;
    lru->free_list = e->hnext;
    memset(e, 0, sizeof *e);
    memcpy(e->key, key, key_len);
    e->key[key_len] = '\0';
    e->key_len = (uint16_t)key_len;
    e->hash = lru_hash(key, key_len);
    e->state = WAF_ENTRY_TRACKED;

    uint32_t idx = e->hash & (lru->bucket_count - 1u);
    e->hnext = lru->buckets[idx];
    lru->buckets[idx] = e;

    e->lru_prev = NULL;
    e->lru_next = lru->head;
    if (lru->head != NULL) {
        lru->head->lru_prev = e;
    }
    lru->head = e;
    if (lru->tail == NULL) {
        lru->tail = e;
    }
    lru->size++;
    return e;
}

void waf_lru_remove(waf_lru *lru, waf_entry *e)
{
    if (lru == NULL || e == NULL) {
        return;
    }
    if (e->lru_prev != NULL) {
        e->lru_prev->lru_next = e->lru_next;
    } else if (lru->head == e) {
        lru->head = e->lru_next;
    }
    if (e->lru_next != NULL) {
        e->lru_next->lru_prev = e->lru_prev;
    } else if (lru->tail == e) {
        lru->tail = e->lru_prev;
    }
    uint32_t idx = e->hash & (lru->bucket_count - 1u);
    waf_entry **pp = &lru->buckets[idx];
    while (*pp != NULL) {
        if (*pp == e) {
            *pp = e->hnext;
            break;
        }
        pp = &(*pp)->hnext;
    }
    memset(e, 0, sizeof *e);
    e->hnext = lru->free_list;
    lru->free_list = e;
    if (lru->size > 0) {
        lru->size--;
    }
}

uint32_t waf_lru_sweep(waf_lru *lru, uint64_t now_ms, uint64_t idle_ms)
{
    if (lru == NULL) {
        return 0;
    }
    uint32_t removed = 0;
    waf_entry *e = lru->tail;
    while (e != NULL) {
        waf_entry *prev = e->lru_prev;
        bool banned = e->state == WAF_ENTRY_BANNED && now_ms < e->banned_until_ms;
        bool idle = e->last_seen_ms == 0 || now_ms <= e->last_seen_ms ||
                    now_ms - e->last_seen_ms > idle_ms;
        if (!banned && idle && e->window.total == 0) {
            waf_lru_remove(lru, e);
            removed++;
        }
        e = prev;
    }
    return removed;
}

/* ==========================================================================
 * WAF 主体
 * ========================================================================== */
struct waf {
    const ncf_config *cfg;
    waf_lru          lru;
    uint32_t         bucket_ms;
    waf_stats        stats;
};

waf *waf_new(const ncf_config *cfg, uint32_t lru_capacity, uint32_t bucket_ms)
{
    waf *w = calloc(1, sizeof *w);
    if (w == NULL) {
        return NULL;
    }
    w->cfg = cfg;
    w->bucket_ms = bucket_ms != 0 ? bucket_ms : SH_WAF_BUCKET_MS;
    if (waf_lru_init(&w->lru, lru_capacity != 0 ? lru_capacity
                                                : SH_WAF_LRU_CAPACITY) != 0) {
        free(w);
        return NULL;
    }
    return w;
}

void waf_free(waf *w)
{
    if (w == NULL) {
        return;
    }
    waf_lru_free(&w->lru);
    free(w);
}

static const char *checker_value(const ncf_ban_rule *rule, const waf_request *req,
                                 size_t *len)
{
    *len = 0;
    switch (rule->checker) {
    case NCF_CHECKER_IP:
        if (req->ip_str != NULL) {
            *len = strlen(req->ip_str);
            return req->ip_str;
        }
        return NULL;
    case NCF_CHECKER_USER_AGENT:
        *len = req->user_agent_len;
        return req->user_agent;
    case NCF_CHECKER_PATH:
        *len = req->path_len;
        return req->path;
    case NCF_CHECKER_METHOD:
        *len = req->method_len;
        return req->method;
    case NCF_CHECKER_COOKIE:
        *len = req->cookie_len;
        return req->cookie;
    case NCF_CHECKER_QUERY:
        *len = req->query_len;
        return req->query;
    case NCF_CHECKER_HEADER:
        /* 首版未解析 "Header: 名字" 语法，直接跳过该规则 */
        return NULL;
    default:
        return NULL;
    }
}

static bool value_matches(const ncf_ban_rule *rule, const char *value, size_t len)
{
    if (rule->match_count == 0) {
        return true;    /* 无 Match 条件：只按频率统计 */
    }
    if (value == NULL) {
        return false;
    }
    size_t hits = 0;
    for (size_t i = 0; i < rule->match_count; i++) {
        const ncf_match *m = &rule->matches[i];
        if (m->value == NULL) {
            continue;
        }
        bool ok = false;
        size_t n = strlen(m->value);
        switch (m->op) {
        case NCF_MATCH_CONTAINS:
            ok = n == 0 || memmem(value, len, m->value, n) != NULL;
            break;
        case NCF_MATCH_STARTS_WITH:
            ok = len >= n && memcmp(value, m->value, n) == 0;
            break;
        case NCF_MATCH_ENDS_WITH:
            ok = len >= n && memcmp(value + len - n, m->value, n) == 0;
            break;
        case NCF_MATCH_EQUALS:
            ok = len == n && memcmp(value, m->value, n) == 0;
            break;
        default:
            ok = false;
            break;
        }
        if (ok) {
            hits++;
            if (rule->match_any) {
                return true;
            }
        }
    }
    return rule->match_any ? false : hits == rule->match_count;
}

static waf_verdict verdict_of(const ncf_ban_rule *rule)
{
    switch (rule->action) {
    case NCF_ACTION_RESPOND_403:
        return WAF_RESPOND_403;
    case NCF_ACTION_LOG_ONLY:
        return WAF_LOG;
    case NCF_ACTION_DROP_CONNECTION:
    default:
        return WAF_DROP;
    }
}

waf_verdict waf_inspect(waf *w, const waf_request *req, waf_hit *hit)
{
    if (w == NULL || req == NULL || w->cfg == NULL) {
        return WAF_ALLOW;
    }
    w->stats.inspected++;

    for (size_t i = 0; i < w->cfg->ban_count; i++) {
        const ncf_ban_rule *rule = &w->cfg->bans[i];
        size_t vlen = 0;
        const char *value = checker_value(rule, req, &vlen);
        if (rule->checker == NCF_CHECKER_USER_AGENT && value == NULL) {
            vlen = 0;    /* 缺 UA：参与 contains 匹配会失败，但 IP 频率仍可统计 */
        } else if (rule->checker != NCF_CHECKER_IP && value == NULL) {
            continue;
        }

        char key[SH_WAF_KEY_MAX];
        int kn = snprintf(key, sizeof key, "%d:%.*s", (int)rule->checker,
                          value != NULL ? (int)SH_MIN(vlen, 96u) : 0,
                          value != NULL ? value : "");
        if (kn <= 0 || (size_t)kn >= sizeof key) {
            continue;
        }
        waf_entry *e = waf_lru_get_or_create(&w->lru, key, (size_t)kn);
        if (e == NULL) {
            continue;
        }
        uint64_t now = req->now_ms != 0 ? req->now_ms : e->last_seen_ms;
        e->last_seen_ms = now;
        e->total_hits++;

        if (e->state == WAF_ENTRY_BANNED) {
            if (now < e->banned_until_ms) {
                if (hit != NULL) {
                    hit->rule = rule;
                    hit->key = rule->name;
                    hit->hits = e->window.total;
                    hit->window_ms = rule->window_ms;
                    hit->retry_after_s = (uint32_t)((e->banned_until_ms - now) / 1000u);
                }
                waf_verdict v = verdict_of(rule);
                if (v == WAF_DROP) {
                    w->stats.dropped++;
                } else if (v == WAF_LOG) {
                    /* log_only 不阻断 */
                }
                return v;
            }
            e->state = WAF_ENTRY_TRACKED;
            e->banned_until_ms = 0;
        }

        if (!value_matches(rule, value, vlen)) {
            continue;
        }

        bool should_ban = false;
        uint32_t hits = 0;
        if (rule->trigger == NCF_TRIGGER_VISIT ||
            rule->condition == NCF_COND_IMMEDIATELY) {
            should_ban = true;
            hits = 1;
        } else {
            if (e->window.bucket_count == 0) {
                uint32_t buckets = rule->window_ms / w->bucket_ms;
                if (buckets == 0) {
                    buckets = 1;
                }
                waf_window_init(&e->window, buckets, w->bucket_ms);
            }
            hits = waf_window_hit(&e->window, now);
            should_ban = hits > rule->threshold;
        }

        if (should_ban) {
            uint32_t ban_ms = rule->ban_ms != 0 ? rule->ban_ms : SH_WAF_DEFAULT_BAN_MS;
            if (ban_ms > SH_WAF_MAX_BAN_MS) {
                ban_ms = SH_WAF_MAX_BAN_MS;
            }
            waf_verdict v = verdict_of(rule);
            /*
             * 关键：只有「真正处置」的规则才允许改写条目状态。
             * log_only 只是观测，绝不能把 entry 置成 BANNED ——
             * 否则同一个 key（如 IP）上的后续 drop 规则会看到
             * "已封禁"而直接断连，等于把只记录规则变成了封禁规则。
             */
            if (v != WAF_LOG) {
                e->state = WAF_ENTRY_BANNED;
                e->banned_until_ms = now + ban_ms;
                w->stats.banned_total++;
            }
            e->last_rule_id = (uint16_t)(i + 1u);
            if (hit != NULL) {
                hit->rule = rule;
                hit->key = rule->name;
                hit->hits = hits;
                hit->window_ms = rule->window_ms;
                hit->retry_after_s = ban_ms / 1000u;
            }
            if (v == WAF_DROP) {
                w->stats.dropped++;
            }
            SH_LOGI("waf: 规则 \"%s\" 命中 key=%.64s hits=%u action=%s",
                    rule->name, key, hits, ncf_action_name(rule->action));
            return v;
        }
    }
    return WAF_ALLOW;
}

int waf_ban_ip(waf *w, const char *ip, uint32_t duration_ms, const char *reason)
{
    if (w == NULL || ip == NULL) {
        return -1;
    }
    char key[SH_WAF_KEY_MAX];
    int n = snprintf(key, sizeof key, "%d:%s", (int)NCF_CHECKER_IP, ip);
    if (n <= 0 || (size_t)n >= sizeof key) {
        return -1;
    }
    waf_entry *e = waf_lru_get_or_create(&w->lru, key, (size_t)n);
    if (e == NULL) {
        return -1;
    }
    e->state = WAF_ENTRY_BANNED;
    e->last_seen_ms = e->last_seen_ms != 0 ? e->last_seen_ms : 1;
    e->banned_until_ms = (duration_ms != 0 ? duration_ms : SH_WAF_DEFAULT_BAN_MS);
    /* 使用相对时间：由调用方在 inspect 里按 now 判断；此处直接存 now+时长 */
    e->banned_until_ms = e->last_seen_ms + e->banned_until_ms;
    w->stats.banned_total++;
    SH_LOGW("waf: 手工封禁 %s（%u ms）- %s", ip, duration_ms,
            reason != NULL ? reason : "-");
    return 0;
}

int waf_unban_ip(waf *w, const char *ip)
{
    if (w == NULL || ip == NULL) {
        return -1;
    }
    char key[SH_WAF_KEY_MAX];
    int n = snprintf(key, sizeof key, "%d:%s", (int)NCF_CHECKER_IP, ip);
    if (n <= 0 || (size_t)n >= sizeof key) {
        return -1;
    }
    waf_entry *e = waf_lru_get(&w->lru, key, (size_t)n);
    if (e == NULL) {
        return -1;
    }
    waf_lru_remove(&w->lru, e);
    return 0;
}

bool waf_is_banned(const waf *w, const char *ip)
{
    if (w == NULL || ip == NULL) {
        return false;
    }
    char key[SH_WAF_KEY_MAX];
    int n = snprintf(key, sizeof key, "%d:%s", (int)NCF_CHECKER_IP, ip);
    if (n <= 0 || (size_t)n >= sizeof key) {
        return false;
    }
    waf_lru *lru = (waf_lru *)&w->lru;    /* get 只做 touch，逻辑上非 const */
    waf_entry *e = waf_lru_get(lru, key, (size_t)n);
    return e != NULL && e->state == WAF_ENTRY_BANNED && e->banned_until_ms != 0;
}

size_t waf_list_bans(const waf *w, char (*out)[SH_INET_ADDR_STRLEN],
                     uint64_t *until_ms, size_t max)
{
    if (w == NULL || out == NULL || max == 0) {
        return 0;
    }
    size_t n = 0;
    for (waf_entry *e = w->lru.head; e != NULL && n < max; e = e->lru_next) {
        if (e->state != WAF_ENTRY_BANNED) {
            continue;
        }
        const char *colon = memchr(e->key, ':', e->key_len);
        const char *ip = colon != NULL ? colon + 1 : e->key;
        snprintf(out[n], SH_INET_ADDR_STRLEN, "%.*s",
                 SH_INET_ADDR_STRLEN - 1, ip);
        if (until_ms != NULL) {
            until_ms[n] = e->banned_until_ms;
        }
        n++;
    }
    return n;
}

void waf_sweep(waf *w, uint64_t now_ms)
{
    if (w == NULL) {
        return;
    }
    (void)waf_lru_sweep(&w->lru, now_ms, 10u * 60u * 1000u);
}

void waf_get_stats(const waf *w, waf_stats *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (w == NULL) {
        return;
    }
    *out = w->stats;
    out->evictions = w->lru.evictions;
    out->tracked_entries = w->lru.size;
    for (waf_entry *e = w->lru.head; e != NULL; e = e->lru_next) {
        if (e->state == WAF_ENTRY_BANNED) {
            out->active_bans++;
        }
    }
}

void waf_format_stats(const waf *w, char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return;
    }
    waf_stats st;
    waf_get_stats(w, &st);
    snprintf(out, cap,
             "safe_http_waf_inspected_total %llu\n"
             "safe_http_waf_dropped_total %llu\n"
             "safe_http_waf_banned_total %llu\n"
             "safe_http_waf_tracked_entries %u\n"
             "safe_http_waf_active_bans %u\n",
             (unsigned long long)st.inspected,
             (unsigned long long)st.dropped,
             (unsigned long long)st.banned_total,
             st.tracked_entries,
             st.active_bans);
}
