// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 日志实现
 *
 * 设计取舍：
 *   - 单文件、行缓冲、flockfile 保证多线程下整行不交错；
 *   - 每行带 ISO8601 本地时间 + 级别 + 文件:行 + 函数；
 *   - 不动态分配（除 vsnprintf 溢出到堆时的行缓冲外），避免日志路径 OOM；
 *   - 访问日志单独格式化，字段用单空格分隔，便于 awk 统计。
 */
#include "log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SH_LOG_LINE_MAX 2048

static FILE   *g_out = NULL;
static int     g_level = SH_LOG_INFO;
static bool    g_owned_file = false;
static bool    g_inited = false;

static const char *const k_level_names[] = {
    "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

static void ensure_init(void)
{
    if (!g_inited) {
        g_out = stderr;
        g_inited = true;
    }
}

int sh_log_init(FILE *fp, sh_log_level level)
{
    if (g_owned_file && g_out != NULL) {
        fclose(g_out);
    }
    g_out = fp != NULL ? fp : stderr;
    g_owned_file = false;
    g_inited = true;
    sh_log_set_level(level);
    return 0;
}

int sh_log_open_file(const char *path, sh_log_level level)
{
    if (path == NULL) {
        return -1;
    }
    FILE *fp = fopen(path, "a");
    if (fp == NULL) {
        return -1;
    }
    setvbuf(fp, NULL, _IOLBF, 0);
    if (g_owned_file && g_out != NULL) {
        fclose(g_out);
    }
    g_out = fp;
    g_owned_file = true;
    g_inited = true;
    sh_log_set_level(level);
    return 0;
}

void sh_log_close(void)
{
    if (g_owned_file && g_out != NULL) {
        fclose(g_out);
    }
    g_out = stderr;
    g_owned_file = false;
}

void sh_log_set_level(sh_log_level level)
{
    if (level < SH_LOG_FATAL) {
        level = SH_LOG_FATAL;
    }
    if (level > SH_LOG_TRACE) {
        level = SH_LOG_TRACE;
    }
    g_level = (int)level;
}

sh_log_level sh_log_get_level(void)
{
    return (sh_log_level)g_level;
}

bool sh_log_enabled(sh_log_level level)
{
    return (int)level <= g_level;
}

int sh_log_level_from_string(const char *s)
{
    if (s == NULL) {
        return -1;
    }
    for (size_t i = 0; i < SH_ARRAY_LEN(k_level_names); i++) {
        if (strcasecmp(s, k_level_names[i]) == 0) {
            return (int)i;
        }
    }
    if (strcasecmp(s, "warning") == 0) {
        return SH_LOG_WARN;
    }
    return -1;
}

const char *sh_log_level_to_string(sh_log_level level)
{
    if (level < SH_LOG_FATAL || level > SH_LOG_TRACE) {
        return "?";
    }
    return k_level_names[level];
}

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

static void format_timestamp(char *out, size_t cap, bool with_ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    size_t n = strftime(out, cap, "%Y-%m-%d %H:%M:%S", &tm);
    if (with_ms && n > 0 && n + 5 < cap) {
        snprintf(out + n, cap - n, ".%03ld", ts.tv_nsec / 1000000L);
    }
}

void sh_log_write(sh_log_level level, const char *file, int line,
                  const char *func, const char *fmt, ...)
{
    if (!sh_log_enabled(level)) {
        return;
    }
    ensure_init();

    char ts[40];
    format_timestamp(ts, sizeof ts, true);

    char msg[SH_LOG_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    flockfile(g_out);
    fprintf(g_out, "[%s] [%s] %s:%d %s: %s\n", ts,
            k_level_names[level], basename_of(file), line,
            func != NULL ? func : "-", msg);
    funlockfile(g_out);
}

void sh_log_fatal_abort(const char *file, int line, const char *func,
                        const char *fmt, ...)
{
    ensure_init();

    char ts[40];
    format_timestamp(ts, sizeof ts, true);

    char msg[SH_LOG_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    flockfile(g_out);
    fprintf(g_out, "[%s] [FATAL] %s:%d %s: %s\n", ts,
            basename_of(file), line, func != NULL ? func : "-", msg);
    fflush(g_out);
    funlockfile(g_out);
    abort();
}

void sh_access_log(const char *peer_ip, const char *method, const char *path,
                   int status, size_t bytes_out, uint64_t elapsed_ms)
{
#if !SH_WITH_ACCESS_LOG
    (void)peer_ip; (void)method; (void)path; (void)status;
    (void)bytes_out; (void)elapsed_ms;
#else
    ensure_init();
    char ts[40];
    format_timestamp(ts, sizeof ts, false);

    flockfile(g_out);
    fprintf(g_out, "%s %s \"%s %s\" %d %zu %llums\n",
            ts,
            peer_ip != NULL ? peer_ip : "-",
            method != NULL ? method : "-",
            path != NULL ? path : "-",
            status, bytes_out,
            (unsigned long long)elapsed_ms);
    funlockfile(g_out);
#endif
}
