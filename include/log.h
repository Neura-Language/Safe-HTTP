// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 日志
 *
 * 单文件、无锁（每 worker 独立文件描述符）的极简日志层。
 * 所有日志统一带 level / 时间戳 / 位置信息，避免业务代码拼字符串。
 */
#ifndef SAFE_HTTP_LOG_H
#define SAFE_HTTP_LOG_H

#include <stdio.h>

#include "config.h"

typedef enum sh_log_level {
    SH_LOG_FATAL = 0,
    SH_LOG_ERROR = 1,
    SH_LOG_WARN  = 2,
    SH_LOG_INFO  = 3,
    SH_LOG_DEBUG = 4,
    SH_LOG_TRACE = 5
} sh_log_level;

/* 初始化：fp 为 NULL 时使用 stderr。返回 0 成功。 */
int  sh_log_init(FILE *fp, sh_log_level level);

/* 打开/切换日志文件（O_APPEND，行缓冲）。返回 0 成功。 */
int  sh_log_open_file(const char *path, sh_log_level level);

/* 关闭日志文件（不关闭 stderr）。 */
void sh_log_close(void);

void sh_log_set_level(sh_log_level level);
sh_log_level sh_log_get_level(void);
bool sh_log_enabled(sh_log_level level);

/* "trace" / "debug" / "info" / "warn" / "error" / "fatal"；未知返回 -1 */
int  sh_log_level_from_string(const char *s);
const char *sh_log_level_to_string(sh_log_level level);

/*
 * 底层写入口；业务代码请使用下方 SH_LOGx 宏。
 * 内部保证一行日志的原子写入（<= PIPE_BUF 时）。
 */
void sh_log_write(sh_log_level level, const char *file, int line,
                  const char *func, const char *fmt, ...) SH_PRINTF(5, 6);

#define SH_LOGF(...) sh_log_write(SH_LOG_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define SH_LOGE(...) sh_log_write(SH_LOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define SH_LOGW(...) sh_log_write(SH_LOG_WARN,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define SH_LOGI(...) sh_log_write(SH_LOG_INFO,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define SH_LOGD(...) sh_log_write(SH_LOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define SH_LOGT(...) sh_log_write(SH_LOG_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)

/* 记录 fatal 后立即 abort（用于不可恢复的不变量破坏） */
void sh_log_fatal_abort(const char *file, int line, const char *func,
                        const char *fmt, ...) SH_PRINTF(4, 5) SH_NORETURN;
#define SH_PANIC(...) sh_log_fatal_abort(__FILE__, __LINE__, __func__, __VA_ARGS__)

/*
 * 访问日志（Standalone / Proxy 通用）：
 * 一行一条，便于 awk 统计，字段之间用单空格分隔。
 */
void sh_access_log(const char *peer_ip, const char *method, const char *path,
                   int status, size_t bytes_out, uint64_t elapsed_ms);

#endif /* SAFE_HTTP_LOG_H */
