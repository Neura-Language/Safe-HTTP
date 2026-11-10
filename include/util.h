// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 通用工具
 *
 * 字符串安全副本、时间、十六进制/Base64URL、SHA-256 指纹、单位解析等。
 * 依赖 libc，不依赖任何第三方库（SHA-256 由 libneura 提供实现）。
 */
#ifndef SAFE_HTTP_UTIL_H
#define SAFE_HTTP_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"

/* ==========================================================================
 * 1. 时间
 * ========================================================================== */
/* 单调时钟毫秒（CLOCK_MONOTONIC），用于超时与滑动窗口 */
uint64_t sh_now_ms(void);
/* 墙钟秒（CLOCK_REALTIME），仅用于日志/证书 */
uint64_t sh_wall_sec(void);
/* 格式化：2025-01-01T00:00:00Z -> out 至少 21 字节 */
int sh_format_iso8601(uint64_t sec, char *out, size_t cap);
/* 格式化毫秒时长为人类可读："300ms" / "1.5s" */
int sh_format_duration(uint64_t ms, char *out, size_t cap);

/* ==========================================================================
 * 2. 字符串
 * ========================================================================== */
/* 总是 NUL 结尾；返回 srclen（同 BSD strlcpy 语义） */
size_t sh_strlcpy(char *dst, const char *src, size_t cap);
size_t sh_strlcat(char *dst, const char *src, size_t cap);
char  *sh_strdup(const char *s);          /* malloc，调用方 free */
char  *sh_strndup(const char *s, size_t n);
bool   sh_str_eq(const char *a, const char *b);
bool   sh_str_ieq(const char *a, const char *b);
bool   sh_str_starts_with(const char *s, size_t slen, const char *prefix);
bool   sh_str_ends_with(const char *s, size_t slen, const char *suffix);
/* ASCII 大小写无关的 contains；MatchLang 的 contains 依赖它（禁止 PCRE） */
const char *sh_str_icontains(const char *s, size_t slen, const char *needle);
/* 原地去除首尾空白，返回新的起点（内部 memmove） */
char  *sh_str_trim(char *s);
/* 去掉行尾 \r\n，返回新的长度 */
size_t sh_str_chomp(char *s, size_t len);
/* 安全 zeroize（不会被优化掉），用于密钥材料 */
void   sh_secure_zero(void *ptr, size_t len);
/* 常量时间比较，返回 true 表示相等 */
bool   sh_consttime_eq(const void *a, const void *b, size_t len);

/* ==========================================================================
 * 3. 数值与单位解析
 * ========================================================================== */
/* 严格解析无符号整数（不接受负号、空白）；成功返回 true */
bool sh_parse_u64(const char *s, uint64_t *out);
bool sh_parse_u32(const char *s, uint32_t *out);
/*
 * 时长解析："300ms" / "1s" / "5m" / "2h" / "100"（裸数字视为毫秒）。
 * 成功返回 true 并输出毫秒值。
 */
bool sh_parse_duration_ms(const char *s, uint32_t *out_ms);
/* 容量解析："16k" / "1m" / "1048576" */
bool sh_parse_size(const char *s, uint32_t *out_bytes);

/* ==========================================================================
 * 4. 编码与摘要
 * ========================================================================== */
#define SH_SHA256_LEN 32
#define SH_HEX_LEN(n) ((n) * 2u + 1u)
#define SH_B64URL_ENC_LEN(n) ((((n) + 2u) / 3u) * 4u + 1u)

/* SHA-256，成功返回 0 */
int sh_sha256(const void *data, size_t len, uint8_t out[SH_SHA256_LEN]);
/* 转小写 hex，NUL 结尾；cap 至少 SH_HEX_LEN(len) */
int sh_hex_encode(const uint8_t *in, size_t len, char *out, size_t cap);
int sh_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t cap);
/* 无填充 Base64URL（DNS TXT / 指纹传输用） */
int sh_base64url_encode(const uint8_t *in, size_t len, char *out, size_t cap);
int sh_base64url_decode(const char *in, size_t len, uint8_t *out, size_t cap);

/* 32 字节公钥 -> 64 字符指纹字符串（不含分隔符） */
int sh_fingerprint_hex(const uint8_t fp[32], char out[SH_FINGERPRINT_HEX_LEN]);

/* ==========================================================================
 * 5. 文件系统小工具
 * ========================================================================== */
bool sh_file_exists(const char *path);
bool sh_dir_exists(const char *path);
/* 原子写文件（先写 .tmp 再 rename），用于公钥指纹落盘 */
int  sh_write_file_atomic(const char *path, const void *data, size_t len,
                          unsigned mode);
int  sh_read_file(const char *path, char **out, size_t *out_len, size_t max_len);
/* 路径规范化 + 阻断 "../" 穿越；成功返回 0，out 至少 PATH_MAX 字节 */
int  sh_path_canonicalize(const char *root, const char *uri,
                          char *out, size_t cap);

#endif /* SAFE_HTTP_UTIL_H */
