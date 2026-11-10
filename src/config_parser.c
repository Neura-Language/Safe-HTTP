// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - MatchLang 配置解析器
 *
 * 手写词法 + 递归下降，禁止 PCRE；匹配算子全部是字面量比较。
 * 支持的块（见 config/config.ncf）：
 *   Encrypt <name> { Path Match: <op> "<v>"; Action: <act>; }
 *   Rewrite <name> { using engine matchlang; pattern: Locate "a" until "b" as $v { Replace with "..."; } }
 *   Ban "<name>" { Checker: ...; Match: ...; Trigger: ...; Condition: ...; Action: ...; }
 *
 * 未知语句一律报错（带 file:line:col），不做"猜测性容忍"。
 */
#include "config_parser.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

/* ==========================================================================
 * 0. 预设目录（Enable Preset 的查找根）
 * ========================================================================== */
#ifndef SH_DEFAULT_PRESET_DIR
#  define SH_DEFAULT_PRESET_DIR "/opt/Safe-HTTP/config/presets"
#endif

static char g_preset_dir[PATH_MAX];    /* ncf_set_preset_dir 的显式覆盖 */

void ncf_set_preset_dir(const char *dir)
{
    if (dir == NULL || dir[0] == '\0') {
        g_preset_dir[0] = '\0';
        return;
    }
    snprintf(g_preset_dir, sizeof g_preset_dir, "%s", dir);
}

/*
 * 查找顺序：ncf_set_preset_dir() 显式设置 > 环境变量 SAFE_HTTP_PRESET_DIR >
 *           编译期默认 SH_DEFAULT_PRESET_DIR。
 * 环境变量便于测试与多实例部署，不影响生产默认值。
 */
const char *ncf_get_preset_dir(void)
{
    if (g_preset_dir[0] != '\0') {
        return g_preset_dir;
    }
    const char *env = getenv("SAFE_HTTP_PRESET_DIR");
    if (env != NULL && env[0] != '\0') {
        return env;
    }
    return SH_DEFAULT_PRESET_DIR;
}

const char *ncf_scope_name(ncf_scope s)
{
    return s == NCF_SCOPE_SYSTEM ? "system" : "user";
}

static uint32_t scope_priority(ncf_scope s)
{
    return s == NCF_SCOPE_SYSTEM ? NCF_PRIORITY_SYSTEM : NCF_PRIORITY_USER;
}


/* ==========================================================================
 * 1. 词法
 * ========================================================================== */
const char *ncf_token_type_name(ncf_token_type type)
{
    switch (type) {
    case NCF_TOK_EOF: return "EOF";
    case NCF_TOK_IDENT: return "标识符";
    case NCF_TOK_STRING: return "字符串";
    case NCF_TOK_NUMBER: return "数字";
    case NCF_TOK_VAR: return "变量";
    case NCF_TOK_LBRACE: return "'{'";
    case NCF_TOK_RBRACE: return "'}'";
    case NCF_TOK_COLON: return "':'";
    case NCF_TOK_SEMI: return "';'";
    case NCF_TOK_COMMA: return "','";
    case NCF_TOK_EQUALS: return "'='";
    case NCF_TOK_SLASH: return "'/'";
    case NCF_TOK_ERROR: return "错误";
    default: return "?";
    }
}

void ncf_lexer_init(ncf_lexer *lx, const char *src, size_t len)
{
    memset(lx, 0, sizeof *lx);
    lx->src = src;
    lx->len = len;
    lx->line = 1;
    lx->col = 1;
}

static void lx_advance(ncf_lexer *lx)
{
    if (lx->pos < lx->len) {
        if (lx->src[lx->pos] == '\n') {
            lx->line++;
            lx->col = 1;
        } else {
            lx->col++;
        }
        lx->pos++;
    }
}

static void lx_skip_space(ncf_lexer *lx)
{
    for (;;) {
        while (lx->pos < lx->len &&
               (lx->src[lx->pos] == ' ' || lx->src[lx->pos] == '\t' ||
                lx->src[lx->pos] == '\r' || lx->src[lx->pos] == '\n')) {
            lx_advance(lx);
        }
        if (lx->pos < lx->len && lx->src[lx->pos] == '#') {
            while (lx->pos < lx->len && lx->src[lx->pos] != '\n') {
                lx_advance(lx);
            }
            continue;
        }
        break;
    }
}

static bool lex_string(ncf_lexer *lx, ncf_token *tok)
{
    char quote = lx->src[lx->pos];
    lx_advance(lx);
    size_t start = lx->pos;
    while (lx->pos < lx->len && lx->src[lx->pos] != quote) {
        if (lx->src[lx->pos] == '\\' && lx->pos + 1 < lx->len) {
            lx_advance(lx);
        }
        lx_advance(lx);
    }
    if (lx->pos >= lx->len) {
        snprintf(lx->err, sizeof lx->err, "字符串未闭合");
        lx->failed = true;
        return false;
    }
    tok->type = NCF_TOK_STRING;
    tok->start = lx->src + start;
    tok->len = lx->pos - start;
    lx_advance(lx);    /* 收尾引号 */
    return true;
}

bool ncf_lexer_next(ncf_lexer *lx, ncf_token *tok)
{
    memset(tok, 0, sizeof *tok);
    lx_skip_space(lx);
    tok->line = lx->line;
    tok->col = lx->col;
    if (lx->pos >= lx->len) {
        tok->type = NCF_TOK_EOF;
        return true;
    }

    char c = lx->src[lx->pos];
    if (c == '"' || c == '\'') {
        return lex_string(lx, tok);
    }
    if (c == '{') { tok->type = NCF_TOK_LBRACE; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == '}') { tok->type = NCF_TOK_RBRACE; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == ':') { tok->type = NCF_TOK_COLON; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == ';') { tok->type = NCF_TOK_SEMI; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == ',') { tok->type = NCF_TOK_COMMA; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == '=') { tok->type = NCF_TOK_EQUALS; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == '/') { tok->type = NCF_TOK_SLASH; tok->start = lx->src + lx->pos; tok->len = 1; lx_advance(lx); return true; }
    if (c == '$') {
        size_t start = ++lx->pos;
        while (lx->pos < lx->len &&
               (isalnum((unsigned char)lx->src[lx->pos]) || lx->src[lx->pos] == '_')) {
            lx_advance(lx);
        }
        tok->type = NCF_TOK_VAR;
        tok->start = lx->src + start;
        tok->len = lx->pos - start;
        return true;
    }
    if (isdigit((unsigned char)c)) {
        size_t start = lx->pos;
        while (lx->pos < lx->len && isdigit((unsigned char)lx->src[lx->pos])) {
            lx_advance(lx);
        }
        /* 时长单位：1s / 100ms / 5m / 1h */
        while (lx->pos < lx->len && isalpha((unsigned char)lx->src[lx->pos])) {
            lx_advance(lx);
        }
        tok->type = NCF_TOK_NUMBER;
        tok->start = lx->src + start;
        tok->len = lx->pos - start;
        return true;
    }
    if (isalpha((unsigned char)c) || c == '_') {
        size_t start = lx->pos;
        while (lx->pos < lx->len &&
               (isalnum((unsigned char)lx->src[lx->pos]) || lx->src[lx->pos] == '_' ||
                lx->src[lx->pos] == '-')) {
            lx_advance(lx);
        }
        tok->type = NCF_TOK_IDENT;
        tok->start = lx->src + start;
        tok->len = lx->pos - start;
        return true;
    }

    snprintf(lx->err, sizeof lx->err, "非法字符 '%c'", c);
    lx->failed = true;
    tok->type = NCF_TOK_ERROR;
    lx_advance(lx);
    return false;
}

/* ==========================================================================
 * 2. 名称表
 * ========================================================================== */
const char *ncf_match_op_name(ncf_match_op op)
{
    switch (op) {
    case NCF_MATCH_STARTS_WITH: return "starts_with";
    case NCF_MATCH_ENDS_WITH: return "ends_with";
    case NCF_MATCH_CONTAINS: return "contains";
    case NCF_MATCH_EQUALS: return "equals";
    case NCF_MATCH_IN: return "in";
    default: return "?";
    }
}

const char *ncf_action_name(ncf_action_type a)
{
    switch (a) {
    case NCF_ACTION_ENFORCE_NEURA_S2S: return "enforce_neura_s2s";
    case NCF_ACTION_ALLOW_PLAIN: return "allow_plain";
    case NCF_ACTION_DROP_CONNECTION: return "drop_connection";
    case NCF_ACTION_LOG_ONLY: return "log_only";
    case NCF_ACTION_RESPOND_403: return "respond_403";
    default: return "none";
    }
}

static bool name_eq(const char *s, size_t len, const char *lit)
{
    return strlen(lit) == len && strncasecmp(s, lit, len) == 0;
}

static ncf_match_op op_from_name(const char *s, size_t len)
{
    if (name_eq(s, len, "starts_with")) return NCF_MATCH_STARTS_WITH;
    if (name_eq(s, len, "ends_with")) return NCF_MATCH_ENDS_WITH;
    if (name_eq(s, len, "contains")) return NCF_MATCH_CONTAINS;
    if (name_eq(s, len, "equals")) return NCF_MATCH_EQUALS;
    if (name_eq(s, len, "in")) return NCF_MATCH_IN;
    return (ncf_match_op)-1;
}

static ncf_action_type action_from_name(const char *s, size_t len)
{
    if (name_eq(s, len, "enforce_neura_s2s")) return NCF_ACTION_ENFORCE_NEURA_S2S;
    if (name_eq(s, len, "allow_plain")) return NCF_ACTION_ALLOW_PLAIN;
    if (name_eq(s, len, "drop_connection")) return NCF_ACTION_DROP_CONNECTION;
    if (name_eq(s, len, "log_only")) return NCF_ACTION_LOG_ONLY;
    if (name_eq(s, len, "respond_403")) return NCF_ACTION_RESPOND_403;
    return NCF_ACTION_NONE;
}

/* ==========================================================================
 * 3. 解析上下文
 * ========================================================================== */
/* 沙盒加载上下文：一次 ncf_parse_file() 全程共享 */
typedef struct ncf_load_ctx {
    ncf_config *cfg;
    char        sandbox_root[PATH_MAX];              /* Include 允许的根 */
    char        stack[NCF_MAX_INCLUDE_DEPTH][PATH_MAX]; /* 已展开文件（防环） */
    unsigned    depth;
    char       *err;
    size_t      errcap;
} ncf_load_ctx;

typedef struct ncf_parser {
    ncf_lexer lx;
    ncf_token tok;
    bool have_tok;
    ncf_config *cfg;
    ncf_load_ctx *lc;        /* 沙盒上下文（Include/Preset 需要） */
    ncf_scope scope;         /* 当前文件的作用域：决定 priority 与是否允许 drop */
    char *err;
    size_t errcap;
    bool failed;
    const char *origin;
} ncf_parser;

static void perr(ncf_parser *p, const char *fmt, ...)
{
    if (p->failed) {
        return;
    }
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    if (p->err != NULL && p->errcap > 0) {
        snprintf(p->err, p->errcap, "%s:%u:%u: %s", p->origin,
                 p->tok.line, p->tok.col, msg);
    }
    p->failed = true;
}

static bool advance(ncf_parser *p)
{
    if (p->failed) {
        return false;
    }
    p->have_tok = ncf_lexer_next(&p->lx, &p->tok);
    if (!p->have_tok) {
        perr(p, "%s", p->lx.err);
        return false;
    }
    if (p->tok.type == NCF_TOK_ERROR) {
        perr(p, "%s", p->lx.err);
        return false;
    }
    return true;
}

static bool tok_is_ident(const ncf_parser *p, const char *s)
{
    size_t n = strlen(s);
    return p->tok.type == NCF_TOK_IDENT && p->tok.len == n &&
           strncasecmp(p->tok.start, s, n) == 0;
}

static bool expect(ncf_parser *p, ncf_token_type type, const char *what)
{
    if (p->tok.type != type) {
        perr(p, "期望 %s，实际 %s", what, ncf_token_type_name(p->tok.type));
        return false;
    }
    return advance(p);
}

static char *dup_tok(const ncf_token *t)
{
    char *s = malloc(t->len + 1u);
    if (s == NULL) {
        return NULL;
    }
    memcpy(s, t->start, t->len);
    s[t->len] = '\0';
    return s;
}

/* 复制字符串 token 并处理 \" \\ 转义 */
static char *dup_string(const ncf_token *t)
{
    char *s = malloc(t->len + 1u);
    if (s == NULL) {
        return NULL;
    }
    size_t w = 0;
    for (size_t i = 0; i < t->len; i++) {
        if (t->start[i] == '\\' && i + 1 < t->len) {
            i++;
            switch (t->start[i]) {
            case 'n': s[w++] = '\n'; break;
            case 't': s[w++] = '\t'; break;
            case 'r': s[w++] = '\r'; break;
            default: s[w++] = t->start[i]; break;
            }
        } else {
            s[w++] = t->start[i];
        }
    }
    s[w] = '\0';
    return s;
}

/*
 * 取一个字符串 token 的内容并前进。
 * 注意：不能先 expect(STRING) 再 dup_string(&p->tok)——expect 会先消费 token，
 * 那样拿到的就是下一个 token（这类错在自测里表现为"期望 ';' 实际 标识符"）。
 */
static char *take_string(ncf_parser *p, const char *what)
{
    if (p->tok.type != NCF_TOK_STRING) {
        perr(p, "期望%s，实际 %s", what, ncf_token_type_name(p->tok.type));
        return NULL;
    }
    char *v = dup_string(&p->tok);
    if (v == NULL) {
        perr(p, "内存不足");
        return NULL;
    }
    if (!advance(p)) {
        free(v);
        return NULL;
    }
    return v;
}

/* "5" / "100ms" / "1s" / "5m" / "1h" -> 毫秒 */
static bool parse_duration(const ncf_token *t, uint32_t *out_ms)
{
    uint64_t value = 0;
    size_t i = 0;
    while (i < t->len && isdigit((unsigned char)t->start[i])) {
        value = value * 10u + (uint64_t)(t->start[i] - '0');
        if (value > 100000000u) {
            return false;
        }
        i++;
    }
    uint64_t mult = 1;
    if (i < t->len) {
        char unit[4] = {0};
        size_t ulen = t->len - i;
        if (ulen > 3) {
            return false;
        }
        memcpy(unit, t->start + i, ulen);
        if (strcasecmp(unit, "ms") == 0) mult = 1;
        else if (strcasecmp(unit, "s") == 0) mult = 1000;
        else if (strcasecmp(unit, "m") == 0) mult = 60u * 1000u;
        else if (strcasecmp(unit, "h") == 0) mult = 3600u * 1000u;
        else return false;
    }
    uint64_t ms = value * mult;
    if (ms == 0 || ms > 86400000u) {
        return false;
    }
    *out_ms = (uint32_t)ms;
    return true;
}

/* ==========================================================================
 * 4. 容量增长
 * ========================================================================== */
static bool grow(void **arr, size_t *cap, size_t elem, size_t need)
{
    if (*cap >= need) {
        return true;
    }
    size_t ncap = *cap == 0 ? 4u : *cap * 2u;
    while (ncap < need) {
        ncap *= 2u;
    }
    void *p = realloc(*arr, ncap * elem);
    if (p == NULL) {
        return false;
    }
    *arr = p;
    *cap = ncap;
    return true;
}

/* ==========================================================================
 * 4.5 沙盒：路径解析 / 防越界 / 防环 / 文件加载
 * ========================================================================== */
static ncf_config *parse_impl_scoped(ncf_load_ctx *lc, const char *src, size_t len,
                                     const char *origin, ncf_scope scope,
                                     char *err, size_t errcap);

/* 取 path 所在目录的真实路径（path 可以没有 '/'，此时取当前目录） */
static void path_dir(const char *path, char *out, size_t cap)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    char *slash = strrchr(tmp, '/');
    if (slash == NULL) {
        snprintf(tmp, sizeof tmp, "%s", ".");
    } else if (slash == tmp) {
        snprintf(tmp, sizeof tmp, "%s", "/");
    } else {
        *slash = '\0';
    }
    char real[PATH_MAX];
    if (realpath(tmp, real) != NULL) {
        snprintf(out, cap, "%s", real);
    } else {
        snprintf(out, cap, "%s", tmp);
    }
}

/* child 是否落在 root 之内（含 root 自身）：逐段前缀比较，避免 /a/bc 误判 */
static bool path_inside_root(const char *root, const char *child)
{
    if (root == NULL || child == NULL || root[0] == '\0' || child[0] != '/') {
        return false;
    }
    size_t n = strlen(root);
    if (strncmp(child, root, n) != 0) {
        return false;
    }
    if (child[n] == '\0') {
        return true;
    }
    return root[n - 1] == '/' || child[n] == '/';
}

/* 沙盒内路径规整：绝对路径直接 realpath；相对路径基于 base 目录 */
static bool resolve_in_sandbox(const char *base_dir, const char *path,
                               char *out, size_t cap)
{
    char joined[PATH_MAX * 2];
    if (path[0] == '/') {
        snprintf(joined, sizeof joined, "%s", path);
    } else {
        snprintf(joined, sizeof joined, "%s/%s", base_dir, path);
    }
    char real[PATH_MAX];
    if (realpath(joined, real) == NULL) {
        return false;
    }
    if (strlen(real) >= cap) {
        return false;
    }
    snprintf(out, cap, "%s", real);
    return true;
}

static bool include_stack_has(const ncf_load_ctx *lc, const char *real)
{
    for (unsigned i = 0; i < lc->depth; i++) {
        if (strcmp(lc->stack[i], real) == 0) {
            return true;
        }
    }
    return false;
}

/* 读取整个文件（≤4MiB） */
static char *read_whole_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long size = ftell(fp);
    if (size < 0 || size > (4 << 20)) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *buf = malloc((size_t)size + 1u);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    buf[got] = '\0';
    if (out_len != NULL) {
        *out_len = got;
    }
    return buf;
}

/* 把一份文件解析进 lc->cfg（带作用域与防环） */
static bool load_file_into(ncf_load_ctx *lc, const char *path, ncf_scope scope,
                           char *err, size_t errcap)
{
    char real[PATH_MAX];
    if (realpath(path, real) == NULL) {
        snprintf(err, errcap, "%s: 文件不存在或不可访问", path);
        return false;
    }
    if (lc->depth >= NCF_MAX_INCLUDE_DEPTH) {
        snprintf(err, errcap, "%.300s: 包含层数超过上限 %u（可能存在循环 Include）",
                 real, NCF_MAX_INCLUDE_DEPTH);
        return false;
    }
    if (include_stack_has(lc, real)) {
        snprintf(err, errcap, "%.300s: 检测到循环 Include（该文件已在加载栈中）",
                 real);
        return false;
    }
    size_t len = 0;
    char *buf = read_whole_file(real, &len);
    if (buf == NULL) {
        snprintf(err, errcap, "%.300s: 无法读取（%s）", real, strerror(errno));
        return false;
    }
    snprintf(lc->stack[lc->depth], sizeof lc->stack[lc->depth], "%s", real);
    lc->depth++;
    ncf_config *got = parse_impl_scoped(lc, buf, len, real, scope, err, errcap);
    lc->depth--;
    free(buf);
    return got != NULL;
}

static bool cfg_add_string(char ***arr, size_t *count, const char *s, size_t max)
{
    if (*count >= max) {
        return false;
    }
    char **grown = realloc(*arr, (*count + 1u) * sizeof(char *));
    if (grown == NULL) {
        return false;
    }
    *arr = grown;
    grown[*count] = strdup(s);
    if (grown[*count] == NULL) {
        return false;
    }
    (*count)++;
    return true;
}

/* ==========================================================================
 * 5. 各块解析
 * ========================================================================== */
/*
 * Enable Preset "name";
 *
 * 从预设目录加载 <dir>/<name>.ncf，以 **SYSTEM 作用域** 解析：
 *   - 隐式 priority = 10000（压过所有用户规则）；
 *   - 允许 Action: drop_connection。
 * 预设内部还可以再 Enable Preset / Include，但受深度与防环约束。
 */
static bool parse_enable_preset(ncf_parser *p)
{
    if (!tok_is_ident(p, "Preset")) {
        perr(p, "仅支持 'Enable Preset \"<name>\";'");
        return false;
    }
    if (!advance(p)) {
        return false;
    }
    char *name = take_string(p, "预设名（字符串）");
    if (name == NULL) {
        return false;
    }
    if (!expect(p, NCF_TOK_SEMI, "';'")) {
        free(name);
        return false;
    }
    if (name[0] == '\0' || strchr(name, '/') != NULL ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        perr(p, "非法预设名 '%s'（只允许 [A-Za-z0-9_-]，不得含路径分隔符）", name);
        free(name);
        return false;
    }
    if (p->cfg->preset_count >= NCF_MAX_PRESETS) {
        perr(p, "Preset 数量超过上限 %u", NCF_MAX_PRESETS);
        free(name);
        return false;
    }
    for (size_t i = 0; i < p->cfg->preset_count; i++) {
        if (strcmp(p->cfg->presets[i], name) == 0) {
            perr(p, "Preset '%s' 重复启用", name);
            free(name);
            return false;
        }
    }

    char path[PATH_MAX * 2];
    snprintf(path, sizeof path, "%s/%s.ncf", ncf_get_preset_dir(), name);
    char inner[512] = {0};
    if (!load_file_into(p->lc, path, NCF_SCOPE_SYSTEM, inner, sizeof inner)) {
        perr(p, "启用预设 '%s' 失败: %s", name, inner);
        free(name);
        return false;
    }
    if (!cfg_add_string(&p->cfg->presets, &p->cfg->preset_count, name,
                        NCF_MAX_PRESETS)) {
        perr(p, "内存不足");
        free(name);
        return false;
    }
    free(name);
    return true;
}

/*
 * Include MatchLang "path";
 *
 * 以 **当前文件的作用域** 展开另一份 MatchLang 配置，并强制沙盒约束：
 *   - 路径必须落在顶层配置所在目录（sandbox_root）之内，越界直接报错；
 *   - 禁止循环包含与超过 NCF_MAX_INCLUDE_DEPTH 层嵌套。
 */
static bool parse_include(ncf_parser *p)
{
    if (!tok_is_ident(p, "MatchLang")) {
        perr(p, "仅支持 'Include MatchLang \"<file>\";'");
        return false;
    }
    if (!advance(p)) {
        return false;
    }
    char *path = take_string(p, "被包含的文件路径");
    if (path == NULL) {
        return false;
    }
    if (!expect(p, NCF_TOK_SEMI, "';'")) {
        free(path);
        return false;
    }

    char base[PATH_MAX];
    path_dir(p->origin, base, sizeof base);
    char real[PATH_MAX];
    if (!resolve_in_sandbox(base, path, real, sizeof real)) {
        perr(p, "Include 目标不存在: %s（基于 %s）", path, base);
        free(path);
        return false;
    }
    if (p->lc != NULL && p->lc->sandbox_root[0] != '\0' &&
        !path_inside_root(p->lc->sandbox_root, real)) {
        perr(p, "Include 越界：%s 不在沙盒根 %s 之内", real,
             p->lc->sandbox_root);
        free(path);
        return false;
    }
    if (p->cfg->include_count >= NCF_MAX_INCLUDES) {
        perr(p, "Include 数量超过上限 %u", NCF_MAX_INCLUDES);
        free(path);
        return false;
    }

    char inner[512] = {0};
    if (!load_file_into(p->lc, real, p->scope, inner, sizeof inner)) {
        perr(p, "Include '%s' 失败: %s", path, inner);
        free(path);
        return false;
    }
    if (!cfg_add_string(&p->cfg->include_paths, &p->cfg->include_count, real,
                        NCF_MAX_INCLUDES)) {
        perr(p, "内存不足");
        free(path);
        return false;
    }
    free(path);
    return true;
}

/*
 * Defined Ban "name";
 *
 * 断言该 Ban 已定义（允许前向引用，解析结束后统一校验）。
 */
static bool parse_defined_ban(ncf_parser *p)
{
    if (!tok_is_ident(p, "Ban")) {
        perr(p, "仅支持 'Defined Ban \"<name>\";'");
        return false;
    }
    if (!advance(p)) {
        return false;
    }
    char *name = take_string(p, "Ban 名称");
    if (name == NULL) {
        return false;
    }
    if (!expect(p, NCF_TOK_SEMI, "';'")) {
        free(name);
        return false;
    }
    ncf_ban_assert *grown = realloc(p->cfg->ban_asserts,
                                    (p->cfg->ban_assert_count + 1u) *
                                        sizeof(ncf_ban_assert));
    if (grown == NULL) {
        perr(p, "内存不足");
        free(name);
        return false;
    }
    p->cfg->ban_asserts = grown;
    ncf_ban_assert *a = &grown[p->cfg->ban_assert_count];
    memset(a, 0, sizeof *a);
    a->name = name;
    a->origin = strdup(p->origin);
    a->line = p->tok.line;
    p->cfg->ban_assert_count++;
    return true;
}

/*
 * Policy {
 *     Plaintext: deny;      # 未匹配路径默认要求 Neura-S2S（全站加密，推荐）
 *     Plaintext: allow;     # 兼容旧行为：未匹配路径允许明文
 * }
 */
static bool parse_policy(ncf_parser *p)
{
    if (!expect(p, NCF_TOK_LBRACE, "'{'")) {
        return false;
    }
    while (!p->failed && p->tok.type != NCF_TOK_RBRACE) {
        if (p->tok.type == NCF_TOK_EOF) {
            perr(p, "Policy 块未闭合");
            return false;
        }
        if (tok_is_ident(p, "Plaintext")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (tok_is_ident(p, "deny")) {
                p->cfg->plaintext = NCF_PLAINTEXT_DENY;
            } else if (tok_is_ident(p, "allow")) {
                p->cfg->plaintext = NCF_PLAINTEXT_ALLOW;
            } else {
                perr(p, "Plaintext 只接受 deny|allow，实际 '%.*s'",
                     (int)p->tok.len, p->tok.start);
                return false;
            }
            if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
            continue;
        }
        perr(p, "Policy 块内未知字段 '%.*s'（期望 Plaintext）",
             (int)p->tok.len, p->tok.start);
        return false;
    }
    return expect(p, NCF_TOK_RBRACE, "'}'");
}

/*
 * 例如：
 *   Encrypt Encrypted Site {
 *       Host Match: in "test.jqlhtm.cn,www.test.jqlhtm.cn";
 *       Path Match: starts_with "/";
 *       Action: enforce_neura_s2s;
 *   }
 *   Encrypt Legacy Hosts {
 *       Host Match: in "aiagent.pltusf.asia,tuweb.pltusf.asia";
 *       Path Match: starts_with "/";
 *       Action: allow_plain;
 *   }
 */
static bool parse_host_match(ncf_parser *p, ncf_match *out)
{
    /* 已在 "Host" 之后：期望 Match: <op> "<value>"; */
    if (!advance(p) || !tok_is_ident(p, "Match")) {
        perr(p, "期望 'Host Match:'");
        return false;
    }
    if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
        return false;
    }
    if (p->tok.type != NCF_TOK_IDENT) {
        perr(p, "期望 Host 匹配算子");
        return false;
    }
    ncf_match_op op = op_from_name(p->tok.start, p->tok.len);
    if ((int)op < 0) {
        perr(p, "未知 Host 匹配算子 '%.*s'（starts_with/ends_with/contains/equals/in）",
             (int)p->tok.len, p->tok.start);
        return false;
    }
    out->op = op;
    out->value = NULL;
    if (!advance(p)) {
        return false;
    }
    out->value = take_string(p, "Host 字符串");
    if (out->value == NULL) {
        return false;
    }
    if (!expect(p, NCF_TOK_SEMI, "';'")) {
        return false;
    }
    return true;
}

static bool parse_encrypt(ncf_parser *p)
{
    if (!grow((void **)&p->cfg->enc_routes, &p->cfg->enc_cap,
              sizeof(ncf_encrypt_route), p->cfg->enc_count + 1u)) {
        perr(p, "内存不足");
        return false;
    }
    ncf_encrypt_route *r = &p->cfg->enc_routes[p->cfg->enc_count];
    memset(r, 0, sizeof *r);
    r->line = p->tok.line;
    r->enabled = true;
    r->action = NCF_ACTION_NONE;
    r->scope = p->scope;
    r->priority = scope_priority(p->scope);

    /* 名称：直到 '{' 为止的所有 ident */
    char name[SH_MAX_RULE_NAME] = {0};
    size_t w = 0;
    while (p->tok.type == NCF_TOK_IDENT) {
        if (w + p->tok.len + 2u >= sizeof name) {
            perr(p, "Encrypt 名称过长");
            return false;
        }
        if (w > 0) {
            name[w++] = ' ';
        }
        memcpy(name + w, p->tok.start, p->tok.len);
        w += p->tok.len;
        if (!advance(p)) {
            return false;
        }
    }
    r->name = strdup(name);
    if (r->name == NULL) {
        perr(p, "内存不足");
        return false;
    }
    if (!expect(p, NCF_TOK_LBRACE, "'{'")) {
        return false;
    }

    while (!p->failed && p->tok.type != NCF_TOK_RBRACE) {
        if (p->tok.type == NCF_TOK_EOF) {
            perr(p, "Encrypt 块未闭合");
            return false;
        }
        if (tok_is_ident(p, "Path")) {
            if (!advance(p) || !tok_is_ident(p, "Match")) {
                perr(p, "期望 'Path Match:'");
                return false;
            }
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (p->tok.type != NCF_TOK_IDENT) {
                perr(p, "期望匹配算子");
                return false;
            }
            ncf_match_op op = op_from_name(p->tok.start, p->tok.len);
            if ((int)op < 0) {
                perr(p, "未知匹配算子 '%.*s'", (int)p->tok.len, p->tok.start);
                return false;
            }
            if (!advance(p)) {
                return false;
            }
            r->path.op = op;
            r->path.value = take_string(p, "路径字符串");
            if (r->path.value == NULL) {
                return false;
            }
            if (!expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else if (tok_is_ident(p, "Host")) {
            if (!parse_host_match(p, &r->host)) {
                return false;
            }
            r->has_host = true;
        } else if (tok_is_ident(p, "Action")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (p->tok.type != NCF_TOK_IDENT) {
                perr(p, "期望 Action 值");
                return false;
            }
            r->action = action_from_name(p->tok.start, p->tok.len);
            if (r->action == NCF_ACTION_NONE) {
                perr(p, "未知 Action '%.*s'", (int)p->tok.len, p->tok.start);
                return false;
            }
            /* 用户作用域禁止 drop：只有系统预设（priority 10000）才允许 */
            if (r->action == NCF_ACTION_DROP_CONNECTION &&
                p->scope != NCF_SCOPE_SYSTEM) {
                perr(p, "用户作用域禁止 Action: drop_connection"
                        "（仅系统预设可用，请改用 respond_403）；Encrypt 规则 '%s'",
                     r->name != NULL ? r->name : "?");
                return false;
            }
            if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else {
            perr(p, "Encrypt 块内未知语句 '%.*s'", (int)p->tok.len, p->tok.start);
            return false;
        }
    }
    if (!expect(p, NCF_TOK_RBRACE, "'}'")) {
        return false;
    }
    if (r->path.value == NULL) {
        perr(p, "Encrypt 块缺少 'Path Match:'");
        return false;
    }
    if (r->action == NCF_ACTION_NONE) {
        r->action = NCF_ACTION_ENFORCE_NEURA_S2S;
    }
    p->cfg->enc_count++;
    return true;
}

static bool parse_rewrite(ncf_parser *p)
{
    if (!grow((void **)&p->cfg->rewrites, &p->cfg->rw_cap,
              sizeof(ncf_rewrite_rule), p->cfg->rw_count + 1u)) {
        perr(p, "内存不足");
        return false;
    }
    ncf_rewrite_rule *r = &p->cfg->rewrites[p->cfg->rw_count];
    memset(r, 0, sizeof *r);
    r->line = p->tok.line;
    r->scope = p->scope;
    r->priority = scope_priority(p->scope);

    char name[SH_MAX_RULE_NAME] = {0};
    size_t w = 0;
    while (p->tok.type == NCF_TOK_IDENT) {
        if (w + p->tok.len + 2u >= sizeof name) {
            perr(p, "Rewrite 名称过长");
            return false;
        }
        if (w > 0) {
            name[w++] = ' ';
        }
        memcpy(name + w, p->tok.start, p->tok.len);
        w += p->tok.len;
        if (!advance(p)) {
            return false;
        }
    }
    r->name = strdup(name);
    if (r->name == NULL) {
        perr(p, "内存不足");
        return false;
    }
    if (!expect(p, NCF_TOK_LBRACE, "'{'")) {
        return false;
    }

    while (!p->failed && p->tok.type != NCF_TOK_RBRACE) {
        if (p->tok.type == NCF_TOK_EOF) {
            perr(p, "Rewrite 块未闭合");
            return false;
        }
        if (tok_is_ident(p, "using")) {
            if (!advance(p) || !tok_is_ident(p, "engine")) {
                perr(p, "期望 'using engine matchlang;'");
                return false;
            }
            if (!advance(p)) {
                return false;
            }
            if (!tok_is_ident(p, "matchlang")) {
                perr(p, "仅支持 'using engine matchlang;'");
                return false;
            }
            r->engine_matchlang = true;
            if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else if (tok_is_ident(p, "pattern")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (!tok_is_ident(p, "Locate")) {
                perr(p, "期望 'Locate \"...\" until \"...\" as $var'");
                return false;
            }
            if (!advance(p)) {
                return false;
            }
            r->steps = calloc(SH_MAX_REWRITE_VARS, sizeof(ncf_locate_step));
            if (r->steps == NULL) {
                perr(p, "内存不足");
                return false;
            }
            r->steps[0].kind = NCF_LOCATE_LITERAL;
            r->steps[0].text = take_string(p, "定位字面量");
            if (r->steps[0].text == NULL) {
                return false;
            }
            r->step_count = 1;

            while (tok_is_ident(p, "until")) {
                if (!advance(p)) {
                    return false;
                }
                if (r->step_count + 2u > SH_MAX_REWRITE_VARS) {
                    perr(p, "Rewrite 步骤过多（上限 %u）", SH_MAX_REWRITE_VARS);
                    return false;
                }
                r->steps[r->step_count].kind = NCF_LOCATE_UNTIL;
                r->steps[r->step_count].text = take_string(p, "分隔符");
                if (r->steps[r->step_count].text == NULL) {
                    return false;
                }
                r->step_count++;
                if (!tok_is_ident(p, "as")) {
                    perr(p, "期望 'as $var'");
                    return false;
                }
                if (!advance(p) || p->tok.type != NCF_TOK_VAR) {
                    perr(p, "期望变量（如 $id）");
                    return false;
                }
                if (r->step_count >= SH_MAX_REWRITE_VARS) {
                    perr(p, "捕获变量过多（上限 %u）", SH_MAX_REWRITE_VARS);
                    return false;
                }
                r->steps[r->step_count].kind = NCF_LOCATE_VAR;
                r->steps[r->step_count].text = dup_tok(&p->tok);
                r->step_count++;
                if (!advance(p)) {
                    return false;
                }
            }
            /* 未使用 until 时，允许 'Locate "x" as $v' 直接把后半段作为变量 */
            if (r->step_count == 1) {
                if (!tok_is_ident(p, "as")) {
                    perr(p, "期望 'until \"...\" as $var'");
                    return false;
                }
                if (!advance(p) || p->tok.type != NCF_TOK_VAR) {
                    perr(p, "期望变量名");
                    return false;
                }
                if (r->step_count + 1u > SH_MAX_REWRITE_VARS) {
                    perr(p, "Rewrite 步骤过多（上限 %u）", SH_MAX_REWRITE_VARS);
                    return false;
                }
                r->steps[r->step_count].kind = NCF_LOCATE_VAR;
                r->steps[r->step_count].text = dup_tok(&p->tok);
                r->step_count++;
                if (!advance(p)) {
                    return false;
                }
            }
            if (!expect(p, NCF_TOK_LBRACE, "'{'")) {
                return false;
            }
            if (!tok_is_ident(p, "Replace")) {
                perr(p, "期望 'Replace with \"...\";'");
                return false;
            }
            if (!advance(p) || !tok_is_ident(p, "with")) {
                perr(p, "期望 'Replace with \"...\";'");
                return false;
            }
            if (!advance(p)) {
                return false;
            }
            r->replace_template = take_string(p, "替换模板");
            if (r->replace_template == NULL) {
                return false;
            }
            if (!expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
            if (!expect(p, NCF_TOK_RBRACE, "'}'")) {
                return false;
            }
        } else {
            perr(p, "Rewrite 块内未知语句 '%.*s'", (int)p->tok.len, p->tok.start);
            return false;
        }
    }
    if (!expect(p, NCF_TOK_RBRACE, "'}'")) {
        return false;
    }
    if (r->replace_template == NULL || r->step_count == 0) {
        perr(p, "Rewrite 缺少 pattern/Replace");
        return false;
    }
    p->cfg->rw_count++;
    return true;
}

static bool parse_ban(ncf_parser *p)
{
    if (p->tok.type != NCF_TOK_STRING && p->tok.type != NCF_TOK_IDENT) {
        perr(p, "Ban 需要名称");
        return false;
    }
    if (!grow((void **)&p->cfg->bans, &p->cfg->ban_cap,
              sizeof(ncf_ban_rule), p->cfg->ban_count + 1u)) {
        perr(p, "内存不足");
        return false;
    }
    ncf_ban_rule *r = &p->cfg->bans[p->cfg->ban_count];
    memset(r, 0, sizeof *r);
    r->line = p->tok.line;
    r->scope = p->scope;
    r->priority = scope_priority(p->scope);
    r->name = p->tok.type == NCF_TOK_STRING ? dup_string(&p->tok) : dup_tok(&p->tok);
    r->ban_ms = SH_WAF_DEFAULT_BAN_MS;
    r->checker = NCF_CHECKER_IP;
    if (r->name == NULL) {
        perr(p, "内存不足");
        return false;
    }
    if (!advance(p) || !expect(p, NCF_TOK_LBRACE, "'{'")) {
        return false;
    }

    while (!p->failed && p->tok.type != NCF_TOK_RBRACE) {
        if (p->tok.type == NCF_TOK_EOF) {
            perr(p, "Ban 块未闭合");
            return false;
        }
        if (tok_is_ident(p, "Checker")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (p->tok.type != NCF_TOK_IDENT) {
                perr(p, "期望 Checker 类型");
                return false;
            }
            if (tok_is_ident(p, "IP")) r->checker = NCF_CHECKER_IP;
            else if (tok_is_ident(p, "User-Agent")) r->checker = NCF_CHECKER_USER_AGENT;
            else if (tok_is_ident(p, "Path")) r->checker = NCF_CHECKER_PATH;
            else if (tok_is_ident(p, "Method")) r->checker = NCF_CHECKER_METHOD;
            else if (tok_is_ident(p, "Header")) r->checker = NCF_CHECKER_HEADER;
            else if (tok_is_ident(p, "Cookie")) r->checker = NCF_CHECKER_COOKIE;
            else if (tok_is_ident(p, "Query")) r->checker = NCF_CHECKER_QUERY;
            else {
                perr(p, "未知 Checker '%.*s'", (int)p->tok.len, p->tok.start);
                return false;
            }
            if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else if (tok_is_ident(p, "Match")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            r->match_any = true;
            for (;;) {
                if (p->tok.type != NCF_TOK_IDENT) {
                    perr(p, "期望匹配算子");
                    return false;
                }
                ncf_match_op op = op_from_name(p->tok.start, p->tok.len);
                if ((int)op < 0) {
                    perr(p, "未知匹配算子 '%.*s'", (int)p->tok.len, p->tok.start);
                    return false;
                }
                if (!advance(p)) {
                    return false;
                }
                size_t mcap = r->match_count + 1u;
                ncf_match *grown = realloc(r->matches, mcap * sizeof(ncf_match));
                if (grown == NULL) {
                    perr(p, "内存不足");
                    return false;
                }
                r->matches = grown;
                r->matches[r->match_count].op = op;
                r->matches[r->match_count].value = take_string(p, "字符串");
                if (r->matches[r->match_count].value == NULL) {
                    return false;
                }
                r->match_count++;
                if (r->match_count >= SH_MAX_MATCHES_PER_RULE) {
                    perr(p, "Match 条目过多（上限 %u）", SH_MAX_MATCHES_PER_RULE);
                    return false;
                }
                if (tok_is_ident(p, "or")) {
                    r->match_any = true;
                    if (!advance(p)) {
                        return false;
                    }
                    continue;
                }
                if (tok_is_ident(p, "and")) {
                    r->match_any = false;
                    if (!advance(p)) {
                        return false;
                    }
                    continue;
                }
                break;
            }
            if (!expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else if (tok_is_ident(p, "Trigger")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (tok_is_ident(p, "Frequency")) r->trigger = NCF_TRIGGER_FREQUENCY;
            else if (tok_is_ident(p, "Visit")) r->trigger = NCF_TRIGGER_VISIT;
            else {
                perr(p, "未知 Trigger '%.*s'", (int)p->tok.len, p->tok.start);
                return false;
            }
            if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else if (tok_is_ident(p, "Condition")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (tok_is_ident(p, "Immediately")) {
                r->condition = NCF_COND_IMMEDIATELY;
                if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                    return false;
                }
            } else if (tok_is_ident(p, "More")) {
                r->condition = NCF_COND_MORE_THAN;
                if (!advance(p) || !tok_is_ident(p, "Than")) {
                    perr(p, "期望 'More Than N Per <时长>'");
                    return false;
                }
                if (!advance(p) || p->tok.type != NCF_TOK_NUMBER) {
                    perr(p, "期望阈值数字");
                    return false;
                }
                uint64_t threshold = 0;
                for (size_t i = 0; i < p->tok.len && isdigit((unsigned char)p->tok.start[i]); i++) {
                    threshold = threshold * 10u + (uint64_t)(p->tok.start[i] - '0');
                }
                r->threshold = (uint32_t)SH_MAX(threshold, 1u);
                if (!advance(p) || !tok_is_ident(p, "Per")) {
                    perr(p, "期望 'Per <时长>'");
                    return false;
                }
                if (!advance(p) || p->tok.type != NCF_TOK_NUMBER) {
                    perr(p, "期望时长（如 1s）");
                    return false;
                }
                if (!parse_duration(&p->tok, &r->window_ms)) {
                    perr(p, "非法时长 '%.*s'", (int)p->tok.len, p->tok.start);
                    return false;
                }
                if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                    return false;
                }
            } else {
                perr(p, "未知 Condition");
                return false;
            }
        } else if (tok_is_ident(p, "Action")) {
            if (!advance(p) || !expect(p, NCF_TOK_COLON, "':'")) {
                return false;
            }
            if (p->tok.type != NCF_TOK_IDENT) {
                perr(p, "期望 Action 值");
                return false;
            }
            r->action = action_from_name(p->tok.start, p->tok.len);
            if (r->action == NCF_ACTION_NONE) {
                perr(p, "未知 Action '%.*s'", (int)p->tok.len, p->tok.start);
                return false;
            }
            if (r->action == NCF_ACTION_DROP_CONNECTION &&
                p->scope != NCF_SCOPE_SYSTEM) {
                perr(p, "用户作用域禁止 Action: drop_connection"
                        "（仅系统预设可用，请改用 respond_403）；Ban '%s'",
                     r->name != NULL ? r->name : "?");
                return false;
            }
            if (!advance(p) || !expect(p, NCF_TOK_SEMI, "';'")) {
                return false;
            }
        } else {
            perr(p, "Ban 块内未知语句 '%.*s'", (int)p->tok.len, p->tok.start);
            return false;
        }
    }
    if (!expect(p, NCF_TOK_RBRACE, "'}'")) {
        return false;
    }
    if (r->action == NCF_ACTION_NONE) {
        r->action = NCF_ACTION_DROP_CONNECTION;
    }
    p->cfg->ban_count++;
    return true;
}

/* ==========================================================================
 * 6. 入口
 * ========================================================================== */
ncf_config *ncf_config_new(void)
{
    ncf_config *cfg = calloc(1, sizeof *cfg);
    if (cfg != NULL) {
        /*
         * 默认策略：allow。
         *
         * 设计取舍（v1.0.1）：
         *   - Safe-HTTP 的第一目标是"任意普通客户端无需安装 SDK 即可访问"，
         *     因此未显式配置 Encrypt 规则的路径默认按明文放行；
         *   - 抗量子能力不退让：需要保护的路由（如 /api/、/admin/）必须用
         *     `Action: enforce_neura_s2s;` 显式强制 Neura-S2S（X-Wing）；
         *   - 高安全站点可写 `Policy { Plaintext: deny; }` 恢复全站 fail-close。
         */
        cfg->plaintext = NCF_PLAINTEXT_ALLOW;
        cfg->scope = NCF_SCOPE_USER;
    }
    return cfg;
}

void ncf_config_free(ncf_config *cfg)
{
    if (cfg == NULL) {
        return;
    }
    for (size_t i = 0; i < cfg->enc_count; i++) {
        free(cfg->enc_routes[i].name);
        free(cfg->enc_routes[i].path.value);
        free(cfg->enc_routes[i].host.value);
    }
    free(cfg->enc_routes);
    for (size_t i = 0; i < cfg->rw_count; i++) {
        ncf_rewrite_rule *r = &cfg->rewrites[i];
        free(r->name);
        for (size_t k = 0; k < r->step_count; k++) {
            free(r->steps[k].text);
        }
        free(r->steps);
        free(r->replace_template);
    }
    free(cfg->rewrites);
    for (size_t i = 0; i < cfg->ban_count; i++) {
        ncf_ban_rule *b = &cfg->bans[i];
        free(b->name);
        free(b->header_name);
        for (size_t k = 0; k < b->match_count; k++) {
            free(b->matches[k].value);
        }
        free(b->matches);
    }
    free(cfg->bans);
    for (size_t i = 0; i < cfg->ban_assert_count; i++) {
        free(cfg->ban_asserts[i].name);
        free(cfg->ban_asserts[i].origin);
    }
    free(cfg->ban_asserts);
    for (size_t i = 0; i < cfg->include_count; i++) {
        free(cfg->include_paths[i]);
    }
    free(cfg->include_paths);
    for (size_t i = 0; i < cfg->preset_count; i++) {
        free(cfg->presets[i]);
    }
    free(cfg->presets);
    free(cfg->sandbox_root);
    free(cfg->source_path);
    free(cfg);
}

/*
 * 解析期终检（在整份配置 + 所有 Preset/Include 都展开后执行）：
 *   1. `Defined Ban "x";` 的断言必须成立，否则报错（带文件:行）；
 *   2. 规则按 priority 降序稳定排序（系统预设 10000 排在用户规则 100 之前）。
 */
static bool finalize_config(ncf_config *cfg, char *err, size_t errcap)
{
    for (size_t i = 0; i < cfg->ban_assert_count; i++) {
        ncf_ban_assert *a = &cfg->ban_asserts[i];
        if (ncf_find_ban(cfg, a->name) == NULL) {
            if (err != NULL && errcap > 0) {
                snprintf(err, errcap,
                         "%s:%u: Defined Ban \"%s\" 未定义（没有对应的 Ban 块）",
                         a->origin != NULL ? a->origin : "?", a->line, a->name);
            }
            return false;
        }
    }

    /* 插入排序（稳定）：enc_routes / bans 按 priority 降序 */
    for (size_t i = 1; i < cfg->enc_count; i++) {
        ncf_encrypt_route key = cfg->enc_routes[i];
        size_t j = i;
        while (j > 0 && cfg->enc_routes[j - 1].priority < key.priority) {
            cfg->enc_routes[j] = cfg->enc_routes[j - 1];
            j--;
        }
        cfg->enc_routes[j] = key;
    }
    for (size_t i = 1; i < cfg->ban_count; i++) {
        ncf_ban_rule key = cfg->bans[i];
        size_t j = i;
        while (j > 0 && cfg->bans[j - 1].priority < key.priority) {
            cfg->bans[j] = cfg->bans[j - 1];
            j--;
        }
        cfg->bans[j] = key;
    }
    return true;
}

static ncf_config *parse_impl_scoped(ncf_load_ctx *lc, const char *src, size_t len,
                                     const char *origin, ncf_scope scope,
                                     char *err, size_t errcap)
{
    ncf_parser p;
    memset(&p, 0, sizeof p);
    p.err = err;
    p.errcap = errcap;
    p.origin = origin != NULL ? origin : "<memory>";
    p.cfg = lc->cfg;
    p.lc = lc;
    p.scope = scope;
    ncf_lexer_init(&p.lx, src, len);

    if (!advance(&p)) {
        return NULL;
    }
    while (!p.failed && p.tok.type != NCF_TOK_EOF) {
        if (tok_is_ident(&p, "Encrypt")) {
            if (!advance(&p) || !parse_encrypt(&p)) {
                return NULL;
            }
        } else if (tok_is_ident(&p, "Rewrite")) {
            if (!advance(&p) || !parse_rewrite(&p)) {
                return NULL;
            }
        } else if (tok_is_ident(&p, "Ban")) {
            if (!advance(&p) || !parse_ban(&p)) {
                return NULL;
            }
        } else if (tok_is_ident(&p, "Policy")) {
            if (!advance(&p) || !parse_policy(&p)) {
                return NULL;
            }
        } else if (tok_is_ident(&p, "Enable")) {
            if (!advance(&p) || !parse_enable_preset(&p)) {
                return NULL;
            }
        } else if (tok_is_ident(&p, "Include")) {
            if (!advance(&p) || !parse_include(&p)) {
                return NULL;
            }
        } else if (tok_is_ident(&p, "Defined")) {
            if (!advance(&p) || !parse_defined_ban(&p)) {
                return NULL;
            }
        } else {
            perr(&p, "未知顶层块 '%.*s'"
                     "（期望 Encrypt/Rewrite/Ban/Policy/Enable/Include/Defined）",
                 (int)p.tok.len, p.tok.start);
            return NULL;
        }
    }
    if (p.failed) {
        return NULL;
    }
    /* 顶层文件的行数用于展示（包含文件的行数不覆盖它） */
    if (lc->cfg->line_count == 0) {
        lc->cfg->line_count = p.lx.line;
    }
    return lc->cfg;
}

/* 顶层入口：建立沙盒上下文（沙盒根 = 顶层配置所在目录的真实路径） */
static ncf_config *parse_impl(const char *src, size_t len, const char *origin,
                              char *err, size_t errcap)
{
    ncf_config *cfg = ncf_config_new();
    if (cfg == NULL) {
        if (err != NULL && errcap > 0) {
            snprintf(err, errcap, "%s: 内存不足", origin != NULL ? origin : "<memory>");
        }
        return NULL;
    }
    cfg->source_path = strdup(origin != NULL ? origin : "<memory>");
    cfg->scope = NCF_SCOPE_USER;

    ncf_load_ctx lc;
    memset(&lc, 0, sizeof lc);
    lc.cfg = cfg;
    lc.err = err;
    lc.errcap = errcap;
    if (origin != NULL && origin[0] != '\0') {
        path_dir(origin, lc.sandbox_root, sizeof lc.sandbox_root);
        cfg->sandbox_root = strdup(lc.sandbox_root);
    }

    if (parse_impl_scoped(&lc, src, len, origin, NCF_SCOPE_USER, err, errcap) == NULL) {
        ncf_config_free(cfg);
        return NULL;
    }
    if (!finalize_config(cfg, err, errcap)) {
        ncf_config_free(cfg);
        return NULL;
    }
    return cfg;
}

ncf_config *ncf_parse_string(const char *src, size_t len,
                             const char *origin, char *err, size_t errcap)
{
    if (src == NULL) {
        if (err != NULL && errcap > 0) {
            snprintf(err, errcap, "%s: 空配置", origin != NULL ? origin : "<memory>");
        }
        return NULL;
    }
    return parse_impl(src, len, origin, err, errcap);
}

ncf_config *ncf_parse_file(const char *path, char *err, size_t errcap)
{
    if (path == NULL) {
        return NULL;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        if (err != NULL && errcap > 0) {
            snprintf(err, errcap, "%s: 无法打开配置 (%s)", path, strerror(errno));
        }
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long size = ftell(fp);
    if (size < 0 || size > (4 << 20)) {
        fclose(fp);
        if (err != NULL && errcap > 0) {
            snprintf(err, errcap, "%s: 配置文件过大", path);
        }
        return NULL;
    }
    rewind(fp);
    char *buf = malloc((size_t)size + 1u);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    buf[got] = '\0';

    ncf_config *cfg = parse_impl(buf, got, path, err, errcap);
    free(buf);
    return cfg;
}

int ncf_validate(const char *src, size_t len, const char *origin,
                 char *err, size_t errcap)
{
    ncf_config *cfg = parse_impl(src, len, origin, err, errcap);
    if (cfg == NULL) {
        return -1;
    }
    ncf_config_free(cfg);
    return 0;
}

/* ==========================================================================
 * 7. 运行期查询
 * ========================================================================== */
static bool match_value(const ncf_match *m, const char *s, size_t len)
{
    if (m->value == NULL) {
        return false;
    }
    switch (m->op) {
    case NCF_MATCH_STARTS_WITH:
        return len >= strlen(m->value) &&
               memcmp(s, m->value, strlen(m->value)) == 0;
    case NCF_MATCH_ENDS_WITH: {
        size_t n = strlen(m->value);
        return len >= n && memcmp(s + len - n, m->value, n) == 0;
    }
    case NCF_MATCH_CONTAINS:
        return memmem(s, len, m->value, strlen(m->value)) != NULL;
    case NCF_MATCH_EQUALS:
        return len == strlen(m->value) && memcmp(s, m->value, len) == 0;
    case NCF_MATCH_IN: {
        const char *p = m->value;
        while (*p != '\0') {
            while (*p == ' ' || *p == ',') {
                p++;
            }
            const char *start = p;
            while (*p != '\0' && *p != ',') {
                p++;
            }
            size_t n = (size_t)(p - start);
            while (n > 0 && start[n - 1] == ' ') {
                n--;
            }
            if (n == len && memcmp(start, s, len) == 0) {
                return true;
            }
        }
        return false;
    }
    default:
        return false;
    }
}

const ncf_encrypt_route *ncf_route_for_path(const ncf_config *cfg,
                                            const char *path, size_t path_len)
{
    if (cfg == NULL || path == NULL) {
        return NULL;
    }
    const ncf_encrypt_route *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < cfg->enc_count; i++) {
        const ncf_encrypt_route *r = &cfg->enc_routes[i];
        if (!r->enabled) {
            continue;
        }
        if (!match_value(&r->path, path, path_len)) {
            continue;
        }
        size_t n = r->path.value != NULL ? strlen(r->path.value) : 0;
        if (best == NULL || n > best_len) {
            best = r;
            best_len = n;
        }
    }
    return best;
}

const ncf_encrypt_route *ncf_route_for_request(const ncf_config *cfg,
                                               const char *host, size_t host_len,
                                               const char *path, size_t path_len)
{
    if (cfg == NULL || path == NULL) {
        return NULL;
    }
    const ncf_encrypt_route *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < cfg->enc_count; i++) {
        const ncf_encrypt_route *r = &cfg->enc_routes[i];
        if (!r->enabled) {
            continue;
        }
        if (!match_value(&r->path, path, path_len)) {
            continue;
        }
        if (r->has_host) {
            if (host == NULL || !match_value(&r->host, host, host_len)) {
                continue;
            }
        }
        size_t n = r->path.value != NULL ? strlen(r->path.value) : 0;
        if (best == NULL) {
            best = r;
            best_len = n;
            continue;
        }
        /* 1) 优先级高者胜（系统预设 10000 > 用户规则 100）
         * 2) 同优先级比路径长度
         * 3) 再同则「带 Host 约束」的更具体 */
        if (r->priority > best->priority) {
            best = r;
            best_len = n;
        } else if (r->priority == best->priority &&
                   (n > best_len ||
                    (n == best_len && r->has_host && !best->has_host))) {
            best = r;
            best_len = n;
        }
    }
    return best;
}

ncf_action_type ncf_effective_action_for(const ncf_config *cfg,
                                         const char *host, size_t host_len,
                                         const char *path, size_t path_len)
{
    if (cfg == NULL) {
        return NCF_ACTION_ENFORCE_NEURA_S2S;      /* 无配置 = fail-close */
    }
    const ncf_encrypt_route *r = ncf_route_for_request(cfg, host, host_len,
                                                       path, path_len);
    if (r != NULL) {
        return r->action;
    }
    return cfg->plaintext == NCF_PLAINTEXT_ALLOW ? NCF_ACTION_ALLOW_PLAIN
                                                 : NCF_ACTION_ENFORCE_NEURA_S2S;
}

ncf_action_type ncf_effective_action(const ncf_config *cfg,
                                     const char *path, size_t path_len)
{
    return ncf_effective_action_for(cfg, NULL, 0, path, path_len);
}

bool ncf_allows_unmatched_plaintext(const ncf_config *cfg)
{
    return cfg != NULL && cfg->plaintext == NCF_PLAINTEXT_ALLOW;
}

bool ncf_requires_encryption(const ncf_config *cfg,
                             const char *path, size_t path_len)
{
    return ncf_effective_action(cfg, path, path_len) ==
           NCF_ACTION_ENFORCE_NEURA_S2S;
}

const ncf_ban_rule *ncf_find_ban(const ncf_config *cfg, const char *name)
{
    if (cfg == NULL || name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < cfg->ban_count; i++) {
        if (cfg->bans[i].name != NULL && strcmp(cfg->bans[i].name, name) == 0) {
            return &cfg->bans[i];
        }
    }
    return NULL;
}

bool ncf_rewrite_apply(const ncf_config *cfg, const char *path, size_t path_len,
                       char *out, size_t cap,
                       const ncf_rewrite_rule **matched)
{
    if (cfg == NULL || path == NULL || out == NULL || cap == 0) {
        return false;
    }
    for (size_t i = 0; i < cfg->rw_count; i++) {
        const ncf_rewrite_rule *r = &cfg->rewrites[i];
        const char *name[SH_MAX_REWRITE_VARS];
        size_t name_len[SH_MAX_REWRITE_VARS];
        const char *val[SH_MAX_REWRITE_VARS];
        size_t val_len[SH_MAX_REWRITE_VARS];
        size_t nvars = 0;
        size_t pos = 0;
        bool ok = true;

        for (size_t k = 0; k < r->step_count && ok; k++) {
            const ncf_locate_step *st = &r->steps[k];
            if (st->kind == NCF_LOCATE_LITERAL) {
                size_t n = strlen(st->text);
                if (pos + n > path_len || memcmp(path + pos, st->text, n) != 0) {
                    ok = false;
                } else {
                    pos += n;
                }
            } else if (st->kind == NCF_LOCATE_UNTIL) {
                const char *hit = memmem(path + pos, path_len - pos,
                                         st->text, strlen(st->text));
                if (hit == NULL) {
                    ok = false;
                } else {
                    /* 记录被省略的区间，供后面的 VAR 使用 */
                    if (nvars < SH_MAX_REWRITE_VARS) {
                        val[nvars] = path + pos;
                        val_len[nvars] = (size_t)(hit - (path + pos));
                    }
                    pos = (size_t)(hit - path) + strlen(st->text);
                }
            } else if (st->kind == NCF_LOCATE_VAR) {
                if (nvars >= SH_MAX_REWRITE_VARS) {
                    ok = false;
                    break;
                }
                name[nvars] = st->text;
                name_len[nvars] = strlen(st->text);
                if (val_len[nvars] == 0 && nvars < SH_MAX_REWRITE_VARS) {
                    /* 没有 until 时捕获到路径末尾 */
                    val[nvars] = path + pos;
                    val_len[nvars] = path_len - pos;
                    pos = path_len;
                }
                nvars++;
            }
        }
        if (!ok || pos != path_len) {
            continue;
        }

        /* 展开模板：{$var} */
        size_t w = 0;
        const char *tpl = r->replace_template;
        for (size_t k = 0; tpl[k] != '\0'; k++) {
            if (tpl[k] == '{' && tpl[k + 1] == '$') {
                const char *brace = strchr(tpl + k + 2, '}');
                if (brace == NULL) {
                    ok = false;
                    break;
                }
                size_t vn = (size_t)(brace - (tpl + k + 2));
                bool found = false;
                for (size_t vi = 0; vi < nvars; vi++) {
                    if (name_len[vi] == vn &&
                        memcmp(name[vi], tpl + k + 2, vn) == 0) {
                        if (w + val_len[vi] >= cap) {
                            ok = false;
                            break;
                        }
                        memcpy(out + w, val[vi], val_len[vi]);
                        w += val_len[vi];
                        found = true;
                        break;
                    }
                }
                if (!ok) {
                    break;
                }
                if (!found) {
                    ok = false;
                    break;
                }
                k = (size_t)(brace - tpl);
            } else {
                if (w + 1u >= cap) {
                    ok = false;
                    break;
                }
                out[w++] = tpl[k];
            }
        }
        if (ok) {
            out[w] = '\0';
            if (matched != NULL) {
                *matched = r;
            }
            return true;
        }
    }
    return false;
}

void ncf_config_dump(const ncf_config *cfg, FILE *out)
{
    if (cfg == NULL || out == NULL) {
        return;
    }
    fprintf(out, "# 来源: %s (%u 行)\n", cfg->source_path != NULL ? cfg->source_path : "?",
            cfg->line_count);
    fprintf(out, "# 作用域: %s（用户规则隐式 priority=%u，系统预设隐式 priority=%u）\n",
            ncf_scope_name(cfg->scope), NCF_PRIORITY_USER, NCF_PRIORITY_SYSTEM);
    if (cfg->sandbox_root != NULL) {
        fprintf(out, "# 沙盒根(Include): %s\n", cfg->sandbox_root);
    }
    if (cfg->preset_count > 0) {
        fprintf(out, "# 已启用 Preset %zu 个:", cfg->preset_count);
        for (size_t i = 0; i < cfg->preset_count; i++) {
            fprintf(out, " %s", cfg->presets[i]);
        }
        fprintf(out, "\n");
    }
    if (cfg->include_count > 0) {
        fprintf(out, "# 已展开 Include %zu 个:\n", cfg->include_count);
        for (size_t i = 0; i < cfg->include_count; i++) {
            fprintf(out, "#   %s\n", cfg->include_paths[i]);
        }
    }
    if (cfg->ban_assert_count > 0) {
        fprintf(out, "# Defined Ban 断言 %zu 条（均已校验通过）\n",
                cfg->ban_assert_count);
    }
    fprintf(out, "# 全局策略: 未匹配路径默认 %s\n",
            cfg->plaintext == NCF_PLAINTEXT_ALLOW
                ? "allow（允许明文）"
                : "deny（强制 Neura-S2S，全站加密）");
    fprintf(out, "Policy {\n    Plaintext: %s;\n}\n\n",
            cfg->plaintext == NCF_PLAINTEXT_ALLOW ? "allow" : "deny");
    fprintf(out, "# Encrypt 规则 %zu 条\n", cfg->enc_count);
    for (size_t i = 0; i < cfg->enc_count; i++) {
        const ncf_encrypt_route *r = &cfg->enc_routes[i];
        if (r->has_host) {
            fprintf(out, "Encrypt \"%s\" { Host Match: %s \"%s\"; "
                         "Path Match: %s \"%s\"; Action: %s; "
                         "Priority: %u; Scope: %s; }\n",
                    r->name, ncf_match_op_name(r->host.op), r->host.value,
                    ncf_match_op_name(r->path.op), r->path.value,
                    ncf_action_name(r->action), r->priority,
                    ncf_scope_name(r->scope));
        } else {
            fprintf(out, "Encrypt \"%s\" { Path Match: %s \"%s\"; Action: %s; "
                         "Priority: %u; Scope: %s; }\n",
                    r->name, ncf_match_op_name(r->path.op), r->path.value,
                    ncf_action_name(r->action), r->priority,
                    ncf_scope_name(r->scope));
        }
    }
    fprintf(out, "# Rewrite 规则 %zu 条\n", cfg->rw_count);
    for (size_t i = 0; i < cfg->rw_count; i++) {
        const ncf_rewrite_rule *r = &cfg->rewrites[i];
        fprintf(out, "Rewrite \"%s\" { steps=%zu Replace: \"%s\"; "
                     "Priority: %u; Scope: %s; }\n",
                r->name, r->step_count, r->replace_template, r->priority,
                ncf_scope_name(r->scope));
    }
    fprintf(out, "# Ban 规则 %zu 条\n", cfg->ban_count);
    for (size_t i = 0; i < cfg->ban_count; i++) {
        const ncf_ban_rule *b = &cfg->bans[i];
        fprintf(out, "Ban \"%s\" { Checker=%d Trigger=%d Condition=%d "
                     "threshold=%u window=%ums matches=%zu Action: %s; "
                     "Priority: %u; Scope: %s; }\n",
                b->name, (int)b->checker, (int)b->trigger, (int)b->condition,
                b->threshold, b->window_ms, b->match_count,
                ncf_action_name(b->action), b->priority,
                ncf_scope_name(b->scope));
    }
}
