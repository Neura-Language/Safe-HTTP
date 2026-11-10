// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - MatchLang 配置解析器（config.ncf）
 *
 * 语法（见 REQUIREMENTS.md §3.1）：
 *
 *   Encrypt API Traffic {
 *       Path Match: starts_with "/api/";
 *       Action: enforce_neura_s2s;
 *   }
 *
 *   Rewrite URL Like {
 *       using engine matchlang;
 *       pattern: Locate "/user/" until "/" as $id {
 *           Replace with "/profile?id={$id}";
 *       }
 *   }
 *
 *   Ban "anti_cc" {
 *       Checker: IP;
 *       Trigger: Frequency;
 *       Condition: More Than 5 Per 1s;
 *       Action: drop_connection;
 *   }
 *
 * 设计要点：
 *   1. 纯手写词法+递归下降解析，禁止 PCRE（匹配算子全部为字面量比较）；
 *   2. 解析结果为一棵扁平的规则表（AST），运行期零分配、零解析；
 *   3. 所有字符串由解析器 strdup 持有，ncf_config_free 统一释放；
 *   4. 行号/列号错误信息通过 err 缓冲区返回，便于 install.sh 校验时报错。
 */
#ifndef SAFE_HTTP_CONFIG_PARSER_H
#define SAFE_HTTP_CONFIG_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"

/* ==========================================================================
 * 1. 词法
 * ========================================================================== */
typedef enum ncf_token_type {
    NCF_TOK_EOF = 0,
    NCF_TOK_IDENT,      /* Encrypt / Ban / starts_with ... */
    NCF_TOK_STRING,     /* "..." 或 '...'（支持 \" 转义） */
    NCF_TOK_NUMBER,     /* 123 */
    NCF_TOK_VAR,        /* $id */
    NCF_TOK_PLACEHOLDER,/* {$id} 仅出现在字符串里，词法层不单独产生 */
    NCF_TOK_LBRACE,
    NCF_TOK_RBRACE,
    NCF_TOK_COLON,
    NCF_TOK_SEMI,
    NCF_TOK_COMMA,
    NCF_TOK_EQUALS,
    NCF_TOK_SLASH,
    NCF_TOK_ERROR
} ncf_token_type;

typedef struct ncf_token {
    ncf_token_type type;
    const char    *start;      /* 指向源缓冲，不拥有内存 */
    size_t         len;
    uint32_t       line;
    uint32_t       col;
    int64_t        num;
} ncf_token;

typedef struct ncf_lexer {
    const char *src;
    size_t      len;
    size_t      pos;
    uint32_t    line;
    uint32_t    col;
    bool        failed;
    char        err[192];
} ncf_lexer;

void ncf_lexer_init(ncf_lexer *lx, const char *src, size_t len);
bool ncf_lexer_next(ncf_lexer *lx, ncf_token *tok);
/* 仅用于错误提示：token 类型名 */
const char *ncf_token_type_name(ncf_token_type type);

/* ==========================================================================
 * 2. 匹配算子（无正则）
 * ========================================================================== */
/* ==========================================================================
 * 2.5 作用域与优先级（沙盒隔离）
 *
 *   SYSTEM —— 系统预设（Enable Preset 加载的 .ncf）：隐式优先级 10000，
 *             允许使用 drop_connection（"系统预设隐式优先级10000允许drop"）。
 *   USER   —— 用户配置（config.ncf 及其 Include）：隐式优先级 100，
 *             禁止使用 drop_connection（"用户规则隐式优先级100禁止drop"），
 *             违规在解析期直接报错，绝不静默降级。
 *
 * 优先级数值越大越先匹配：先比 priority，再比路径长度，最后比 Host 约束具体度。
 * ========================================================================== */
typedef enum ncf_scope {
    NCF_SCOPE_USER = 0,
    NCF_SCOPE_SYSTEM = 1
} ncf_scope;

#define NCF_PRIORITY_SYSTEM 10000u
#define NCF_PRIORITY_USER     100u
/* 预设/包含的最大嵌套深度（防环 + 防栈溢出） */
#define NCF_MAX_INCLUDE_DEPTH 8u
/* 单份配置最多启用多少个 Preset / 展开多少个 Include */
#define NCF_MAX_PRESETS       32u
#define NCF_MAX_INCLUDES      32u

const char *ncf_scope_name(ncf_scope s);

typedef enum ncf_match_op {
    NCF_MATCH_STARTS_WITH = 0,
    NCF_MATCH_ENDS_WITH,
    NCF_MATCH_CONTAINS,
    NCF_MATCH_EQUALS,
    NCF_MATCH_IN          /* 逗号分隔的多值等值匹配 */
} ncf_match_op;

const char *ncf_match_op_name(ncf_match_op op);

typedef struct ncf_match {
    ncf_match_op op;
    char        *value;      /* 已 strdup；IN 时为逗号分隔原文 */
} ncf_match;

/* ==========================================================================
 * 3. Encrypt 路由规则
 * ========================================================================== */
typedef enum ncf_action_type {
    NCF_ACTION_NONE = 0,
    NCF_ACTION_ENFORCE_NEURA_S2S,   /* 强制加密（默认要求握手） */
    NCF_ACTION_ALLOW_PLAIN,         /* 显式放行明文 */
    NCF_ACTION_DROP_CONNECTION,
    NCF_ACTION_LOG_ONLY,
    NCF_ACTION_RESPOND_403
} ncf_action_type;

const char *ncf_action_name(ncf_action_type a);

typedef struct ncf_encrypt_route {
    char         *name;              /* "API Traffic" */
    ncf_match     path;              /* Path Match: starts_with "/api/"; */
    /*
     * 可选：Host Match（按请求头 Host 限定规则）。
     * 共享 IP/端口的边缘代理必须靠它把「本站强制加密」与「其它站点放行」
     * 区分开：未写 Host Match 的规则对所有 Host 生效。
     */
    ncf_match     host;
    bool          has_host;
    ncf_action_type action;
    uint32_t      priority;          /* 隐式：SYSTEM=10000 / USER=100 */
    ncf_scope     scope;             /* 该规则来自系统预设还是用户配置 */
    bool          enabled;
    uint32_t      line;
} ncf_encrypt_route;

/* ==========================================================================
 * 4. Rewrite 规则（Locate ... until ... as $var { Replace with "..." }）
 * ========================================================================== */
typedef enum ncf_locate_kind {
    NCF_LOCATE_LITERAL = 0,   /* Locate "/user/" */
    NCF_LOCATE_UNTIL,         /* until "/"   —— 捕获到下一个分隔符 */
    NCF_LOCATE_VAR            /* as $id */
} ncf_locate_kind;

typedef struct ncf_locate_step {
    ncf_locate_kind kind;
    char           *text;     /* 字面量或分隔符；VAR 时为变量名（不含 $）*/
    bool            optional; /* { } 后缀表示可选段 */
} ncf_locate_step;

typedef struct ncf_rewrite_rule {
    char            *name;
    bool             engine_matchlang;    /* using engine matchlang */
    ncf_locate_step *steps;
    size_t           step_count;
    char            *replace_template;    /* "/profile?id={$id}" */
    uint32_t         priority;
    ncf_scope        scope;
    uint32_t         line;
} ncf_rewrite_rule;

/* ==========================================================================
 * 5. Ban 规则（WAF / 防 CC）
 * ========================================================================== */
typedef enum ncf_checker_type {
    NCF_CHECKER_IP = 0,
    NCF_CHECKER_USER_AGENT,
    NCF_CHECKER_PATH,
    NCF_CHECKER_METHOD,
    NCF_CHECKER_HEADER,
    NCF_CHECKER_COOKIE,
    NCF_CHECKER_QUERY
} ncf_checker_type;

typedef enum ncf_trigger_type {
    NCF_TRIGGER_FREQUENCY = 0,  /* Trigger: Frequency; */
    NCF_TRIGGER_VISIT           /* Trigger: Visit; */
} ncf_trigger_type;

typedef enum ncf_condition_kind {
    NCF_COND_IMMEDIATELY = 0,   /* Condition: Immediately; */
    NCF_COND_MORE_THAN          /* Condition: More Than 5 Per 1s; */
} ncf_condition_kind;

typedef struct ncf_ban_rule {
    char           *name;            /* "anti_cc" */
    ncf_checker_type checker;
    char           *header_name;     /* checker == HEADER/COOKIE 时的名字 */
    ncf_match      *matches;         /* contains "a" or contains "b" */
    size_t          match_count;
    bool            match_any;       /* or -> true；and -> false */
    ncf_trigger_type trigger;
    ncf_condition_kind condition;
    uint32_t        threshold;       /* More Than N */
    uint32_t        window_ms;       /* Per 1s -> 1000 */
    ncf_action_type action;
    uint32_t        ban_ms;          /* 命中后封禁时长，默认 SH_WAF_DEFAULT_BAN_MS */
    uint32_t        priority;        /* 隐式：SYSTEM=10000 / USER=100 */
    ncf_scope       scope;
    uint32_t        line;
} ncf_ban_rule;

/*
 * `Defined Ban "名字";` 断言：
 * 该名字必须存在对应的 Ban 块，否则解析失败（"Ban defined 未定义则报错"）。
 * 断言允许前向引用，因此在顶层解析完成后统一校验。
 */
typedef struct ncf_ban_assert {
    char    *name;
    char    *origin;      /* 出现该断言的文件 */
    uint32_t line;
} ncf_ban_assert;

/* ==========================================================================
 * 6. 配置根
 * ========================================================================== */

/*
 * 未匹配任何 Encrypt 规则时的默认策略。
 *
 *   deny  —— 全站加密（推荐）：未显式 allow_plain 的路径一律要求 Neura-S2S，
 *            明文请求直接 403。这是 fail-close 默认值（枚举 0 = DENY）。
 *   allow —— 兼容旧行为：未匹配路径允许明文直通。
 *
 * 配置写法：
 *   Policy {
 *       Plaintext: deny;
 *   }
 */
typedef enum ncf_plaintext_policy {
    NCF_PLAINTEXT_DENY = 0,
    NCF_PLAINTEXT_ALLOW
} ncf_plaintext_policy;

typedef struct ncf_config {
    char             *source_path;   /* 文件路径或 "<memory>" */
    ncf_plaintext_policy plaintext;  /* 未匹配路径的默认策略（默认 DENY） */
    ncf_scope         scope;         /* 顶层作用域（用户配置恒为 USER） */
    char             *sandbox_root;  /* Include 沙盒根（顶层配置文件目录的 realpath） */
    char            **include_paths; /* 已展开的 Include 文件（realpath） */
    size_t            include_count;
    char            **presets;       /* 已启用的 Preset 名 */
    size_t            preset_count;
    ncf_ban_assert   *ban_asserts;   /* `Defined Ban` 断言 */
    size_t            ban_assert_count;
    ncf_encrypt_route *enc_routes;
    size_t             enc_count;
    size_t             enc_cap;
    ncf_rewrite_rule  *rewrites;
    size_t             rw_count;
    size_t             rw_cap;
    ncf_ban_rule      *bans;
    size_t             ban_count;
    size_t             ban_cap;
    uint32_t           line_count;
} ncf_config;

ncf_config *ncf_config_new(void);
void        ncf_config_free(ncf_config *cfg);

/*
 * 预设目录（Enable Preset "name" → <dir>/name.ncf，以 SYSTEM 作用域加载）。
 * 默认 SH_DEFAULT_PRESET_DIR；进程启动时可覆盖（便于测试）。
 */
void ncf_set_preset_dir(const char *dir);
const char *ncf_get_preset_dir(void);

/*
 * 解析入口：成功返回配置对象；失败返回 NULL 并把
 * "config.ncf:12:5: 期望 ';'，实际 '}'" 之类的信息写入 err。
 *
 * 解析期会：
 *   1. 处理 `Enable Preset "x";`（SYSTEM 作用域，priority=10000，允许 drop）
 *   2. 处理 `Include MatchLang "p";`（同作用域，限制在沙盒根内，防环）
 *   3. 处理 `Defined Ban "x";`（解析完成后统一校验，未定义即报错）
 *   4. 校验 USER 作用域禁用 drop_connection
 *   5. 按 priority 降序稳定排序规则
 */
ncf_config *ncf_parse_file(const char *path, char *err, size_t errcap);
ncf_config *ncf_parse_string(const char *src, size_t len,
                             const char *origin, char *err, size_t errcap);

/* 只做语法检查（install.sh / --check-config 使用）：返回 0 表示合法 */
int ncf_validate(const char *src, size_t len, const char *origin,
                 char *err, size_t errcap);

/* ==========================================================================
 * 7. 运行期查询
 * ========================================================================== */
/*
 * 最长前缀匹配：返回第一条命中的 Encrypt 规则，未命中返回 NULL
 * （不考虑 Host 维度，仅按 Path）。
 */
const ncf_encrypt_route *ncf_route_for_path(const ncf_config *cfg,
                                            const char *path, size_t path_len);
/*
 * 带 Host 维度的匹配：带 `Host Match:` 的规则仅在 Host 命中时参与；
 * 路径最长者优先，长度相同则「带 Host 约束」的规则优先（更具体）。
 * host 为 NULL 时等价于 ncf_route_for_path()。
 */
const ncf_encrypt_route *ncf_route_for_request(const ncf_config *cfg,
                                               const char *host, size_t host_len,
                                               const char *path, size_t path_len);
/*
 * 该请求「最终生效」的动作：命中规则取其 action；未命中则回落到
 * ncf_config.plaintext（默认 DENY → 视为 enforce_neura_s2s）。
 */
ncf_action_type ncf_effective_action_for(const ncf_config *cfg,
                                         const char *host, size_t host_len,
                                         const char *path, size_t path_len);
ncf_action_type ncf_effective_action(const ncf_config *cfg,
                                     const char *path, size_t path_len);
/*
 * 该路径「最终生效」的动作：命中 Encrypt 规则取其 action；
 * 未命中则回落到 ncf_config.plaintext（默认 DENY → 视为 enforce_neura_s2s）。
 * 调用方（Proxy）应以此为准做策略判定，不要只看 ncf_route_for_path 是否为 NULL。
 */
ncf_action_type ncf_effective_action(const ncf_config *cfg,
                                     const char *path, size_t path_len);
/* 是否需要强制 Neura-S2S（包含未匹配路径的默认策略） */
bool ncf_requires_encryption(const ncf_config *cfg,
                             const char *path, size_t path_len);
/* 未匹配路径是否允许明文（= plaintext == ALLOW） */
bool ncf_allows_unmatched_plaintext(const ncf_config *cfg);

/*
 * 应用第一条匹配的 Rewrite 规则。
 * 成功改写返回 true，结果写入 out（NUL 结尾）；未匹配返回 false。
 */
bool ncf_rewrite_apply(const ncf_config *cfg, const char *path, size_t path_len,
                       char *out, size_t cap,
                       const ncf_rewrite_rule **matched);

/* 按名字查找 Ban 规则 */
const ncf_ban_rule *ncf_find_ban(const ncf_config *cfg, const char *name);

/* 调试输出（--dump-config） */
void ncf_config_dump(const ncf_config *cfg, FILE *out);

#endif /* SAFE_HTTP_CONFIG_PARSER_H */
