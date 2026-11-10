// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 编译期配置与全局常量
 *
 * 本文件是整个项目的"零号头文件"：所有模块共享的常量、编译期开关、
 * 通用工具宏以及运行时设置结构体都集中在此。
 *
 * 运行模式由编译器宏在编译期决定（见 REQUIREMENTS.md §2）：
 *   make MODE=STANDALONE  -> -DSAFE_HTTP_STANDALONE=1
 *   make MODE=PROXY       -> -DSAFE_HTTP_PROXY=1
 * 未选择模式或同时选择两种模式都会在编译期直接 error，确保零冗余、
 * 零攻击面（不参与当前模式的代码根本不会被编译进产物）。
 *
 * 加密层事实来源：/opt/neura/c-s2s（libs2s.a，符号前缀 ns2s_）。
 * 本文件只描述 Safe-HTTP 自身的策略常量，协议常量一律引用
 * neura/s2s.h，禁止在本文件重复定义线上格式。
 */
#ifndef SAFE_HTTP_CONFIG_H
#define SAFE_HTTP_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "neura/s2s.h"   /* 协议常量唯一来源：帧头/密钥/KEM 参数 */

/* ==========================================================================
 * 1. 版本信息
 * ========================================================================== */
#define SH_NAME            "Safe-HTTP"
#define SH_VERSION_MAJOR   1
#define SH_VERSION_MINOR   0
#define SH_VERSION_PATCH   0
#define SH_VERSION_STRING  "1.0.0"
#define SH_USER_AGENT      "Safe-HTTP/" SH_VERSION_STRING

/* ==========================================================================
 * 2. 通用编译期工具宏
 * ========================================================================== */

#if defined(__GNUC__) || defined(__clang__)
#  define SH_LIKELY(x)          __builtin_expect(!!(x), 1)
#  define SH_UNLIKELY(x)        __builtin_expect(!!(x), 0)
#  define SH_UNUSED             __attribute__((unused))
#  define SH_NORETURN           __attribute__((noreturn))
#  define SH_WARN_UNUSED        __attribute__((warn_unused_result))
#  define SH_PRINTF(fmt, args)  __attribute__((format(printf, fmt, args)))
#  define SH_PACKED             __attribute__((packed))
#  define SH_ALIGNED(n)         __attribute__((aligned(n)))
#  define SH_INLINE             static inline __attribute__((always_inline))
#else
#  define SH_LIKELY(x)          (x)
#  define SH_UNLIKELY(x)        (x)
#  define SH_UNUSED
#  define SH_NORETURN
#  define SH_WARN_UNUSED
#  define SH_PRINTF(fmt, args)
#  define SH_PACKED
#  define SH_ALIGNED(n)
#  define SH_INLINE             static inline
#endif

#define SH_ARRAY_LEN(a)         (sizeof(a) / sizeof((a)[0]))
#define SH_MIN(a, b)            ((a) < (b) ? (a) : (b))
#define SH_MAX(a, b)            ((a) > (b) ? (a) : (b))
#define SH_CLAMP(x, lo, hi)     (SH_MIN(SH_MAX((x), (lo)), (hi)))
#define SH_ALIGN_UP(x, a)       (((x) + ((size_t)(a) - 1u)) & ~((size_t)(a) - 1u))
#define SH_BIT(n)               (1u << (n))
#define SH_IS_POW2(n)           ((n) != 0u && (((n) & ((n) - 1u)) == 0u))
#define SH_STRINGIFY_(x)        #x
#define SH_STRINGIFY(x)         SH_STRINGIFY_(x)
#define SH_CONTAINER_OF(ptr, type, member) \
    ((type *)(void *)((char *)(ptr) - offsetof(type, member)))

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define SH_STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)
#else
#  define SH_STATIC_ASSERT(cond, msg) \
       typedef char sh_static_assert_##__LINE__[(cond) ? 1 : -1]
#endif

/* ==========================================================================
 * 3. 运行模式（条件编译的唯一开关）
 * ========================================================================== */
#if defined(SAFE_HTTP_STANDALONE) && defined(SAFE_HTTP_PROXY)
#  error "SAFE_HTTP_STANDALONE 与 SAFE_HTTP_PROXY 互斥，不能同时定义"
#endif

#if !defined(SAFE_HTTP_STANDALONE) && !defined(SAFE_HTTP_PROXY)
#  error "未选择运行模式：请使用 make MODE=STANDALONE 或 make MODE=PROXY"
#endif

#if defined(SAFE_HTTP_STANDALONE)
/* ---- Standalone：直接监听 80/443，替代 Nginx/Apache ---- */
#  define SH_MODE_STANDALONE    1
#  define SH_MODE_PROXY         0
#  define SH_MODE_NAME          "standalone"
#  define SH_MODE_UP_NAME       "STANDALONE"
#  define SH_MODE_ID            0
#  define SH_HAS_UPSTREAM       0   /* 无上游：内部处理静态文件与 API 路由 */
#  define SH_HAS_STATIC_FILE    1
#  define SH_DEFAULT_LISTEN_HOST "0.0.0.0"
#  define SH_DEFAULT_LISTEN_PORT 80
#  define SH_DEFAULT_TLS_PORT    443
#else
/* ---- Proxy：监听 127.0.0.1:5362，挂在 Nginx/Apache 之前 ---- */
#  define SH_MODE_STANDALONE    0
#  define SH_MODE_PROXY         1
#  define SH_MODE_NAME          "proxy"
#  define SH_MODE_UP_NAME       "PROXY"
#  define SH_MODE_ID            1
#  define SH_HAS_UPSTREAM       1
#  define SH_HAS_STATIC_FILE    0
#  define SH_DEFAULT_LISTEN_HOST "127.0.0.1"
#  define SH_DEFAULT_LISTEN_PORT 5362
#  define SH_DEFAULT_TLS_PORT    0   /* Proxy 模式不直接终止 TLS */
#endif

/* ==========================================================================
 * 4. 网络层容量与超时（epoll ET 场景下的默认值）
 * ========================================================================== */
#define SH_ACCEPT_BACKLOG               1024
#define SH_MAX_EVENTS                   1024
#define SH_MAX_CONNECTIONS              10000u   /* 单 worker 连接上限 */
#define SH_CONN_PREALLOC                256u
#define SH_READ_BUF_SIZE                (16u * 1024u)
#define SH_WRITE_BUF_SIZE               (64u * 1024u)
#define SH_UPSTREAM_BUF_SIZE            (16u * 1024u)
#define SH_MAX_HEAD_BYTES               (16u * 1024u)  /* 请求头硬上限，防御 slowloris */
#define SH_MAX_HEADER_COUNT             100u
#define SH_MAX_REQUESTS_PER_CONN        1000000u
#define SH_MAX_PIPELINE_REQUESTS        16u
#define SH_INET_ADDR_STRLEN             64
/*
 * 单次 EPOLLIN 边沿里最多 accept 多少条连接。
 *
 * ET 模式下必须一直 accept 到 EAGAIN；这里的数字只是"防饥饿预算"：
 * 达到预算后 reactor 会对 listen fd 做一次 EPOLL_CTL_MOD 重新 arm，
 * 内核会再次投递边沿，绝不会像旧实现那样在 64 条之后永久丢失连接。
 */
#define SH_EPOLL_BATCH_ACCEPT           512
#define SH_MAX_URI_LEN                  2048u
#define SH_MAX_TARGET_LEN               4096u
#define SH_SENDFILE_CHUNK               (256u * 1024u)
#define SH_MAX_FRAME_HEADROOM           (NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + NS2S_TAG_BYTES)

#define SH_IDLE_TIMEOUT_MS              60000u
#define SH_HANDSHAKE_TIMEOUT_MS         5000u
#define SH_UPSTREAM_CONNECT_TIMEOUT_MS  3000u
#define SH_UPSTREAM_IO_TIMEOUT_MS       30000u
#define SH_LINGER_MS                    5000u
#define SH_TIMER_TICK_MS                100u

/* Neura-S2S 棘轮由 libs2s 内部实现：RATCHET_PERIOD_MS = 300（服务端发起）。
 * 这里只保留观测/超时常量，禁止在 Safe-HTTP 侧重复实现棘轮逻辑。 */
#define SH_RATCHET_INTERVAL_MS          300u
#define SH_RATCHET_GRACE_MS             1000u

/* ==========================================================================
 * 5. Neura-S2S / 信任锚定常量
 * ========================================================================== */
#define SH_ROOTKEY_BYTES                32u
#define SH_ROOTKEY_HEX_LEN              65      /* 32B -> 64 hex + NUL */
#define SH_ANCHOR_FP_BYTES              32u     /* SHA-512(domain||rootkey) 截断 */
#define SH_FINGERPRINT_HEX_LEN          65
#define SH_DNS_TXT_PREFIX               "_neura-s2s."
#define SH_DNS_TXT_MAX_LEN              512u
#define SH_DOH_DEFAULT_URL              "https://cloudflare-dns.com/dns-query"
#define SH_DOH_TIMEOUT_MS               3000u
#define SH_TRUST_ANCHOR_TTL_S           86400u
#define SH_ANCHOR_TXT_VERSION           "ns2s1"

/*
 * 信任锚指纹的域分离前缀（不含 NUL）：
 *   fp[32] = SHA-512(SH_ANCHOR_FP_DOMAIN || rootkey)[0..31]
 * install.sh 用 openssl 走同一布局复算，必须与 src/security.c 逐字节一致。
 */
#define SH_ANCHOR_FP_DOMAIN             "safe-http/trust-anchor/v1:"
#define SH_ANCHOR_FP_DOMAIN_LEN         (sizeof(SH_ANCHOR_FP_DOMAIN) - 1u)

/* 加密帧与 KEM */
#define SH_DEFAULT_MAX_FRAME            (1u << 20)   /* 与 NS2S_DEFAULT_MAX_FRAME 一致 */
#define SH_PREAUTH_CAP                  (8u << 10)   /* 握手期每连接缓冲 */
#define SH_KEM_WORKERS                  2u
#define SH_ALG_MASK_DEFAULT             (NS2S_ALG_AES256GCM | NS2S_ALG_CHACHA20POLY1305)

/* ==========================================================================
 * 6. MatchLang / WAF 容量
 * ========================================================================== */
#define SH_MAX_ENCRYPT_ROUTES           128u
#define SH_MAX_REWRITE_RULES            128u
#define SH_MAX_BAN_RULES                64u
#define SH_MAX_MATCHES_PER_RULE         8u
#define SH_MAX_REWRITE_VARS             8u
#define SH_MAX_RULE_NAME                64u
#define SH_WAF_LRU_CAPACITY             16384u  /* LRU 哈希表容量 */
#define SH_WAF_BUCKET_MS                100u    /* 滑动窗口最小桶 */
#define SH_WAF_MAX_BUCKETS              64u     /* 单个窗口的桶数 */
#define SH_WAF_KEY_MAX                  128u
#define SH_WAF_MAX_BAN_MS               (24u * 3600u * 1000u)
#define SH_WAF_DEFAULT_BAN_MS           60000u

/* ==========================================================================
 * 7. 默认路径 / 身份
 * ========================================================================== */
#define SH_DEFAULT_CONFIG_PATH          "/etc/safe-http/config.ncf"
#define SH_FALLBACK_CONFIG_PATH         "config/config.ncf"
#define SH_DEFAULT_ROOTKEY_PATH         "/etc/safe-http/rootkey.hex"
#define SH_DEFAULT_PID_PATH             "/run/safe-http.pid"
#define SH_DEFAULT_LOG_PATH             "/var/log/safe-http.log"
#define SH_DEFAULT_TLS_CERT_PATH        "/etc/safe-http/cert.pem"
#define SH_DEFAULT_TLS_KEY_PATH         "/etc/safe-http/key.pem"
#define SH_DEFAULT_STATIC_ROOT          "/var/www/html"
#define SH_DEFAULT_INDEX_FILE           "index.html"
#define SH_DEFAULT_UPSTREAM_HOST        "127.0.0.1"
#define SH_DEFAULT_UPSTREAM_PORT        8080
#define SH_SERVICE_USER                 "neura"
#define SH_SERVICE_NAME                 "safe-http"
#define SH_NGINX_MARK_BEGIN             "# BEGIN NEURA S2S"
#define SH_NGINX_MARK_END               "# END NEURA S2S"

/* ==========================================================================
 * 8. 可选特性开关（-DSH_WITH_XXX=0 可编译期裁掉）
 * ========================================================================== */
#ifndef SH_WITH_WAF
#  define SH_WITH_WAF               1
#endif
#ifndef SH_WITH_TRUST_ANCHOR
#  define SH_WITH_TRUST_ANCHOR      1
#endif
#ifndef SH_WITH_ACCESS_LOG
#  define SH_WITH_ACCESS_LOG        1
#endif
#ifndef SH_WITH_TLS_TERMINATION
/* Standalone 模式可选终止常规 TLS；Proxy 模式由 Neura-S2S 接管 */
#  define SH_WITH_TLS_TERMINATION   SH_MODE_STANDALONE
#endif

/* ==========================================================================
 * 9. 运行时设置（CLI + 默认值，解析结果写入此结构）
 * ========================================================================== */
typedef struct sh_settings {
    /* 配置与身份 */
    const char *config_path;
    const char *root_key_path;        /* RootKey（信任锚）文件，64 hex */
    const char *anchor_host;          /* 发布 TXT 的域名，默认取监听主机名 */
    const char *doh_url;
    int         dnssec_mode;          /* sh_dnssec_mode */
    const char *pid_path;
    const char *log_path;
    const char *user;                 /* 低优先级服务用户（systemd 生成时使用） */
    /* 监听 */
    const char *listen_host;
    uint16_t    listen_port;
    const char *listen_tls_host;
    uint16_t    listen_tls_port;

    /* 上游（仅 Proxy 模式有效） */
    const char *upstream_host;
    uint16_t    upstream_port;

    /* TLS（仅 Standalone 模式有效） */
    const char *tls_cert_path;
    const char *tls_key_path;

    /* 静态站点（仅 Standalone 模式有效） */
    const char *static_root;
    const char *index_file;
    bool        static_listing;

    /* 容量与超时 */
    uint32_t    max_connections;
    uint32_t    read_buf_size;
    uint32_t    write_buf_size;
    uint32_t    idle_timeout_ms;
    uint32_t    handshake_timeout_ms;
    uint32_t    upstream_timeout_ms;
    uint32_t    ratchet_interval_ms;
    uint32_t    waf_lru_capacity;
    uint32_t    max_frame;
    uint32_t    kem_workers;

    /* 运行行为 */
    int         log_level;            /* sh_log_level，避免头文件循环依赖 */
    bool        trust_anchor_required;
    bool        daemonize;
    bool        foreground;
} sh_settings;

/*
 * 填充编译期默认值（按当前 MODE 选择端口/host 等）。
 * 不分配内存，所有 const char * 都指向静态字符串字面量。
 */
void sh_settings_defaults(sh_settings *s);

/* CLI 解析见 src/main.c（parse_cli），本文件只负责默认值与结构定义。 */

/* 编译期不变量校验：缓冲区布局与常量语义 */
SH_STATIC_ASSERT(SH_READ_BUF_SIZE >= SH_MAX_HEAD_BYTES, "读缓冲必须容纳完整请求头");
SH_STATIC_ASSERT(SH_IS_POW2(SH_READ_BUF_SIZE), "读缓冲应为 2 的幂");
SH_STATIC_ASSERT(SH_IS_POW2(SH_WRITE_BUF_SIZE), "写缓冲应为 2 的幂");
SH_STATIC_ASSERT(SH_MAX_EVENTS == 1024, "epoll 批次容量需与 SH_MAX_EVENTS 保持一致");
SH_STATIC_ASSERT(SH_WAF_MAX_BUCKETS * SH_WAF_BUCKET_MS <= SH_WAF_MAX_BAN_MS,
                 "滑动窗口总跨度不得超过最大封禁时长");
SH_STATIC_ASSERT(SH_HAS_UPSTREAM == SH_MODE_PROXY, "Upstream 仅 Proxy 模式存在");
SH_STATIC_ASSERT(SH_DEFAULT_MAX_FRAME >= SH_MAX_HEAD_BYTES, "帧容量必须容纳最大请求头");
SH_STATIC_ASSERT(SH_ROOTKEY_BYTES == NS2S_ROOT_KEY_BYTES, "RootKey 必须与 libs2s 一致");

#endif /* SAFE_HTTP_CONFIG_H */
