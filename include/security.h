// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Neura-S2S 加密层（libs2s 薄封装）
 *
 * 事实来源：/opt/neura/c-s2s（Phase 3 封板）
 *   - 头文件：neura/s2s.h、s2s_handshake.h、s2s_crypto.h、s2s_ring.h、
 *             s2s_secure_mem.h、s2s_reactor.h
 *   - 静态库：build-release/libs2s.a（发布）/ build/libs2s.a（ASan 调试）
 *   - 符号前缀：ns2s_；密码学全部来自 libsodium 1.0.22
 *
 * 本层只做三件事，绝不重复实现密码学或协议状态机：
 *   1. 生命周期与内存：把 ns2s_handshake / ns2s_session 放进
 *      ns2s_secure_alloc() 的 mlock + MADV_DONTDUMP 区域；
 *   2. 握手胶水：把"线上字节 → ns2s_hs_decode_* → ns2s_handshake_step
 *      → KEM job → apply → ns2s_session_init"串起来（方案 B：我们自己的
 *      ET epoll reactor 调它，不使用库自带的 reactor）；
 *   3. 信任锚：libs2s 的身份是预共享 32 字节 RootKey，库里没有
 *      DoH/DNSSEC；Safe-HTTP 用 RootKey 的域分离哈希作为"锚点指纹"，
 *      发布到 _neura-s2s.<host> 的 TXT，客户端经 DoH+DNSSEC 取回并比对。
 *
 * 安全约束（实现时必须遵守）：
 *   - 禁止在本层出现自研密码学原语；只用 ns2s_* / libsodium；
 *   - 密钥只允许 sodium_memzero / ns2s_secure_zero 清理，禁止 memset；
 *   - 帧长度必须先用 ns2s_frame_header_decode(..., max_frame) 校验，
 *     禁止用线上长度字段作为分配上限；
 *   - session 非线程安全：只在 reactor 线程访问。
 */
#ifndef SAFE_HTTP_SECURITY_H
#define SAFE_HTTP_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "network.h"

#include "neura/s2s.h"
#include "neura/s2s_handshake.h"

/* ==========================================================================
 * 1. 状态码与全局初始化
 * ========================================================================== */
/*
 * Safe-HTTP 自有状态码（不与 libs2s 的 ns2s_status 重叠，全部 < -100）。
 * 加密/协议错误一律直接返回 libs2s 的 NS2S_ERR_*，便于日志对照。

 */
#define SH_ERR_TRUST_ANCHOR   (-100)  /* 指纹与 DNS TXT 不一致 */
#define SH_ERR_DNS            (-101)  /* DoH 查询/解析失败 */
#define SH_ERR_TIMEOUT        (-102)  /* 握手/上游超时 */
#define SH_ERR_NO_KEM_JOB     (-103)  /* 无待提交的 KEM 任务 */
#define SH_ERR_POLICY         (-104)  /* 被 WAF/MatchLang 策略拒绝 */

/*
 * 调用 ns2s_init() + ns2s_crypto_init()，进程内幂等。
 * 必须在任何其他加密 API 之前调用。
 * 失败返回 ns2s_status（NS2S_ERR_CRYPTO 表示 libsodium 初始化失败）。
 */
int sh_neura_global_init(void);

/* 算法名："AES-256-GCM" / "ChaCha20-Poly1305" / "unknown" */
const char *sh_neura_alg_name(uint8_t alg);

/* 当前链接进来的库里 libsodium 版本（诊断用，指向静态字符串） */
const char *sh_neura_crypto_version(void);

/* ==========================================================================
 * 2. RootKey（信任锚的根）
 *
 * 32 字节预共享密钥，同时作为 HKDF salt 与握手 HMAC key。
 * 磁盘格式：64 个 hex 字符 + 可选换行，权限 0600。写入用临时文件 +
 * rename + fsync，避免安装脚本被打断后留下半截密钥。
 * ========================================================================== */
int sh_rootkey_generate(uint8_t out[SH_ROOTKEY_BYTES]);
int sh_rootkey_load(const char *path, uint8_t out[SH_ROOTKEY_BYTES],
                    char *err, size_t errcap);
int sh_rootkey_save(const char *path, const uint8_t key[SH_ROOTKEY_BYTES],
                    unsigned mode, char *err, size_t errcap);
/*
 * 读不到就生成并落盘；*created 指示是否新建。
 * 用于 install.sh 与服务首次启动。
 */
int sh_rootkey_load_or_create(const char *path, unsigned mode, bool *created,
                              uint8_t out[SH_ROOTKEY_BYTES],
                              char *err, size_t errcap);
int sh_rootkey_hex(const uint8_t key[SH_ROOTKEY_BYTES],
                   char out[SH_ROOTKEY_HEX_LEN]);
int sh_rootkey_from_hex(const char *hex, uint8_t out[SH_ROOTKEY_BYTES]);

/* ==========================================================================
 * 3. 信任锚（DNS TXT + DoH + DNSSEC）
 *
 * 指纹布局（与 install.sh 的 openssl 复算逐字节一致）：
 *   fp[32] = SHA-512(SH_ANCHOR_FP_DOMAIN || rootkey)[0..31]
 *   fp_hex = 64 个小写 hex 字符
 *
 * TXT 记录内容（_neura-s2s.<host>）：
 *   "v=ns2s1; fp=<64hex>"
 *
 * 部署模型：RootKey 带外下发（install.sh 打印 / 管理员复制给客户端），
 * DNS TXT 用于"验证手里这把 RootKey 确实属于该域名"，防止首次连接
 * 被中间人替换 RootKey。TXT 不是密钥分发通道。
 * ========================================================================== */
typedef enum sh_dnssec_mode {
    SH_DNSSEC_DISABLED   = 0,   /* 不校验（仅离线/内网调试） */
    SH_DNSSEC_AD_TRUSTED = 1,   /* 要求 DoH 响应 AD=1（验证型递归解析器背书） */
    SH_DNSSEC_LOCAL_CHAIN = 2   /* 本地校验 RRSIG/DNSKEY 链（后续增强） */
} sh_dnssec_mode;

typedef struct sh_doh_config {
    const char *url;            /* 默认 SH_DOH_DEFAULT_URL */
    uint32_t    timeout_ms;
    sh_dnssec_mode dnssec;
    const char *ca_bundle;      /* NULL 使用系统 CA */
} sh_doh_config;

typedef struct sh_anchor {
    char     host[256];
    char     fp_hex[SH_FINGERPRINT_HEX_LEN];
    uint8_t  fp[SH_ANCHOR_FP_BYTES];
    uint64_t fetched_ms;
    uint32_t ttl_s;
    bool     dnssec_valid;      /* AD=1 且（模式允许时）本地链校验通过 */
    bool     verified;          /* 已与本地 RootKey 比对成功 */
} sh_anchor;

int  sh_anchor_fingerprint(const uint8_t root_key[SH_ROOTKEY_BYTES],
                           uint8_t out[SH_ANCHOR_FP_BYTES]);
int  sh_anchor_fingerprint_hex(const uint8_t root_key[SH_ROOTKEY_BYTES],
                               char out[SH_FINGERPRINT_HEX_LEN]);
/* "example.com" -> "_neura-s2s.example.com" */
int  sh_anchor_txt_name(const char *host, char *out, size_t cap);
/* 生成 TXT 值："v=ns2s1; fp=<hex>" */
int  sh_anchor_format_txt(const uint8_t root_key[SH_ROOTKEY_BYTES],
                          char *out, size_t cap);
/* 解析 TXT 值；失败返回 NS2S_ERR_INVALID 并写 err */
int  sh_anchor_parse_txt(const char *txt, sh_anchor *out,
                         char *err, size_t errcap);
/* 比对 fingerprint 与本地 RootKey 派生值；成功置 out->verified */
int  sh_anchor_verify(const uint8_t root_key[SH_ROOTKEY_BYTES], sh_anchor *a);

#if SH_WITH_TRUST_ANCHOR
typedef struct sh_dns_answer {
    char     txt[SH_DNS_TXT_MAX_LEN];
    uint32_t ttl_s;
    bool     ad;                /* DNSSEC Authenticated Data 位 */
} sh_dns_answer;

/*
 * 通过 DoH（POST application/dns-message）查询 TXT 记录。
 * HTTPS 传输由本项目实现（OpenSSL），不依赖 libcurl。
 * 返回 ns2s_status；NS2S_ERR_STATE 表示该 dnssec 模式尚未实现。
 */
int sh_doh_query_txt(const sh_doh_config *cfg, const char *name,
                     sh_dns_answer *out, char *err, size_t errcap);

/* 取回并解析锚点；require_dnssec 为 true 时 AD=0 直接失败 */
int sh_anchor_fetch(const sh_doh_config *cfg, const char *host,
                    bool require_dnssec, sh_anchor *out,
                    char *err, size_t errcap);
#else
#  define sh_doh_query_txt(cfg, name, out, err, errcap)   (NS2S_ERR_STATE)
#  define sh_anchor_fetch(cfg, host, req, out, err, ec)   (NS2S_ERR_STATE)
#endif /* SH_WITH_TRUST_ANCHOR */

/* ==========================================================================
 * 4. 加密会话（每个连接一个 sh_neura_conn）
 *
 * 阶段流转：
 *   IDLE → HANDSHAKING → ESTABLISHED
 *                      ↘ FAILED
 * 握手期内存 = ns2s_secure_alloc(sizeof(ns2s_handshake))（mlock+DONTDUMP）；
 * 建立后 session 复用该 secure region，业务缓冲另行分配。
 * ========================================================================== */
typedef enum sh_neura_phase {
    SH_NEURA_IDLE = 0,
    SH_NEURA_HANDSHAKING,
    SH_NEURA_ESTABLISHED,
    SH_NEURA_FAILED
} sh_neura_phase;

typedef struct sh_neura_opts {
    ns2s_role      role;
    const uint8_t *root_key;                    /* 必填，32B */
    uint8_t        alg_mask;                    /* 默认 SH_ALG_MASK_DEFAULT */
    uint32_t       max_frame;                   /* 默认 SH_DEFAULT_MAX_FRAME */
    uint32_t       handshake_timeout_ms;        /* 默认 SH_HANDSHAKE_TIMEOUT_MS */
    const char    *server_name;                 /* 信任锚主机名，可为 NULL */
    bool           require_trust_anchor;        /* true 时握手成功前必须校验 TXT */
    const sh_doh_config *doh;                   /* require_trust_anchor 时必填 */
} sh_neura_opts;

typedef struct sh_neura_conn sh_neura_conn;

sh_neura_conn *sh_neura_conn_new(const sh_neura_opts *opts);
void           sh_neura_conn_free(sh_neura_conn *n);

sh_neura_phase sh_neura_phase_of(const sh_neura_conn *n);
bool           sh_neura_established(const sh_neura_conn *n);
uint8_t        sh_neura_alg(const sh_neura_conn *n);       /* 协商结果，未定返回 0 */
uint64_t       sh_neura_epoch(const sh_neura_conn *n);     /* 当前 ratchet_id */
int            sh_neura_last_status(const sh_neura_conn *n);

/* 客户端主动发起握手（服务端不需要调用）。now_ms 用单调时钟。 */
int sh_neura_handshake_start(sh_neura_conn *n, uint64_t now_ms);

/*
 * 喂入线上字节并推进握手，产生的待发送字节追加到 out。
 * consumed 返回实际消费的字节数（可能为 0：等更多数据）。
 * 返回 NS2S_OK / NS2S_ERR_AGAIN（需要更多字节）/ 其他错误（连接应关闭）。
 */
int sh_neura_handshake_pump(sh_neura_conn *n,
                            const uint8_t *in, size_t in_len, size_t *consumed,
                            sh_buf *out);

/*
 * 取出需要提交给 KEM worker pool 的任务（连接持有所有权，勿自行释放）。
 * 返回 true 表示有任务；提交用 ns2s_kem_pool_submit(pool, job)，
 * worker 完成后必须回到 reactor 线程调用 sh_neura_kem_done()。
 */
bool sh_neura_take_kem_job(sh_neura_conn *n, ns2s_kem_job **job_out);
/*
 * KEM 完成回调（在 reactor 线程调用）：写回结果、推进状态机，
 * 产出的字节追加到 out。job 由 reactor 传入，函数内不释放。
 */
int  sh_neura_kem_done(sh_neura_conn *n, const ns2s_kem_job *job,
                       uint64_t now_ms, sh_buf *out);

/* 会话建立后：加密一条应用消息追加到 out（out 需预留 15+12+16 头部开销） */
int sh_neura_seal(sh_neura_conn *n, const uint8_t *plain, size_t len, sh_buf *out);
/*
 * 从 in 里解析并解密一条完整帧，明文追加到 out，consumed 返回消耗字节数。
 * 返回 NS2S_ERR_AGAIN 表示帧不完整；其他错误表示应断开。
 */
int sh_neura_open(sh_neura_conn *n, const uint8_t *in, size_t in_len,
                  size_t *consumed, sh_buf *out);

/*
 * 0.3s KEM 重置由库内部定时（RATCHET_PERIOD_MS=300，服务端发起）。
 * 每次事件循环 tick 调用本函数；需要提交 KEM 时返回 true 并给出 job。
 */
bool sh_neura_ratchet_tick(sh_neura_conn *n, uint64_t now_ms, ns2s_kem_job **job_out);
/* 棘轮 KEM 完成后写回 */
int  sh_neura_ratchet_apply(sh_neura_conn *n, const ns2s_kem_job *job,
                            uint64_t now_ms, sh_buf *out);
/* 握手超时检查（库内 deadline 为 3s，这里按 opts 配置） */
int  sh_neura_check_deadline(sh_neura_conn *n, uint64_t now_ms);

/* ==========================================================================
 * 5. reactor 胶水层（供 src/neura_conn.c 实现，network.c 调用）
 *
 * sh_conn.neura 非空且 crypto != SH_CRYPTO_PLAIN 时，reactor 只把
 * 密文字节交给本层；握手完成前不解析任何 HTTP 语义。
 * ========================================================================== */
int  sh_crypto_start(sh_reactor *r, sh_conn *c, ns2s_role role);
int  sh_crypto_pump(sh_reactor *r, sh_conn *c);            /* 握手推进 */
ssize_t sh_crypto_read(sh_reactor *r, sh_conn *c, sh_buf *dst); /* 解密到 dst */
int  sh_crypto_write(sh_reactor *r, sh_conn *c,
                     const uint8_t *src, size_t len);      /* 加密到 c->out */
int  sh_crypto_tick(sh_reactor *r, sh_conn *c);            /* 棘轮/超时 */
void sh_crypto_close(sh_reactor *r, sh_conn *c);

#endif /* SAFE_HTTP_SECURITY_H */
