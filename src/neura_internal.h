// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Neura-S2S 内部共享定义（不对外安装）
 *
 * 只有 src/security.c 与 src/neura_conn.c 包含本文件。
 * 对外公开接口一律见 include/security.h。
 *
 * 内存布局要求：
 *   整个 sh_neura_conn（含 ns2s_session 与 ns2s_handshake）都必须位于
 *   ns2s_secure_alloc() 的 mlock + MADV_DONTDUMP 区域内，因为
 *   ns2s_session 里保存 root/send.key/recv.key/ratchet 私钥。
 *   因此 sh_neura_conn_new() 一次性安全分配 sizeof(conn)+sizeof(handshake)，
 *   hs 指针指向结构体尾部。
 */
#ifndef SAFE_HTTP_NEURA_INTERNAL_H
#define SAFE_HTTP_NEURA_INTERNAL_H

#include "security.h"

#include "neura/s2s_crypto.h"
#include "neura/s2s_secure_mem.h"

#define SH_NEURA_MAGIC 0x53484e43u /* "SHNC"：用于识别已初始化的上下文 */

struct sh_neura_conn {
    uint32_t          magic;
    ns2s_role         role;
    sh_neura_phase    phase;
    uint8_t           alg;
    uint8_t           alg_mask;
    uint32_t          max_frame;
    uint32_t          handshake_timeout_ms;

    ns2s_secure_region region;      /* 整个结构体 + handshake 都在此区域内 */
    ns2s_handshake    *hs;          /* 指向 region 尾部 */
    ns2s_session       session;     /* 建立后才有效（magic 哨兵保护） */

    ns2s_kem_job      *pending;     /* 待提交给 KEM pool（next 链） */
    uint32_t           pending_count;
    uint32_t           inflight;    /* 已提交未回收 */

    uint8_t            root_key[SH_ROOTKEY_BYTES];
    char               server_name[256];
    sh_doh_config      doh;
    bool               has_doh;
    bool               require_anchor;

    uint64_t           created_ms;
    uint64_t           established_ms;
    int                last_status;

    /* ---- 棘轮宽限期（SH_RATCHET_GRACE_MS）----
     * 棘轮每 300ms 切一代。切代瞬间对端可能已用新代发帧，而本端刚切成新代，
     * 在途帧的 header.ratchet_id 与 recv.ratchet_id 不一致 → 库内
     * ns2s_frame_validate() 返回 NS2S_ERR_REPLAY，安全但会误杀整条连接。
     * 这里保留上一代 (ratchet_id - 1) 的收方向链密钥，宽限期内允许双解一次。
     * 字段全部位于 secure region（mlock + MADV_DONTDUMP），不做堆外副本。 */
    ns2s_chain_key     prev_recv;          /* 上一代收链（ratchet_id/seq/key） */
    uint32_t           prev_ratchet_id;    /* 上一代的 ratchet_id */
    uint64_t           prev_valid_until_ms;/* 宽限期截止（单调毫秒） */
    bool               prev_valid;         /* 上一代密钥是否可用 */
    uint32_t           grace_hits;         /* 宽限期命中次数（观测用） */
};

/* 内部工具：单调毫秒（避免依赖尚未实现的 util.c） */
uint64_t sh_neura_mono_ms(void);

/*
 * 推进握手状态机（decode → step → 执行 action）。
 * 需要 KEM 时把任务挂到 n->pending，由调用方 take 出来提交。
 */
int sh_neura_hs_advance(struct sh_neura_conn *n, const uint8_t *msg, size_t len,
                        sh_buf *out);

/* 建立业务会话（ns2s_session_init + 擦除 handshake 里的密钥副本） */
int sh_neura_establish(struct sh_neura_conn *n, uint64_t now_ms);

/* 棘轮宽限期观测/判定（实现在 src/neura_conn.c） */
bool     sh_neura_grace_active(const struct sh_neura_conn *n, uint64_t now_ms);
uint32_t sh_neura_grace_hits(const struct sh_neura_conn *n);

#endif /* SAFE_HTTP_NEURA_INTERNAL_H */
