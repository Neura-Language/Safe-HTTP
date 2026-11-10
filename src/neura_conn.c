// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - Neura-S2S 握手/会话胶水层
 *
 * 这是"自建 ET epoll reactor"与"libs2s 密码学状态机"之间的唯一桥梁。
 * 流程严格照 libs2s Phase 3 的接线方式（见 c-s2s/src/s2s_reactor.c）：
 *
 *   hello/ack/finish/ready  → ns2s_hs_decode_*() → ns2s_handshake_step()
 *       START_KEM_*  → 生成 ns2s_kem_job 挂到 n->pending，交给 KEM pool
 *       SEND_*       → ns2s_hs_encode_*()              → c->out
 *       FAIL_CLOSE   → 关闭连接
 *   会话建立      → ns2s_session_init()（服务端 auto_ratchet=1）
 *   KEM 完成      → 握手阶段：apply → verify_finish → step(KEM_DONE)
 *                 棘轮阶段：ns2s_session_apply_ratchet_job()
 *   0.3s 棘轮     → ns2s_session_ratchet_tick()（库内 RATCHET_PERIOD_MS=300）
 *
 * 关键约束：
 *   - 所有密钥只在 reactor 线程访问（session 非线程安全）；
 *   - X-Wing 运算一律走 KEM worker pool，绝不在 epoll 线程内执行；
 *   - 帧长度先用 ns2s_frame_header_decode(..., max_frame) 校验再解密；
 *   - 密钥清理只用 sodium_memzero / ns2s_secure_zero。
 */
#include "neura_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "network.h"

/* 握手报文头部：magic4 + ver + type + dir（与库内 NS2S_HS_HEAD_PEEK 一致） */
#define SH_HS_HEAD_PEEK 7u
/* 单条握手报文最大长度（ack = 32+1216+1120+64 = 2432） */
#define SH_HS_MAX_MSG   (NS2S_HS_COMMON_BYTES + NS2S_XWING_PK_BYTES + \
                         NS2S_XWING_CT_BYTES + NS2S_HMAC_BYTES)
/* 单条加密帧的固定开销 */
#define SH_FRAME_OVERHEAD (NS2S_FRAME_HEADER_BYTES + NS2S_NONCE_BYTES + NS2S_TAG_BYTES)

/* ==========================================================================
 * 基础工具
 * ========================================================================== */
uint64_t sh_neura_mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static bool conn_alive(const sh_neura_conn *n)
{
    return n != NULL && n->magic == SH_NEURA_MAGIC && n->hs != NULL;
}

/* 把待提交的 KEM 任务挂到队列尾（保持顺序） */
static int pending_push(sh_neura_conn *n, ns2s_kem_job *job)
{
    job->next = NULL;
    if (n->pending == NULL) {
        n->pending = job;
    } else {
        ns2s_kem_job *t = n->pending;
        while (t->next != NULL) {
            t = t->next;
        }
        t->next = job;
    }
    n->pending_count++;
    return NS2S_OK;
}

static int queue_hs_msg(sh_buf *out, const uint8_t *msg, size_t len)
{
    if (out == NULL) {
        return NS2S_OK;
    }
    if (sh_buf_append(out, msg, len) != len) {
        return NS2S_ERR_NOMEM;
    }
    return NS2S_OK;
}

/* ==========================================================================
 * 状态机动作执行
 * ========================================================================== */
static int submit_handshake_kem(sh_neura_conn *n, ns2s_kem_phase phase)
{
    ns2s_kem_job *job = (ns2s_kem_job *)calloc(1, sizeof(*job));
    if (job == NULL) {
        return NS2S_ERR_NOMEM;
    }
    int rc = ns2s_kem_job_from_handshake(job, n->hs, phase);
    if (rc != NS2S_OK) {
        ns2s_kem_job_destroy(job);
        free(job);
        return rc;
    }
    return pending_push(n, job);
}

typedef int (*sh_hs_encode_fn)(ns2s_handshake *, uint8_t *, size_t, size_t *);

static int send_hs_msg(sh_neura_conn *n, sh_hs_encode_fn enc, sh_buf *out)
{
    uint8_t buf[SH_HS_MAX_MSG];
    size_t len = 0;
    int rc = enc(n->hs, buf, sizeof buf, &len);
    if (rc == NS2S_OK) {
        rc = queue_hs_msg(out, buf, len);
    }
    sodium_memzero(buf, sizeof buf);
    return rc;
}

static int apply_hs_action(sh_neura_conn *n, ns2s_hs_action act, sh_buf *out)
{
    switch (act) {
    case NS2S_HS_ACT_NONE:
    case NS2S_HS_ACT_ESTABLISHED:
        return NS2S_OK;
    case NS2S_HS_ACT_START_KEM_CLIENT_HELLO:
        return submit_handshake_kem(n, NS2S_KEM_PHASE_CLIENT_HELLO);
    case NS2S_HS_ACT_START_KEM_SERVER_ACK:
        return submit_handshake_kem(n, NS2S_KEM_PHASE_SERVER_ACK);
    case NS2S_HS_ACT_START_KEM_CLIENT_FINISH:
        return submit_handshake_kem(n, NS2S_KEM_PHASE_CLIENT_FINISH);
    case NS2S_HS_ACT_START_KEM_SERVER_FINISH:
        return submit_handshake_kem(n, NS2S_KEM_PHASE_SERVER_FINISH);
    case NS2S_HS_ACT_SEND_HELLO:
        return send_hs_msg(n, ns2s_hs_encode_hello, out);
    case NS2S_HS_ACT_SEND_ACK:
        return send_hs_msg(n, ns2s_hs_encode_ack, out);
    case NS2S_HS_ACT_SEND_FINISH:
        return send_hs_msg(n, ns2s_hs_encode_finish, out);
    case NS2S_HS_ACT_SEND_READY: {
        int rc = send_hs_msg(n, ns2s_hs_encode_ready, out);
        if (rc != NS2S_OK) {
            return rc;
        }
        /* ready 已入队 = 服务端密钥确认已发出，才允许进入 ESTABLISHED */
        (void)ns2s_handshake_step(n->hs, NS2S_HS_EV_READY_SENT, 0);
        return NS2S_OK;
    }
    case NS2S_HS_ACT_FAIL_CLOSE:
    default:
        return NS2S_ERR_AUTH;
    }
}

/* ==========================================================================
 * 会话建立
 * ========================================================================== */
int sh_neura_establish(sh_neura_conn *n, uint64_t now_ms)
{
    if (!conn_alive(n) || n->hs->state != NS2S_HS_ESTABLISHED) {
        return NS2S_ERR_STATE;
    }
    int rc = ns2s_session_init(&n->session, n->role, n->hs->alg, n->max_frame,
                              n->hs->rk0, n->hs->c2s_key, n->hs->s2c_key,
                              now_ms);
    if (rc != NS2S_OK) {
        n->last_status = rc;
        return rc;
    }
    /* 与 Go 版一致：0.3s KEM 重置由服务端发起 */
    n->session.auto_ratchet = (n->role == NS2S_ROLE_SERVER) ? 1 : 0;
    n->alg = n->hs->alg;
    n->phase = SH_NEURA_ESTABLISHED;
    n->established_ms = now_ms;

    /* 握手密钥已进入 session，擦掉 handshake 内的副本 */
    sodium_memzero(n->hs->root_key, sizeof n->hs->root_key);
    sodium_memzero(n->hs->rk0, sizeof n->hs->rk0);
    sodium_memzero(n->hs->c2s_key, sizeof n->hs->c2s_key);
    sodium_memzero(n->hs->s2c_key, sizeof n->hs->s2c_key);
    sodium_memzero(n->hs->client_sk, sizeof n->hs->client_sk);
    sodium_memzero(n->hs->server_sk, sizeof n->hs->server_sk);
    sodium_memzero(n->hs->ss_client, sizeof n->hs->ss_client);
    sodium_memzero(n->hs->ss_server, sizeof n->hs->ss_server);
    return NS2S_OK;
}

/* 状态机推进后统一收尾：失败/建立/继续 */
static int hs_after_step(sh_neura_conn *n, uint64_t now_ms, sh_buf *out)
{
    if (n->hs->state == NS2S_HS_FAILED) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = NS2S_ERR_AUTH;
        return NS2S_ERR_AUTH;
    }
    if (n->hs->state == NS2S_HS_ESTABLISHED && n->phase != SH_NEURA_ESTABLISHED) {
        int rc = sh_neura_establish(n, now_ms);
        if (rc != NS2S_OK) {
            return rc;
        }
        SH_LOGI("neura: 握手完成 role=%s alg=%s", n->role == NS2S_ROLE_SERVER ? "server" : "client",
                sh_neura_alg_name(n->alg));
    }
    (void)out;
    return NS2S_OK;
}

/* ==========================================================================
 * 握手
 * ========================================================================== */
int sh_neura_handshake_start(sh_neura_conn *n, uint64_t now_ms)
{
    if (!conn_alive(n) || n->role != NS2S_ROLE_CLIENT) {
        return NS2S_ERR_STATE;
    }
    /*
     * 关键：用真实 now_ms 初始化。库内 deadline = now_ms + 3s，
     * 用 0 初始化会让 ns2s_hs_check_deadline() 立刻判定超时。
     */
    ns2s_handshake_init(n->hs, n->role, n->root_key, n->alg_mask, now_ms);
    n->created_ms = now_ms;
    n->phase = SH_NEURA_HANDSHAKING;

    ns2s_hs_action act = ns2s_handshake_step(n->hs, NS2S_HS_EV_START, 0);
    int rc = apply_hs_action(n, act, NULL);
    if (rc != NS2S_OK) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = rc;
        return rc;
    }
    return hs_after_step(n, now_ms, NULL);
}

/*
 * 按 NS2H 定长报文增量解析。
 * 返回：NS2S_OK（已消费若干字节）/ NS2S_ERR_AGAIN（数据不足）/ 其他错误。
 */
int sh_neura_handshake_pump(sh_neura_conn *n,
                            const uint8_t *in, size_t in_len, size_t *consumed,
                            sh_buf *out)
{
    if (consumed != NULL) {
        *consumed = 0;
    }
    if (!conn_alive(n) || in == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (n->phase == SH_NEURA_ESTABLISHED) {
        return NS2S_OK;    /* 已建立：后续字节属于业务帧 */
    }
    if (n->phase == SH_NEURA_FAILED) {
        return NS2S_ERR_STATE;
    }

    size_t off = 0;
    int rc = NS2S_OK;
    while (in_len - off >= SH_HS_HEAD_PEEK) {
        const uint8_t *p = in + off;
        if (p[0] != 'N' || p[1] != 'S' || p[2] != '2' || p[3] != 'H') {
            rc = NS2S_ERR_INVALID;    /* 未握手就发非握手数据：fail-close */
            break;
        }
        size_t need = ns2s_hs_msg_len(p[5]);
        if (need == 0 || need > SH_HS_MAX_MSG) {
            rc = NS2S_ERR_INVALID;
            break;
        }
        if (in_len - off < need) {
            break;    /* 等更多字节，不分配内存 */
        }
        rc = sh_neura_hs_advance(n, p, need, out);
        if (rc != NS2S_OK) {
            break;
        }
        off += need;
        if (n->phase == SH_NEURA_ESTABLISHED) {
            break;    /* 剩余字节是业务帧，交回调用方 */
        }
    }

    if (consumed != NULL) {
        *consumed = off;
    }
    if (rc != NS2S_OK) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = rc;
        return rc;
    }
    return (off == 0 && n->pending == NULL) ? NS2S_ERR_AGAIN : NS2S_OK;
}

/* 解码一条完整握手报文并推进状态机 */
int sh_neura_hs_advance(sh_neura_conn *n, const uint8_t *msg, size_t len,
                        sh_buf *out)
{
    if (!conn_alive(n) || msg == NULL || len < NS2S_HS_COMMON_BYTES) {
        return NS2S_ERR_INVALID;
    }
    uint8_t type = msg[5];
    ns2s_hs_event ev;
    int rc;

    if (n->role == NS2S_ROLE_SERVER) {
        if (type == NS2S_HS_TYPE_HELLO) {
            ev = NS2S_HS_EV_HELLO_RX;
            rc = ns2s_hs_decode_hello(n->hs, msg, len);
        } else if (type == NS2S_HS_TYPE_FINISH) {
            ev = NS2S_HS_EV_FINISH_RX;
            rc = ns2s_hs_decode_finish(n->hs, msg, len);
        } else {
            return NS2S_ERR_STATE;    /* 服务端不接受 ack/ready */
        }
    } else {
        if (type == NS2S_HS_TYPE_ACK) {
            ev = NS2S_HS_EV_ACK_RX;
            rc = ns2s_hs_decode_ack(n->hs, msg, len);
        } else if (type == NS2S_HS_TYPE_READY) {
            ev = NS2S_HS_EV_READY_RX;
            rc = ns2s_hs_decode_ready(n->hs, msg, len);
        } else {
            return NS2S_ERR_STATE;
        }
    }
    if (rc != NS2S_OK) {
        return rc;
    }

    ns2s_hs_action act = ns2s_handshake_step(n->hs, ev, 0);
    rc = apply_hs_action(n, act, out);
    if (rc != NS2S_OK) {
        return rc;
    }
    return hs_after_step(n, sh_neura_mono_ms(), out);
}

bool sh_neura_take_kem_job(sh_neura_conn *n, ns2s_kem_job **job_out)
{
    if (job_out != NULL) {
        *job_out = NULL;
    }
    if (!conn_alive(n) || n->pending == NULL) {
        return false;
    }
    ns2s_kem_job *job = n->pending;
    n->pending = job->next;
    job->next = NULL;
    if (n->pending_count > 0) {
        n->pending_count--;
    }
    n->inflight++;
    if (job_out != NULL) {
        *job_out = job;
    }
    return true;
}

int sh_neura_kem_done(sh_neura_conn *n, const ns2s_kem_job *job,
                      uint64_t now_ms, sh_buf *out)
{
    if (!conn_alive(n) || job == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (n->inflight > 0) {
        n->inflight--;
    }
    if (job->status != NS2S_OK) {
        (void)ns2s_handshake_step(n->hs, NS2S_HS_EV_KEM_DONE, job->status);
        n->phase = SH_NEURA_FAILED;
        n->last_status = job->status;
        return NS2S_ERR_AUTH;
    }
    int rc = ns2s_hs_apply_kem_job(n->hs, job);
    if (rc != NS2S_OK) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = rc;
        return rc;
    }
    if (job->phase == NS2S_KEM_PHASE_SERVER_FINISH) {
        /* 服务端必须在进入 READY 之前校验 finish 的 HMAC（漏调即 fail-close） */
        rc = ns2s_hs_verify_finish(n->hs);
        if (rc != NS2S_OK) {
            n->phase = SH_NEURA_FAILED;
            n->last_status = rc;
            return rc;
        }
    }
    ns2s_hs_action act = ns2s_handshake_step(n->hs, NS2S_HS_EV_KEM_DONE, NS2S_OK);
    rc = apply_hs_action(n, act, out);
    if (rc != NS2S_OK) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = rc;
        return rc;
    }
    return hs_after_step(n, now_ms, out);
}

int sh_neura_check_deadline(sh_neura_conn *n, uint64_t now_ms)
{
    if (!conn_alive(n) || n->phase != SH_NEURA_HANDSHAKING) {
        return NS2S_OK;
    }
    if (ns2s_hs_check_deadline(n->hs, now_ms) != NS2S_OK) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = SH_ERR_TIMEOUT;
        return SH_ERR_TIMEOUT;
    }
    if (n->created_ms != 0 && now_ms > n->created_ms &&
        now_ms - n->created_ms > n->handshake_timeout_ms) {
        n->phase = SH_NEURA_FAILED;
        n->last_status = SH_ERR_TIMEOUT;
        return SH_ERR_TIMEOUT;
    }
    return NS2S_OK;
}

/* ==========================================================================
 * 会话数据路径
 * ========================================================================== */
/* 棘轮宽限期辅助（实现见下方「棘轮宽限期」小节；seal 也要用，故前置声明） */
static void grace_expire(sh_neura_conn *n, uint64_t now_ms);
static void grace_switch_begin(sh_neura_conn *n, ns2s_chain_key *saved,
                               uint32_t *saved_id);
static void grace_switch_end(sh_neura_conn *n, const ns2s_chain_key *saved,
                             uint32_t saved_id, uint64_t now_ms);

int sh_neura_seal(sh_neura_conn *n, const uint8_t *plain, size_t len, sh_buf *out)
{
    if (!conn_alive(n) || out == NULL || !sh_neura_established(n)) {
        return NS2S_ERR_STATE;
    }
    if (plain == NULL && len > 0) {
        return NS2S_ERR_INVALID;
    }
    if (len > n->max_frame) {
        return NS2S_ERR_LENGTH;
    }
    size_t need = SH_FRAME_OVERHEAD + len;
    if (sh_buf_reserve(out, need) != 0) {
        return NS2S_ERR_NOMEM;
    }
    size_t written = 0;
    /*
     * libs2s 在 seal 内部可能切代（switch_after：服务端把 CONFIRM 封进输出
     * 的瞬间就换新钥）。必须在此处夹住快照，否则对端在途的旧代帧会被误杀。
     */
    const uint64_t now_ms = sh_neura_mono_ms();
    ns2s_chain_key saved_chain;
    uint32_t saved_id = 0;
    grace_switch_begin(n, &saved_chain, &saved_id);

    int rc = ns2s_session_seal(&n->session, plain, len,
                               out->data + out->wpos, sh_buf_writable(out),
                               &written, now_ms);
    if (rc != NS2S_OK) {
        n->last_status = rc;
        return rc;
    }
    grace_switch_end(n, &saved_chain, saved_id, now_ms);
    grace_expire(n, now_ms);
    out->wpos += written;
    return NS2S_OK;
}

/* ==========================================================================
 * 棘轮宽限期：上一代密钥双解
 *
 * 背景：棘轮每 300ms 切一代（库内 RATCHET_PERIOD_MS）。切代瞬间，对端可能
 * 已经用新代加密发帧，而本端此刻刚切成新代：在途帧的 header.ratchet_id 与
 * recv.ratchet_id 不一致，库内 ns2s_frame_validate() 直接返回
 * NS2S_ERR_REPLAY。安全上正确，但会误杀整条 keep-alive 连接
 * （线上现象：SH_LOGW "解密失败" + 客户端看到 EOF）。
 *
 * 对策（严格收敛：只收方向、只一代、只宽限期内、不放宽 seq）：
 *   1. apply 棘轮前快照 recv 链（ratchet_id/seq/key）；
 *   2. 新代解密失败且帧头 ratchet_id == 上一代 → 临时换回旧链重解一次；
 *   3. 解出后把「已前进」的旧链写回快照，同代后续帧仍可继续解；
 *   4. 主状态（新代链）无论成败都原样恢复，旧代绝不覆盖新代；
 *   5. 超过 SH_RATCHET_GRACE_MS 立即 memzero 旧链并失效。
 *
 * 安全性说明：ns2s_session_open() 在校验失败（REPLAY/AEAD）时不修改会话
 * 状态，因此"换链重试 + 恢复"不会造成链密钥双重推进；旧链同样执行完整
 * seq 校验与 AEAD 认证，跨代最多放宽 1 代、最久 1000ms。
 * ========================================================================== */
static void grace_expire(sh_neura_conn *n, uint64_t now_ms)
{
    if (!n->prev_valid) {
        return;
    }
    if (now_ms >= n->prev_valid_until_ms) {
        sodium_memzero(&n->prev_recv, sizeof n->prev_recv);
        n->prev_ratchet_id = 0;
        n->prev_valid_until_ms = 0;
        n->prev_valid = false;
    }
}

/* 棘轮切代前快照上一代收链；未真正切代则不快照（避免把当前代当成上一代）。
 *
 * 关键：libs2s 的切代点在 ns2s_session_seal() 内部（switch_after，服务端在把
 * CONFIRM 帧封进输出的瞬间就换新钥），以及 ns2s_session_consume_control()
 * 收到 CONFIRM 时（客户端）。因此凡是「可能触发切代」的调用都要用
 * grace_switch_begin/end 夹住，而不是只看 apply_ratchet_job。
 */
static void grace_switch_begin(sh_neura_conn *n, ns2s_chain_key *saved,
                               uint32_t *saved_id)
{
    *saved = n->session.recv;
    *saved_id = n->session.recv.ratchet_id;
}

static void grace_switch_end(sh_neura_conn *n, const ns2s_chain_key *saved,
                             uint32_t saved_id, uint64_t now_ms)
{
    if (n->session.recv.ratchet_id == saved_id) {
        return;                       /* 本次调用没有真正切代 */
    }
    sodium_memzero(&n->prev_recv, sizeof n->prev_recv);
    n->prev_recv = *saved;
    n->prev_ratchet_id = saved_id;
    n->prev_valid_until_ms = now_ms + SH_RATCHET_GRACE_MS;
    n->prev_valid = true;
    SH_LOGD("neura: 棘轮切代 recv %u -> %u，旧链保留 %u ms",
            saved_id, n->session.recv.ratchet_id, (unsigned)SH_RATCHET_GRACE_MS);
}


bool sh_neura_grace_active(const sh_neura_conn *n, uint64_t now_ms)
{
    return n != NULL && n->prev_valid && now_ms < n->prev_valid_until_ms;
}

uint32_t sh_neura_grace_hits(const sh_neura_conn *n)
{
    return n != NULL ? n->grace_hits : 0;
}

/*
 * 用上一代密钥解一帧。成功时 *app_len 为应用层字节数，且快照里的旧链已前进。
 * 失败时主状态与会话控制缓冲均原样恢复。
 */
static int open_prev_epoch(sh_neura_conn *n, const uint8_t *in, size_t total,
                           uint8_t *dst, size_t dst_cap, size_t *app_len)
{
    ns2s_session *s = &n->session;

    /* 保存新代主状态 */
    const ns2s_chain_key cur_chain = s->recv;
    const uint32_t cur_id = s->current_ratchet_id;
    uint8_t ctrl_save[NS2S_CTRL_MAX];
    const size_t ctrl_len_save = s->ctrl_in_len;
    if (ctrl_len_save > 0) {
        memcpy(ctrl_save, s->ctrl_in, ctrl_len_save);
    }

    /* 临时切到上一代 */
    s->recv = n->prev_recv;
    s->current_ratchet_id = n->prev_ratchet_id;

    size_t got = 0;
    int rc = ns2s_session_open(s, in, total, dst, dst_cap, &got);

    if (rc == NS2S_OK) {
        /* 旧链已前进：写回快照，同代后续在途帧还能解 */
        n->prev_recv = s->recv;
        n->prev_ratchet_id = s->current_ratchet_id;
        n->grace_hits++;
    }

    /* 恢复新代主状态（成功失败都恢复） */
    s->recv = cur_chain;
    s->current_ratchet_id = cur_id;
    if (ctrl_len_save > 0) {
        memcpy(s->ctrl_in, ctrl_save, ctrl_len_save);
        s->ctrl_in_len = ctrl_len_save;
    } else {
        s->ctrl_in_len = 0;
    }

    if (rc == NS2S_OK) {
        *app_len = got;
    }
    return rc;
}

int sh_neura_open(sh_neura_conn *n, const uint8_t *in, size_t in_len,
                  size_t *consumed, sh_buf *out)
{
    if (consumed != NULL) {
        *consumed = 0;
    }
    if (!conn_alive(n) || in == NULL || out == NULL || !sh_neura_established(n)) {
        return NS2S_ERR_STATE;
    }
    if (in_len < NS2S_FRAME_HEADER_BYTES) {
        return NS2S_ERR_AGAIN;
    }

    /* 帧头先按 max_frame 校验，禁止用线上长度做分配上限 */
    ns2s_frame_header h;
    int rc = ns2s_frame_header_decode(in, &h, n->max_frame);
    if (rc != NS2S_OK) {
        n->last_status = rc;
        return rc;
    }
    size_t total = SH_FRAME_OVERHEAD + (size_t)h.plaintext_len;
    if (total > n->max_frame + SH_FRAME_OVERHEAD) {
        return NS2S_ERR_LENGTH;
    }
    if (in_len < total) {
        return NS2S_ERR_AGAIN;
    }
    if (sh_buf_reserve(out, (size_t)h.plaintext_len) != 0) {
        return NS2S_ERR_NOMEM;
    }
    size_t app_len = 0;
    rc = ns2s_session_open(&n->session, in, total,
                           out->data + out->wpos, sh_buf_writable(out), &app_len);
    if (rc != NS2S_OK) {
        /*
         * 棘轮切代竞态：帧属于上一代 → 宽限期内用旧链双解一次。
         * 只在「帧头 ratchet_id 恰为上一代」时尝试，且不放宽 seq/AEAD 校验。
         */
        uint64_t now_ms = sh_neura_mono_ms();
        grace_expire(n, now_ms);
        if (sh_neura_grace_active(n, now_ms) &&
            h.ratchet_id == n->prev_ratchet_id) {
            size_t prev_len = 0;
            int prc = open_prev_epoch(n, in, total, out->data + out->wpos,
                                      sh_buf_writable(out), &prev_len);
            if (prc == NS2S_OK) {
                SH_LOGI("neura: 棘轮宽限期命中，用上一代密钥解出在途帧"
                        "（ratchet_id=%u，seq=%u，剩余 %llu ms）",
                        h.ratchet_id, h.seq,
                        (unsigned long long)(n->prev_valid_until_ms - now_ms));
                app_len = prev_len;
                rc = NS2S_OK;
            } else {
                rc = prc;      /* 旧链也解不出：按原错误上报 */
            }
        }
        if (rc != NS2S_OK) {
            SH_LOGW("neura: 解密失败 rc=%d 帧 ratchet_id=%u seq=%u | 当前 %u "
                    "上一代 %u(valid=%d,%lldms)",
                    rc, h.ratchet_id, h.seq, n->session.recv.ratchet_id,
                    n->prev_ratchet_id, (int)n->prev_valid,
                    (long long)(n->prev_valid
                                    ? (long long)(n->prev_valid_until_ms - now_ms)
                                    : 0LL));
            n->last_status = rc;
            return rc;
        }
    }
    out->wpos += app_len;
    if (consumed != NULL) {
        *consumed = total;
    }
    return NS2S_OK;
}

/* ==========================================================================
 * 0.3s KEM 棘轮
 * ========================================================================== */
bool sh_neura_ratchet_tick(sh_neura_conn *n, uint64_t now_ms, ns2s_kem_job **job_out)
{
    if (job_out != NULL) {
        *job_out = NULL;
    }
    if (!conn_alive(n) || !sh_neura_established(n)) {
        return false;
    }
    ns2s_kem_job *job = (ns2s_kem_job *)calloc(1, sizeof(*job));
    if (job == NULL) {
        return false;
    }
    int need = ns2s_session_ratchet_tick(&n->session, now_ms, job);
    if (need != 1) {
        free(job);
        return false;
    }
    n->inflight++;
    if (job_out != NULL) {
        *job_out = job;
    }
    return true;
}

int sh_neura_ratchet_apply(sh_neura_conn *n, const ns2s_kem_job *job,
                           uint64_t now_ms, sh_buf *out)
{
    if (!conn_alive(n) || job == NULL || !sh_neura_established(n)) {
        return NS2S_ERR_STATE;
    }
    if (n->inflight > 0) {
        n->inflight--;
    }
    /* 切代前快照上一代收链，成功后若 ratchet_id 真的变了则启用宽限期 */
    ns2s_chain_key saved_chain;
    uint32_t saved_id = 0;
    grace_switch_begin(n, &saved_chain, &saved_id);

    int rc = ns2s_session_apply_ratchet_job(&n->session, job, now_ms);
    if (rc != NS2S_OK) {
        n->last_status = rc;
        return rc;
    }
    grace_switch_end(n, &saved_chain, saved_id, now_ms);
    grace_expire(n, now_ms);
    /*
     * offer/cipher/confirm 是捎带在下一帧里的：应用完棘轮后主动发一帧
     * 空载荷，确保控制信息不会因为"没有业务数据"而卡住整条重协商链。
     */
    if (out != NULL) {
        rc = sh_neura_seal(n, NULL, 0, out);
    }
    return rc;
}

/* ==========================================================================
 * reactor 胶水层
 * ========================================================================== */
static int drain_pending_jobs(sh_reactor *r, sh_conn *c);

int sh_crypto_start(sh_reactor *r, sh_conn *c, ns2s_role role)
{
    if (r == NULL || c == NULL || c->neura != NULL) {
        return NS2S_ERR_INVALID;
    }
    if (!r->have_root_key) {
        SH_LOGE("crypto: reactor 未配置 RootKey，拒绝加密连接");
        return NS2S_ERR_STATE;
    }

    sh_neura_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.role = role;
    opts.root_key = r->root_key;
    opts.alg_mask = SH_ALG_MASK_DEFAULT;
    opts.max_frame = r->settings.max_frame != 0 ? r->settings.max_frame
                                               : SH_DEFAULT_MAX_FRAME;
    opts.handshake_timeout_ms = r->settings.handshake_timeout_ms != 0
                                    ? r->settings.handshake_timeout_ms
                                    : SH_HANDSHAKE_TIMEOUT_MS;
    opts.server_name = r->settings.anchor_host;
    opts.require_trust_anchor = r->settings.trust_anchor_required;
    opts.doh = NULL;    /* DoH 在启动时完成，握手期只做纯 CPU 比对 */

    sh_neura_conn *n = sh_neura_conn_new(&opts);
    if (n == NULL) {
        return NS2S_ERR_NOMEM;
    }
    c->neura = n;
    c->crypto = SH_CRYPTO_HANDSHAKE;
    SH_LOGD("crypto start: conn#%u role=%s", c->id,
            role == NS2S_ROLE_SERVER ? "server" : "client");
    c->ratchet_timer.name = "ratchet";

    if (role == NS2S_ROLE_CLIENT) {
        int rc = sh_neura_handshake_start(n, sh_neura_mono_ms());
        if (rc != NS2S_OK) {
            sh_crypto_close(r, c);
            return rc;
        }
        /* 客户端 hello 的 X-Wing keypair 立即进 KEM pool */
        rc = drain_pending_jobs(r, c);
        if (rc != NS2S_OK) {
            sh_crypto_close(r, c);
            return rc;
        }
    }
    return NS2S_OK;
}

/* 把 n->pending 里的 KEM 任务全部提交给 worker pool */
static int drain_pending_jobs(sh_reactor *r, sh_conn *c)
{
    ns2s_kem_job *job = NULL;
    while (sh_neura_take_kem_job(c->neura, &job)) {
        if (sh_reactor_kem_submit(r, c, job) != 0) {
            ns2s_kem_job_destroy(job);
            free(job);
            return NS2S_ERR_NOMEM;
        }
        job = NULL;
    }
    return NS2S_OK;
}

/* 握手完成后按需做一次信任锚比对（纯 CPU，不做网络 I/O） */
static int verify_anchor(sh_reactor *r, sh_conn *c)
{
    if (!r->settings.trust_anchor_required) {
        return NS2S_OK;
    }
    sh_anchor *a = r->anchor;
    if (a == NULL) {
        SH_LOGE("trust-anchor: 要求校验但启动时未取得 TXT 锚点，拒绝连接");
        return SH_ERR_TRUST_ANCHOR;
    }
    int rc = sh_anchor_verify(r->root_key, a);
    if (rc != NS2S_OK) {
        SH_LOGE("trust-anchor: 指纹不匹配（host=%s），拒绝连接", a->host);
        return rc;
    }
    return NS2S_OK;
}

int sh_crypto_pump(sh_reactor *r, sh_conn *c)
{
    if (r == NULL || c == NULL || c->neura == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (c->crypto == SH_CRYPTO_PLAIN) {
        return NS2S_OK;
    }

    for (;;) {
        size_t avail = sh_buf_readable(&c->in);
        SH_LOGD("pump: conn#%u crypto=%d avail=%zu", c->id, (int)c->crypto, avail);
        if (avail == 0) {
            break;
        }
        const uint8_t *p = sh_buf_peek(&c->in, NULL);
        size_t consumed = 0;
        int rc;
        if (c->crypto == SH_CRYPTO_HANDSHAKE) {
            rc = sh_neura_handshake_pump(c->neura, p, avail, &consumed, &c->out);
        } else {
            break;    /* 会话数据由 sh_crypto_read 处理 */
        }
        if (consumed > 0) {
            sh_buf_consume(&c->in, consumed);
        }
        if (drain_pending_jobs(r, c) != NS2S_OK) {
            return NS2S_ERR_NOMEM;
        }
        if (rc == NS2S_ERR_AGAIN) {
            break;
        }
        if (rc != NS2S_OK) {
            return rc;
        }
        if (sh_neura_phase_of(c->neura) == SH_NEURA_ESTABLISHED &&
            c->crypto == SH_CRYPTO_HANDSHAKE) {
            int vrc = verify_anchor(r, c);
            if (vrc != NS2S_OK) {
                return vrc;
            }
            c->crypto = SH_CRYPTO_READY;
            r->stats.handshakes_ok++;
            SH_LOGI("conn#%u 握手完成 alg=%s", c->id,
                    sh_neura_alg_name(sh_neura_alg(c->neura)));
        }
        if (sh_neura_phase_of(c->neura) == SH_NEURA_FAILED) {
            r->stats.handshakes_failed++;
            return NS2S_ERR_AUTH;
        }
    }
    return NS2S_OK;
}

ssize_t sh_crypto_read(sh_reactor *r, sh_conn *c, sh_buf *dst)
{
    if (r == NULL || c == NULL || c->neura == NULL || dst == NULL) {
        return -1;
    }
    if (c->crypto != SH_CRYPTO_READY) {
        return 0;
    }
    ssize_t total = 0;
    for (;;) {
        size_t avail = sh_buf_readable(&c->in);
        if (avail < NS2S_FRAME_HEADER_BYTES) {
            break;
        }
        const uint8_t *p = sh_buf_peek(&c->in, NULL);
        size_t consumed = 0;
        size_t before = sh_buf_readable(dst);
        int rc = sh_neura_open(c->neura, p, avail, &consumed, dst);
        if (rc == NS2S_ERR_AGAIN) {
            break;
        }
        if (rc != NS2S_OK) {
            return -1;
        }
        sh_buf_consume(&c->in, consumed);
        total += (ssize_t)(sh_buf_readable(dst) - before);

        /* 对端可能捎带棘轮控制帧：解析后可能需要提交 KEM */
        if (c->neura->session.ctrl_in_len > 0) {
            ns2s_kem_job *job = (ns2s_kem_job *)calloc(1, sizeof(*job));
            if (job == NULL) {
                return -1;
            }
            int submit = 0;
            /* 客户端收到 CONFIRM 时在 consume_control 内部切代，同样要夹快照 */
            const uint64_t ctrl_now = sh_neura_mono_ms();
            ns2s_chain_key ctrl_saved;
            uint32_t ctrl_saved_id = 0;
            grace_switch_begin(c->neura, &ctrl_saved, &ctrl_saved_id);

            rc = ns2s_session_consume_control(&c->neura->session,
                                              ctrl_now, job, &submit);
            if (rc != NS2S_OK) {
                free(job);
                return -1;
            }
            grace_switch_end(c->neura, &ctrl_saved, ctrl_saved_id, ctrl_now);
            grace_expire(c->neura, ctrl_now);
            if (submit) {
                if (sh_reactor_kem_submit(r, c, job) != 0) {
                    ns2s_kem_job_destroy(job);
                    free(job);
                    return -1;
                }
            } else {
                free(job);
            }
        }
    }
    return total;
}

int sh_crypto_write(sh_reactor *r, sh_conn *c, const uint8_t *src, size_t len)
{
    (void)r;
    if (c == NULL || c->neura == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (c->crypto != SH_CRYPTO_READY) {
        return NS2S_ERR_STATE;
    }
    return sh_neura_seal(c->neura, src, len, &c->out);
}

int sh_crypto_tick(sh_reactor *r, sh_conn *c)
{
    if (r == NULL || c == NULL) {
        return NS2S_ERR_INVALID;
    }
    if (c->neura == NULL) {
        return 0;    /* 明文连接（尚未启用加密）：无需 tick，不是错误 */
    }
    uint64_t now = sh_neura_mono_ms();

    if (c->crypto == SH_CRYPTO_HANDSHAKE) {
        int rc = sh_neura_check_deadline(c->neura, now);
        if (rc != NS2S_OK) {
            r->stats.timeouts++;
            return rc;
        }
        return NS2S_OK;
    }
    if (c->crypto != SH_CRYPTO_READY) {
        return NS2S_OK;
    }

    ns2s_kem_job *job = NULL;
    if (sh_neura_ratchet_tick(c->neura, now, &job)) {
        if (sh_reactor_kem_submit(r, c, job) != 0) {
            ns2s_kem_job_destroy(job);
            free(job);
            return NS2S_ERR_NOMEM;
        }
        r->stats.ratchets++;
    }
    return NS2S_OK;
}

void sh_crypto_close(sh_reactor *r, sh_conn *c)
{
    (void)r;
    if (c == NULL || c->neura == NULL) {
        return;
    }
    sh_neura_conn_free(c->neura);
    c->neura = NULL;
    c->crypto = SH_CRYPTO_PLAIN;
}
