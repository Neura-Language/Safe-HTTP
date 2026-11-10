// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 加密层链接自检
 *
 * 目的：在没有 src/main.c 的骨架阶段，验证
 *   1. 头文件与 libs2s.a / libsodium.a 的 ABI 一致；
 *   2. 库路径与 NEURA_PROFILE 选择正确；
 *   3. ns2s_init() + libsodium 可用，打印实际版本；
 *   4. ns2s_secure_alloc()（mlock + MADV_DONTDUMP）能分配并释放；
 *   5. 锚点指纹派生与 install.sh 的 openssl 复算逐字节一致。
 *
 * 该程序不进入生产二进制，仅由 `make link-check` 编译运行。
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "security.h"

int main(void)
{
    uint8_t key[SH_ROOTKEY_BYTES];
    char hex[SH_ROOTKEY_HEX_LEN];
    char fp[SH_FINGERPRINT_HEX_LEN];
    char name[300];
    char txt[200];

    int rc = sh_neura_global_init();
    if (rc != NS2S_OK) {
        printf("FAIL: sh_neura_global_init rc=%d\n", rc);
        return 1;
    }

    if (sh_rootkey_generate(key) != NS2S_OK ||
        sh_rootkey_hex(key, hex) != NS2S_OK ||
        sh_anchor_fingerprint_hex(key, fp) != NS2S_OK ||
        sh_anchor_txt_name("example.com", name, sizeof name) != NS2S_OK ||
        sh_anchor_format_txt(key, txt, sizeof txt) != NS2S_OK) {
        printf("FAIL: rootkey/anchor 基础 API\n");
        return 1;
    }

    printf("libsodium   = %s\n", sh_neura_crypto_version());
    printf("rootkey     = %s\n", hex);
    printf("anchor_fp   = %s\n", fp);
    printf("txt_name    = %s\n", name);
    printf("txt_value   = %s\n", txt);

    /* 回环：TXT 值解析后应与本地 RootKey 派生指纹一致 */
    sh_anchor a;
    memset(&a, 0, sizeof a);
    if (sh_anchor_parse_txt(txt, &a, NULL, 0) != NS2S_OK ||
        sh_anchor_verify(key, &a) != NS2S_OK || !a.verified) {
        printf("FAIL: TXT 解析/比对不一致\n");
        return 1;
    }
    printf("verify      = ok (txt <-> rootkey)\n");

    /* RootKey 落盘/读回（0600 + rename） */
    const char *path = "build/link_check_rootkey.hex";
    char err[160] = {0};
    if (sh_rootkey_save(path, key, 0600, err, sizeof err) != NS2S_OK) {
        printf("FAIL: save rootkey: %s\n", err);
        return 1;
    }
    uint8_t back[SH_ROOTKEY_BYTES];
    if (sh_rootkey_load(path, back, err, sizeof err) != NS2S_OK ||
        memcmp(back, key, sizeof key) != 0) {
        printf("FAIL: load rootkey: %s\n", err);
        return 1;
    }
    remove(path);
    printf("rootkey_io  = ok\n");

    /* 安全区分配：mlock + MADV_DONTDUMP */
    sh_neura_opts o;
    memset(&o, 0, sizeof o);
    o.role = NS2S_ROLE_SERVER;
    o.root_key = key;
    o.server_name = "example.com";
    sh_neura_conn *c = sh_neura_conn_new(&o);
    if (c == NULL) {
        printf("FAIL: conn_new errno=%d\n", errno);
        return 1;
    }
    printf("conn        = phase=%d alg=%s\n",
           (int)sh_neura_phase_of(c), sh_neura_alg_name(sh_neura_alg(c)));
    sh_neura_conn_free(c);
    printf("secure_area = ok (alloc + destroy + free)\n");

    printf("RESULT      = PASS\n");
    return 0;
}
