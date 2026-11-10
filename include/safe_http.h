// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Neura-L (Safe-HTTP Project)
//
/*
 * Safe-HTTP - 总入口头文件
 *
 * 按依赖顺序聚合全部模块头文件，便于单元测试与外部集成方
 * 一次性引入。业务实现请优先直接包含所需的最小头文件（编译更快）。
 *
 * 依赖顺序：config -> util/log -> network -> security/http
 *           -> config_parser -> waf -> (proxy | standalone)
 */
#ifndef SAFE_HTTP_H
#define SAFE_HTTP_H

#include "config.h"
#include "util.h"
#include "log.h"
#include "network.h"
#include "security.h"
#include "http.h"
#include "config_parser.h"
#include "waf.h"

#if SH_MODE_PROXY
#  include "neura_proxy.h"
#else
#  include "standalone.h"
#endif

/*
 * 生命周期约定（main.c 负责）：
 *
 *   sh_settings_defaults(&settings);
 *   sh_settings_apply_cli(&settings, argc, argv, err, sizeof err);
 *   cfg = ncf_parse_file(settings.config_path, err, sizeof err);
 *   w   = waf_new(cfg, 0, 0);
 *   sh_reactor_init(&reactor, &settings, cfg, w);
 *   reactor.hooks = SH_MODE_PROXY ? &sh_proxy_hooks : &sh_standalone_hooks;
 *   sh_reactor_listen(&reactor);
 *   sh_reactor_run(&reactor);           // 阻塞，直到 SIGTERM
 *   sh_reactor_destroy(&reactor);
 *   waf_free(w); ncf_config_free(cfg);
 */
int sh_server_main(int argc, char **argv);

#endif /* SAFE_HTTP_H */
