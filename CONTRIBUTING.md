# 贡献指南（Contributing to Safe-HTTP）

感谢你参与 Safe-HTTP。本项目是**安全敏感**的加密网关，对正确性、可审计性与
"密钥零泄漏"的要求高于一般项目，因此流程比普通仓库稍严格。

---

## 1. 开始之前

- 提 **Issue** 讨论设计（尤其是涉及协议、密钥派生、epoll 事件循环的改动）；
- **安全漏洞请勿公开**，走 [`SECURITY.md`](SECURITY.md) 的私密渠道；
- 代码贡献需要先签署 [`CLA.md`](CLA.md)（PR 里评论一句话即可）。

## 2. 环境准备

```bash
# 依赖：Linux + gcc/clang + make；libs2s 默认在 /opt/neura/c-s2s
make MODE=PROXY all                 # 编译网关
make MODE=PROXY neura-probe         # 加密探针（压测/断言）
make MODE=PROXY upstream-stub       # 纯 C 上游桩
```

需要改动浏览器端时，另需 `wasi-sdk` 与为 `wasm32-wasi` 交叉编译的 libsodium，
步骤见 `README.md`「浏览器端加密接入（WASM）」。`NEURA_ROOT=` 可覆盖 libs2s 路径。

## 3. 提交前必须通过的门禁

```bash
make MODE=PROXY headers-check   # 头文件双模式语法检查
make MODE=PROXY link-check      # 链接 libs2s/libsodium + 加密层自检
make MODE=PROXY e2e-check       # 双 reactor 真实网络握手/回显/棘轮
make MODE=PROXY verify          # 明文 403 / 加密 200 断言矩阵（须全绿）
make MODE=PROXY bench BENCH_LOOP=20000 BENCH_WARMUP=200
```

- 涉及加密路径的改动，`verify` 必须 **PASS=6 FAIL=0**；
- 涉及数据路径的改动，`bench` 必须 **零断连**（探针会以非 0 退出报告异常）；
- 涉及浏览器端时，追加 `node sdk/test_neura_js.mjs` 与 `node sdk/test_browser_client.mjs`。

## 4. 代码规范

**语言与依赖**

- 纯 C11，禁止引入新的第三方运行时依赖；密码学原语**只能**来自 libsodium /
  libs2s，**禁止自研任何加密算法、模式、填充或随机数**。
- 断言与协议验证工具必须是**纯 C**（可执行文件），不要用 shell / Python / jq
  去解析 JSON 或解密结果——历史包袱请参考 `tests/neura_probe.c` 里的
  `json_field_is_one()`（手写极简扫描）。

**并发与性能**

- 事件循环（reactor 线程）内**禁止**做重计算与阻塞 IO；KEM 等重运算必须走
  worker pool，并通过既有接口回收结果。
- 新增缓冲必须走 `sh_buf_*`，关注 `sh_buf_reserve()` 失败分支；
  ET 模式下注意"读到 EAGAIN 才算抽干"，必要时重新 arm。

**安全**

- 密钥、明文、会话状态只放 secure region；释放前 `sodium_memzero` / `ns2s_secure_zero`；
- **不要**为了"能跑"而放宽 `seq` 校验、`ratchet_id` 校验或 AEAD 认证；
  棘轮宽限期只允许"多留一代、只放宽收方向"（见 `src/neura_conn.c`）；
- 日志里禁止输出密钥、明文正文、完整帧内容；错误信息不要泄漏内存地址。

**风格**

- 每个源文件首行必须带 `// SPDX-License-Identifier: AGPL-3.0-or-later`
  与 `// Copyright (C) 2026 Neura-L (Safe-HTTP Project)`（新建文件请照抄现有头部）；
- 4 空格缩进，行宽 ~90 列；函数用 `snake_case`，类型用 `sh_*` 前缀；
- 每个 `if (rc != 0)` 都要有明确处理；不要静默吞错；
- 提交信息用祈使句，首行 ≤ 72 字符，正文说明"为什么"：
  `fix(neura): reset g_stop in reactor_init so reactors can be rebuilt`

## 5. PR 要求

1. 一个 PR 只做一件事；配套测试/断言与文档同步更新；
2. 新功能请附**可复现的验证命令**与输出（贴关键行，不要贴密钥或明文正文）；
3. 修改行为、配置语法或协议字段时，同步更新 `README.md` / `REQUIREMENTS.md`；
4. 不要提交构建产物（`build/`）、密钥文件（`rootkey.hex`、`id.xwing`）或 `.bak`；
5. 首次 PR 记得签署 CLA，CI 会校验。

## 6. 报告问题

请提供：复现命令、期望/实际结果、`--log-level info` 的相关日志片段、
是否加密通道、以及是否使用了自定义配置。
**切勿**在公开 issue 里贴 RootKey、私钥或真实用户数据。
