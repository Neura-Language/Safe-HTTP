## 变更说明

<!-- 这个 PR 做了什么？为什么需要它？关联的 issue：Fixes #… -->

## 变更类型

- [ ] Bug 修复
- [ ] 新功能
- [ ] 性能优化
- [ ] 重构（无行为变更）
- [ ] 文档 / 构建 / CI

## 影响范围

- [ ] 加密协议 / 密钥派生（`src/neura_conn.c`、`sdk/wasm/`）
- [ ] 事件循环 / 网络层（`src/reactor.c`、`src/neura_proxy.c`）
- [ ] 策略引擎 / WAF（`src/config_parser.c`、`src/waf.c`）
- [ ] 工具链（`tools/`、`tests/`）
- [ ] 纯文档

## 验证（请贴关键输出，勿贴密钥或明文正文）

```text
$ make MODE=PROXY headers-check
...
$ make MODE=PROXY link-check
...
$ make MODE=PROXY verify
[suite] PASS  PASS=6 FAIL=0

$ make MODE=PROXY bench BENCH_LOOP=20000 BENCH_WARMUP=200
# 零断连 + P50/P90/P99
```

涉及浏览器端时：

```text
$ make MODE=PROXY sdk-wasm
$ node sdk/test_neura_js.mjs http://127.0.0.1
mitm_blocked = YES
```

## 检查清单

- [ ] 已在本地跑过 `headers-check` / `link-check` / `e2e-check` / `verify`（全绿）
- [ ] 涉及数据路径的改动已跑 `bench`，**零断连**
- [ ] 未引入新的第三方依赖；未自研任何密码学原语
- [ ] 未放宽 `seq` / `ratchet_id` / AEAD 校验，或已在说明中给出安全论证
- [ ] 日志中无密钥、明文正文、完整帧内容
- [ ] 新增/修改的源文件已带 `SPDX-License-Identifier: AGPL-3.0-or-later` 头
- [ ] 已更新相关文档（`README.md` / `REQUIREMENTS.md` / `config/`）
- [ ] 提交里不含 `build/`、`*.bak`、`rootkey.hex`、`id.xwing` 等敏感或产物文件

## CLA

- [ ] 我已在 PR 中评论 `I have read the CLA Document and I hereby sign the CLA`
      （代表公司/组织贡献者需另行提交实体 CLA）

## 备注

<!-- 兼容性影响、回滚方式、后续计划等 -->
