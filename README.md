# Safe-HTTP

> 面向 **无 SSL 证书 / 纯 HTTP 环境 / 内网设备** 的抗量子加密 Web 网关。
> 纯 C 实现，epoll 边缘触发，集成 [Neura-S2S](https://github.com/Neura-Language/Neura-S2S) 抗量子协议（X-Wing = ML-KEM-768 + X25519，0.3s 会话棘轮）。

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![CLA](https://img.shields.io/badge/CLA-required-orange.svg)](CLA.md)
[![Language: C11](https://img.shields.io/badge/Language-C11-informational.svg)](#)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(epoll%20ET)-lightgrey.svg)](#)

许可证 **AGPL-3.0**（对外提供网络服务须提供对应源码，见[许可证与服务端义务](#许可证与服务端义务)）；
代码贡献需签署 [CLA](CLA.md)，贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 目录

- [特性](#特性)
- [三种接入形态](#三种接入形态)
- [快速开始](#快速开始)
- [编译与运行模式](#编译与运行模式)
- [浏览器端加密接入（WASM）](#浏览器端加密接入wasm)
- [配置语法（config.ncf）](#配置语法configncf)
- [工具链与 Make 目标](#工具链与-make-目标)
- [性能实测](#性能实测)
- [目录结构](#目录结构)
- [安全说明与已知限制](#安全说明与已知限制)
- [路线图](#路线图)
- [许可证与服务端义务](#许可证与服务端义务)

---

## 特性

| 能力 | 说明 |
|---|---|
| **抗量子加密** | X-Wing 混合 KEM（ML-KEM-768 + X25519），密钥协商不依赖任何可被量子算法攻破的假设 |
| **无证书** | 不需要 CA、不需要 SSL 证书：用 RootKey / 静态公钥指纹做信任锚 |
| **会话棘轮** | 每 300 ms 一次 KEM 重置，带 1000 ms 在途帧宽限期（双代密钥可解），长连接不断流 |
| **双模式条件编译** | `STANDALONE`（自带静态站点）与 `PROXY`（挂在 Nginx/Apache 前），编译期隔离，互不编入 |
| **策略即配置** | 自有 MatchLang 规则引擎（非 PCRE）解析 `config.ncf`：强制加密、URL 重写、防 CC、WAF |
| **全链路非阻塞** | epoll ET + 非阻塞上游 connect + 双向背压；KEM 运算走 worker pool，绝不在事件循环里做重计算 |
| **三种接入形态** | 浏览器（WASM 端到端解密）、本地网关（普通 curl 可用）、服务端反代（对上游透明） |
| **纯 C 工具链** | 探针、网关、边缘、上游桩全部纯 C；断言验证不依赖 shell / Python / jq |

---

## 三种接入形态

```
① 浏览器直连（WASM 端到端加密，用户零安装）
   浏览器 ──明文? 不──> [WASM 内加解密] ⇄ HTTP 密文帧 ⇄ neura-browser-edge(:80) ⇄ Safe-HTTP ⇄ 上游

② 本地客户端网关（普通 curl / 老浏览器可用）
   curl ──明文 localhost──> neura-gateway ⇄ Neura-S2S ⇄ Safe-HTTP(:18081) ⇄ 上游

③ 服务端反代（对上游完全透明，最经典）
   客户端 ⇄ Neura-S2S ⇄ Safe-HTTP(PROXY) ──明文──> 上游应用
```

三种形态的安全边界不同，请按场景选择：

| 形态 | 谁做加解密 | 用户需要安装 | 端到端覆盖 |
|---|---|---|---|
| ① 浏览器 WASM | 浏览器 | 无 | 浏览器 ⇄ 边缘（出网段全密文） |
| ② 本地网关 | 本机进程 | 一个二进制 | 本机进程 ⇄ 服务端 |
| ③ 服务端反代 | Safe-HTTP 进程 | 无（需客户端支持协议或走 ②/①） | 客户端 ⇄ 网关 |

---

## 快速开始

### 依赖

- Linux（x86_64 / aarch64），glibc
- gcc / clang、make、libsodium（项目内 vendored 源码可自编）
- [libs2s](https://github.com/Neura-Language/Neura-S2S)（Neura-S2S C 实现），默认路径 `/opt/neura/c-s2s`，可用 `NEURA_ROOT=` 覆盖
- 可选：`/opt/wasi-sdk`（只有需要重新编译 `sdk/neura-crypto.wasm` 时才要）

### 60 秒跑起来（PROXY 模式 + 加密访问）

```bash
# 1) 编译网关 + 工具
make MODE=PROXY all
make MODE=PROXY neura-probe neura-gateway upstream-stub

# 2) 生成 RootKey（首次）
make MODE=PROXY install            # 或手工: head -c 32 /dev/urandom | xxd -p > /etc/safe-http/rootkey.hex

# 3) 起一个上游（演示用纯 C 桩，也可换成你的应用）
./build/proxy/upstream-stub --listen 127.0.0.1:19080

# 4) 起网关（18081 加密入口 / 18443 备用入口）
./build/proxy/safe-http --config config/config.ncf --root-key /etc/safe-http/rootkey.hex \
    --listen 127.0.0.1:18081 --listen-tls 127.0.0.1:18443 \
    --upstream 127.0.0.1:19080 --log-level info

# 5) 断言验证（明文 403 / 加密 200 的完整矩阵 + neura 字段校验）
make MODE=PROXY verify VERIFY_ROOT_KEY=/etc/safe-http/rootkey.hex

# 6) 长连接压测（零断连断言 + P50/P90/P99）
make MODE=PROXY bench BENCH_LOOP=50000 VERIFY_ROOT_KEY=/etc/safe-http/rootkey.hex
```

`verify` 的期望输出（确定性，每次应全绿）：

```
[suite] plain /        status=200  expect=200  neura=-   PASS
[suite] plain /echo    status=200  expect=200  neura=-   PASS
[suite] plain /api/x   status=403  expect=403  neura=-   PASS
[suite] neura /        status=200  expect=200  neura=-   PASS
[suite] neura /echo    status=200  expect=200  neura=1   PASS
[suite] neura /api/x   status=200  expect=200  neura=-   PASS
[suite] PASS  PASS=6 FAIL=0
```

---

## 编译与运行模式

```bash
make MODE=STANDALONE    # 直接监听 80/443，自己处理静态文件与 API 路由
make MODE=PROXY         # 监听本地端口，反代到现有 Nginx/Apache
make both               # 两种模式各编译一遍（CI 用）
```

常用变量：

| 变量 | 作用 |
|---|---|
| `MODE=STANDALONE\|PROXY` | 必填，编译期决定模式 |
| `NEURA_ROOT=/path` | libs2s 源码根（默认 `/opt/neura/c-s2s`） |
| `DEBUG=1` | `-O0 -g3` |
| `SANITIZE=1` + `NEURA_PROFILE=asan` | ASan + UBSan |
| `WERROR=1` | 警告即错误 |

主要命令行参数：

```
--config PATH           配置文件（默认 /etc/safe-http/config.ncf）
--root-key PATH         RootKey（默认 /etc/safe-http/rootkey.hex）
--listen HOST:PORT      主监听（默认 127.0.0.1:5362 / 模式相关）
--listen-tls HOST:PORT  额外监听口（别名 --https）
--upstream HOST:PORT    上游（PROXY 模式，默认 127.0.0.1:8080）
--static-root PATH      静态根（STANDALONE 模式，默认 /var/www/html）
--anchor-host HOST      信任锚域名（DNS TXT 指纹所在域）
--max-frame BYTES       单帧明文上限（默认 1 MiB）
--kem-workers N         KEM worker 线程数（默认 2）
--log-level LEVEL       fatal|error|warn|info|debug|trace
--check-config / --dump-config / --print-fingerprint   诊断
```

---

## 浏览器端加密接入（WASM）

让**普通用户零安装**地走抗量子加密：页面里的 WASM 自己做握手与解密，服务器只提供密文帧。

```
浏览器                                  neura-browser-edge(:80)           上游
  |-- GET / ------------------------->  shell 页面（HTML+JS+WASM）
  |-- GET /neura-pk ----------------->  服务端静态 X-Wing 公钥（1216 B）
  |                                     [本地用 WASM 算 SHA512 指纹并 pin 校验]
  |-- POST /__neura/boot ------------>  Decaps(ct_auth, 静态sk) + Encaps(cpk)
  |<-- sid ‖ srv_eph_pk ‖ ct_fs ------
  |                                     [双方派生 root/c2s/s2c，建会话]
  |-- POST /__neura/app (密文帧) ----->  ns2s_session_open → 明文 HTTP → 转发上游
  |<-- 密文响应 -----------------------  ns2s_session_seal
  |                                     [WASM 解密 → 渲染真实页面]
```

### 密钥协商（浏览器侧**不持有任何长期密钥**）

```
client: ephemeral X-Wing keypair (cpk/csk)
ss_auth = Decaps(Encaps(server_static_pk), server_static_sk)   # 服务端认证
ss_fs   = Decaps(Encaps(cpk), csk)                             # 前向保密
ikm     = ss_auth ‖ ss_fs
salt    = SHA512(server_static_pk)                             # 浏览器 pin 的指纹
info    = "neura-s2s-v1/http-boot" ‖ nonce‖cpk‖spk_e‖ct_auth‖ct_fs
okm     = HKDF-SHA512(ikm, salt, info, 128) → root(64)‖c2s(32)‖s2c(32)
```

- **RootKey 永不下发**：浏览器里没有任何长期密钥，因此不存在"中间人窃取 rootkey"这条攻击面；
- **抗量子**：拿到 `ikm` 需同时攻破 ML-KEM-768 与 X25519；
- **防调包**：换掉 `server_static_pk` 必须同时伪造 SHA-512 指纹（与 pin 冲突，实测会中止并在页面报错）；
- 浏览器无 AES-NI，该通道固定 **ChaCha20-Poly1305**。

### 编译 WASM 与部署

```bash
# 1) 准备 wasi-sdk（只需一次）
#    https://github.com/WebAssembly/wasi-sdk/releases  → 解压到 /opt/wasi-sdk-24.0-x86_64-linux

# 2) 为 wasm32-wasi 交叉编译 libsodium（vendored 源码）
cd /opt/neura/c-s2s/third_party/libsodium-src
make distclean
CC=/path/to/wasi-clang-wrapper ./configure --host=wasm32-wasi \
    --disable-shared --enable-static --disable-asm
make -j"$(nproc)"

# 3) 编译 WASM 模块 → build/sdk/neura-crypto.wasm
make MODE=PROXY sdk-wasm

# 4) 编译 80 端口边缘服务
make MODE=PROXY neura-browser-edge

# 5) 起服务（--sdk-dir 指向放 neura.js / neura-crypto.wasm 的目录）
./build/proxy/neura-browser-edge --listen 0.0.0.0:80 \
    --upstream 127.0.0.1:18081 --host example.com \
    --sdk-dir sdk --page sdk/index.html --id /etc/safe-http/id.xwing
```

第一次启动会自动生成服务端静态 X-Wing 身份（`/etc/safe-http/id.xwing`，权限 0600），并打印 SHA-512 指纹。
**该指纹请离线核对一次**（写进用户书签 / DNS TXT / 发布页），这是唯一的"首次信任"步骤。

### 前端集成

```html
<script src="/neura.js"></script>
<script>
  const n = new Neura({ site: location.hostname, pinHex: '<离线核对的指纹>' });
  await n.load();      // 载入 wasm
  await n.boot();      // 密钥协商（自动校验 pin）
  const body = n.bodyOf(await n.request('GET', '/'));
  document.getElementById('app').innerHTML = body;   // 渲染真实页面
</script>
```

---

## 配置语法（config.ncf）

```ncf
# 未匹配任何 Encrypt 规则时的默认策略
Policy { Plaintext: allow; }        # allow | deny（deny=全站强制加密）

# 强制加密
Encrypt API {
    Path Match: starts_with "/api/";
    Action: enforce_neura_s2s;
}

# 普通页面放行
Encrypt Web {
    Path Match: starts_with "/";
    Action: allow_plain;
}
```

可用 `Action`：`enforce_neura_s2s` / `allow_plain` / `respond_403` / `drop_connection` / `log_only`。
另有 `Rewrite`（MatchLang 模式匹配，禁止 PCRE）、`Ban`（防 CC / UA 黑名单）等规则，见 `config/presets/`。

校验与查看：

```bash
make MODE=PROXY config-check
./build/proxy/safe-http --dump-config config/config.ncf
./build/proxy/safe-http --print-fingerprint config/config.ncf
```

---

## 工具链与 Make 目标

全部纯 C（除 `sdk/neura.js` 是前端胶水）。**不依赖 shell / Python / jq 做断言或解析。**

| 目标 | 产物 / 作用 |
|---|---|
| `make MODE=PROXY all` | 主程序 `build/proxy/safe-http` |
| `headers-check` / `link-check` / `e2e-check` | 头文件双模式语法检查 / 链接自检 / 双 reactor 真实握手 |
| `neura-probe` | 加密探针：单发、`--loop N` 压测（P50/P90/P99）、`--suite` 断言矩阵、`--plain` 明文基准 |
| `verify` | 确定性断言：明文 vs 加密状态码 + 响应 `neura` 字段（手写 JSON 扫描） |
| `bench` | 稳态延迟基准（P50/P90/P99/QPS/CPU） |
| `neura-gateway` | 本地客户端网关：`curl`/老浏览器经它走加密 |
| `neura-browser-edge` | 80 端口浏览器边缘（WASM 客户端配套） |
| `upstream-stub` | 纯 C 上游桩：`/echo` JSON + `--webroot` 静态站，单次 write 发送（规避 Nagle） |
| `sdk-wasm` | 编译 `sdk/neura-crypto.wasm` |

探针常用写法：

```bash
# 断言 + 压测（失败即非 0 退出，适合 CI）
./build/proxy/neura-probe --host 127.0.0.1 --port 18081 --root-key /etc/safe-http/rootkey.hex \
    --path /echo --host-header example.com --loop 50000 --warmup 200 \
    --assert-neura --expect-status 200

# 明文基准（A/B 用，隔离"加密开销"与"上游开销"）
./build/proxy/neura-probe --host 127.0.0.1 --port 18081 --plain --loop 50000 \
    --path /echo --host-header example.com
```

> ⚠️ 压测请务必用纯 C 上游桩。用 `python -m http.server` 这类实现（先发头、再发体、未关 Nagle）会稳定引入 **~40 ms** 的延迟 ACK 尖峰，把 P90 从亚毫秒污染到 40 ms+，彻底掩盖真实开销。

---

## 性能实测

单机 `127.0.0.1`、纯 C 上游桩、单连接串行（`loop=50000, warmup=200`），仅供量级参考：

| 场景 | QPS | P50 | P90 | P99 | 备注 |
|---|---|---|---|---|---|
| 加密通道（Neura-S2S） | 7 803 | **114 µs** | 127 µs | 242 µs | 50000/50000 零断连、0 WARN |
| 明文经同一代理 | 10 547 | 90 µs | 98 µs | 144 µs | A/B 基准 |
| **加密净开销** | −26% 吞吐 | **+24 µs（+27%）** | — | — | 对称加解密固定成本为主 |

长连接稳定性：50000 请求跨 ~21 个棘轮 epoch，**零断连、零解密失败**；棘轮宽限期（1000 ms 双代密钥）实测命中 4–5 次并全部兜住。

浏览器通道：每次会话一次 KEM 协商（~1.6 ms），每请求密文开销 **43–45 字节**（帧头 15 + nonce 12 + tag 16），1.7 KB 页面解密耗时在亚毫秒级。

---

## 目录结构

```
safe-http/
├── src/                 # 网关实现（reactor/代理/加密胶水/WAF/配置解析）
├── include/             # 公共头文件（零号头 config.h 在此）
├── sdk/
│   ├── wasm/neura_client.c   # 浏览器端 C 模块（编译为 wasm）
│   ├── neura.js              # 浏览器客户端（WASM 加解密 + pin 校验）
│   ├── index.html            # 用户入口 shell
│   └── test_*.mjs            # node 端端到端验证（跑同一份 JS/WASM）
├── tools/
│   ├── neura_gateway.c       # 本地客户端网关
│   └── neura_browser_edge.c  # 80 端口浏览器边缘
├── tests/
│   ├── neura_probe.c         # 探针（压测 + 断言矩阵）
│   ├── upstream_stub.c       # 纯 C 上游桩
│   ├── link_check.c          # 链接/自检
│   └── e2e_handshake.c       # 双 reactor 端到端握手
├── config/              # config.ncf + presets（baseline / anti_cc）
├── Makefile             # 双模式构建 + 工具 + 断言/压测目标
├── install.sh           # 一键安装（systemd、Nginx 注入与回滚）
├── LICENSE              # AGPL-3.0 全文
├── CLA.md               # 贡献者许可协议（个人 + 实体）
├── CONTRIBUTING.md      # 贡献流程、代码规范、门禁
├── SECURITY.md          # 漏洞私密报告流程
├── .github/             # CLA Assistant 工作流 + PR 模板
└── REQUIREMENTS.md      # 架构与需求规格
```

---

## 安全说明与已知限制

**已实现的安全性质**

- 传输层密钥协商不依赖任何长期密钥的传输；浏览器/客户端侧没有 RootKey 可偷；
- 抗量子（ML-KEM-768 + X25519 双腿），棘轮保证前向保密；
- 棘轮切换有 1000 ms 在途帧宽限期，且**只放宽一代、只放宽收方向、不放宽 seq/AEAD 校验**；
- 公钥调包会被指纹 pin 拦截（有自动化用例验证）。

**必须了解的边界（诚实清单）**

1. **首次信任**：`/`、`/neura.js`、`.wasm` 本身经明文 HTTP 下发。若攻击者在**首次加载**时篡改 shell，可绕过加密（与 TLS 的首次信任问题是同一类）。闭环方式：把指纹写进书签/SRI，或用 DNS TXT + DNSSEC 公布指纹（`REQUIREMENTS.md §3.2` 的目标，DoH 尚未实现）。
2. **子资源**：示例页面把 CSS/JS 内联，因此整页密文；外链图片/样式会走明文，完整方案需要 Service Worker 拦截（见路线图）。
3. **边缘↔上游**：`neura-browser-edge` 到上游是明文（同机/内网），可再套一层 Safe-HTTP 加密监听做二段加密。
4. **浏览器 E2E**：CI/开发环境无 GUI 浏览器，用 node 执行**同一份** `neura.js` + `.wasm` 验证协议路径；真实浏览器的渲染与 Service Worker 行为尚未做浏览器矩阵测试。
5. **会话管理**：浏览器边缘会话 TTL 120 s、上限 128 个、串行处理，未做连接复用与并发优化。
6. **信任锚 DoH/DNSSEC**：`--require-trust-anchor` 在 DoH 未实现时会拒绝启动（设计如此）。

---

## 路线图

- [ ] Service Worker 全站拦截：图片 / CSS / XHR 一并走密文
- [ ] DNS TXT + DNSSEC 指纹锚定（DoH 解析），补上首次信任闭环
- [ ] 浏览器通道会话复用与并发（去掉逐请求握手）
- [ ] STANDALONE 模式静态文件与 API 路由完善
- [ ] CI：`headers-check` / `link-check` / `e2e-check` / `verify` 全绿门禁

---

## 许可证与服务端义务

本项目以 **GNU Affero General Public License v3.0（AGPL-3.0）** 发布，
完整条款见 [`LICENSE`](LICENSE)。Copyright (C) 2026 **Neura-L**（Safe-HTTP Project）

### AGPL-3.0 对你意味着什么

| 使用方式 | 义务 |
|---|---|
| 自用 / 内部部署（不对外提供网络服务） | 无额外义务，可自由修改 |
| **作为网络服务对外提供**（SaaS、在线网关等） | **第 13 条**：必须向使用者提供**对应源码**（含你的修改），并提供获取方式 |
| 分发二进制 / 镜像 | 必须附许可证与源码获取方式 |
| 修改后分发 | 修改部分同样以 AGPL-3.0 授权 |

对 Safe-HTTP 而言，"对应源码"包括：本仓库代码 + 你对 `src/`、`include/`、
`tools/`、`sdk/` 的修改。建议在服务页面底部放置源码链接，例如：

```html
<a href="https://github.com/<your-org>/safe-http">本站基于 Safe-HTTP（AGPL-3.0），源码在此</a>
```

### 商业授权

AGPL-3.0 的强著佐权不适合闭源集成场景。如需在闭源产品中嵌入本项目，
可联系项目方获取**商业许可证**（这正是需要 CLA 中的"可再许可"授权的原因）。

### 贡献与 CLA

提交代码、文档或配置前需签署 [`CLA.md`](CLA.md)：

- **个人**：在首个 PR 下评论
  `I have read the CLA Document and I hereby sign the CLA`；
- **公司/组织**：填写 `CLA.md` 第二部分，由授权代表签署并邮件发送。

PR 提交后由 **CLA Assistant** 自动校验（见 `.github/workflows/cla.yml`）：
未签署的 PR 会被状态检查阻塞，签署记录写入 `cla-signatures` 分支的 `signatures/cla.json`。

CLA **不转让版权**，你仍拥有自己贡献的著作权；它只授予项目方一份范围较宽的、
可再许可的许可，以便项目方进行双许可/商业授权。

### 第三方组件

- **libsodium**（ISC 许可，vendored 源码位于 libs2s 仓库 `third_party/`）；
- **libs2s / Neura-S2S**（许可证以上游仓库声明为准）。

分发二进制时请一并保留上述组件的许可证与版权声明。
