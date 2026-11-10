# Safe-HTTP 核心架构与开发需求规格说明书 (v1.0)

## 1. 项目背景
Safe-HTTP 是一个基于 Neura-S2S 抗量子加密协议和 MatchLang 规则引擎的开源安全 Web 网关。旨在为无 SSL 证书、纯 HTTP 环境、内网设备提供工业级的端到端加密、防 CC 攻击及极速路由功能。

## 2. 核心架构：双模式条件编译
项目必须在编译期决定运行模式，通过 C 语言宏（#ifdef）实现代码的绝对隔离，确保零冗余、零攻击面。

*   Standalone 模式（独立模式）：make MODE=STANDALONE。直接监听 80/443 端口，替代 Nginx/Apache，内部处理静态文件与 API 路由。
*   Proxy 模式（网关模式）：make MODE=PROXY。监听 127.0.0.1:5362，作为反向代理挂在现有 Nginx/Apache 之前，负责解密、WAF 过滤，再将明文转发给上游。

## 3. 核心组件规范

### 3.1 config.ncf 语法设计 (用户配置)
由 MatchLang 引擎极速解析（禁止使用 PCRE 正则）。

# 1. 强制加密路由
Encrypt API Traffic {
    Path Match: starts_with "/api/";
    Action: enforce_neura_s2s;
}

# 2. URL 重写
Rewrite URL Like {
    using engine matchlang;
    pattern: Locate "/user/" until "/" as $id {
        Replace with "/profile?id={$id}";
    }
}

# 3. 防 CC 与 WAF
Ban "anti_cc" {
    Checker: IP;
    Trigger: Frequency;
    Condition: More Than 5 Per 1s;
    Action: drop_connection;
}

Ban "block_scanner" {
    Checker: User-Agent;
    Match: contains "sqlmap" or contains "nikto";
    Trigger: Visit;          # 访问即封禁
    Condition: Immediately;
    Action: drop_connection;
}

### 3.2 安全与加密模块
*   底层引擎：集成纯 C 编写的 Neura-S2S 库（静态链接）。
*   抗量子握手：X25519 + ML-KEM-768。
*   棘轮机制：0.3s 极速 KEM 重置。
*   信任锚定：客户端/服务端通过 DNS TXT 记录（DoH 查询）+ DNSSEC 验证首次连接公钥指纹。

### 3.3 网络层 (epoll)
*   统一使用 epoll 边缘触发（ET）模式。
*   实现 LRU 哈希表配合滑动窗口算法，支撑高并发下的 Ban 规则（限流与黑名单）。
*   Proxy 模式下实现非阻塞的 Upstream 转发。

## 4. 前端 SDK 规范 (WASM)
*   sdk/safe-http.js：拦截全局 fetch。
*   sdk/sw.js：利用 Service Worker 隔离加密环境，防 XSS 窃取。
*   sdk/neura-crypto.wasm：由纯 C 编译，负责实际的加解密与 MatchLang 执行。

## 5. 安装脚本 install.sh 规范
一键无脑安装，对生产环境保持敬畏。

1. 模式选择：交互式选择 Standalone 或 Proxy，自动调用对应的 make 命令并清理编译产物。
2. 环境依赖处理：
   - 若选 Standalone：自动检查并停止系统现有的 Nginx/Apache。
   - 若选 Proxy：自动探测 Nginx 配置文件路径。
3. 安全注入与回滚：
   - 修改 Nginx 配置前，自动备份（.bak）。
   - 使用 # BEGIN NEURA S2S 和 # END NEURA S2S 包裹注入的反向代理规则。
   - 执行 nginx -t 进行语法检查。若失败，立刻回滚备份并报错。
   - 提供 force install 参数：允许强制重写整个配置文件（警告用户会丢失旧配置）。
4. 系统服务隔离：
   - 生成 Systemd 服务，必须指定低权限用户（如 www 或 neura）。
   - 配置 NoNewPrivileges=true、PrivateTmp=true。
5. 收尾：打印绿色成功信息，输出服务器公钥指纹，提示用户去配置 DNS TXT 记录。

## 6. 代码目录结构要求
Safe-HTTP/
├── README.md               # 项目核心文档
├── install.sh              # 一键安装脚本
├── Makefile                # 支持条件编译
├── include/                # C 头文件 (config.h, network.h, security.h)
├── src/
│   ├── main.c              # 入口，条件编译隔离
│   ├── reactor.c           # epoll 网络循环
│   ├── config_parser.c     # MatchLang 解析 .ncf
│   ├── waf.c               # Ban 规则与 LRU 限流
│   └── neura_proxy.c       # Neura-S2S 握手与数据转发
├── sdk/                    # 前端 SDK
│   ├── safe-http.js
│   ├── sw.js
│   └── neura-crypto.wasm
└── config/
    └── config.ncf          # 示例配置
