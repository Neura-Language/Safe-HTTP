# =============================================================================
# Safe-HTTP — 双模式条件编译构建系统
#
#   make MODE=STANDALONE          # 独立模式：直接监听 80/443
#   make MODE=PROXY               # 网关模式：监听 127.0.0.1:5362 反代上游
#   make MODE=PROXY NEURA_PROFILE=asan   # 链接 ASan 版 libs2s（自己也要 SANITIZE=1）
#   make both                     # 两种模式都编译（CI 用）
#   make headers-check            # 仅语法检查全部头文件（两种模式）
#   make link-check               # 编译+链接+运行加密层自检（不需要 main.c）
#   make wasm                     # 编译 sdk/neura-crypto.wasm（需要 emcc）
#   make install                  # 安装到 PREFIX
#   make clean / distclean
#
# 加密层事实来源：$(NEURA_ROOT)（默认 /opt/neura/c-s2s）
#   - 头文件  : $(NEURA_ROOT)/include/neura/*.h
#   - 发布库  : $(NEURA_ROOT)/build-release/libs2s.a   （无 sanitizer）
#   - 调试库  : $(NEURA_ROOT)/build/libs2s.a           （ASan+UBSan）
#   - 依赖    : libsodium 1.0.22 静态库（vendored 在 third_party/libsodium）
#
# 关键约束：一次 make 只产出一种模式的二进制；两种模式的目标文件
# 分别落在 build/standalone 与 build/proxy，互不污染。
# =============================================================================

SHELL := /bin/sh

PROJECT   := safe-http
MODE      ?= STANDALONE
MODE_LC   := $(shell printf '%s' '$(MODE)' | tr '[:upper:]' '[:lower:]')
MODE_UC   := $(shell printf '%s' '$(MODE)' | tr '[:lower:]' '[:upper:]')

# -----------------------------------------------------------------------------
# 模式校验与条件编译宏（与 include/config.h 保持一致）
# -----------------------------------------------------------------------------
ifeq ($(MODE_UC),STANDALONE)
  MODE_DEFINES  := -DSAFE_HTTP_STANDALONE=1
  MODE_TAG      := standalone
  MODE_PORT     := 80
else ifeq ($(MODE_UC),PROXY)
  MODE_DEFINES  := -DSAFE_HTTP_PROXY=1
  MODE_TAG      := proxy
  MODE_PORT     := 5362
else
  $(error MODE 必须为 STANDALONE 或 PROXY（当前为 '$(MODE)'）；用法: make MODE=STANDALONE | make MODE=PROXY)
endif

# -----------------------------------------------------------------------------
# 目录与产物
# -----------------------------------------------------------------------------
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
SYSCONFDIR  ?= /etc/safe-http
UNITDIR     ?= /usr/lib/systemd/system
DESTDIR     ?=

BUILD_ROOT  := build
BUILD_DIR   := $(BUILD_ROOT)/$(MODE_TAG)
OBJ_DIR     := $(BUILD_DIR)/obj
BIN         := $(BUILD_DIR)/$(PROJECT)
UNIT_SRC    := deploy/safe-http.service

SRCS        := $(wildcard src/*.c)
OBJS        := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS        := $(OBJS:.o=.d)
# 测试可执行文件（link-check / e2e-check）自带 main()，必须排除 src/main.o，
# 否则 libc 会报 "multiple definition of `main'". 保持 src/main.c 干净，
# 不用 -DSH_NO_MAIN 之类的条件编译。
OBJS_NOMAIN := $(filter-out $(OBJ_DIR)/main.o,$(OBJS))

# -----------------------------------------------------------------------------
# Neura-S2S（libs2s）依赖
# -----------------------------------------------------------------------------
NEURA_ROOT    ?= /opt/neura/c-s2s
NEURA_PROFILE ?= release

ifeq ($(NEURA_PROFILE),release)
  NEURA_BUILD   := build-release
  NEURA_SAN     :=
else ifeq ($(NEURA_PROFILE),asan)
  NEURA_BUILD   := build
  NEURA_SAN     := -fsanitize=address,undefined -fno-omit-frame-pointer
else
  $(error NEURA_PROFILE 必须为 release 或 asan（当前为 '$(NEURA_PROFILE)'））
endif

NEURA_LIB       := $(NEURA_ROOT)/$(NEURA_BUILD)/libs2s.a
NEURA_INC       := $(NEURA_ROOT)/include
LIBSODIUM_ROOT  ?= $(NEURA_ROOT)/third_party/libsodium
LIBSODIUM_LIB   := $(LIBSODIUM_ROOT)/lib/libsodium.a
LIBSODIUM_INC   := $(LIBSODIUM_ROOT)/include

# -----------------------------------------------------------------------------
# 工具链
# -----------------------------------------------------------------------------
CC          ?= cc
INSTALL     ?= install
WASM_CC     ?= emcc

WERROR      ?= 0
DEBUG       ?= 0
SANITIZE    ?= 0

# -----------------------------------------------------------------------------
# 编译/链接参数
# -----------------------------------------------------------------------------
CPPFLAGS += -Iinclude -I$(NEURA_INC) -I$(LIBSODIUM_INC) \
            -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 $(MODE_DEFINES)

BASE_CFLAGS := -std=c11 -Wall -Wextra -Wshadow -Wpointer-arith \
               -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
               -Wformat=2 -Wno-unused-parameter -fno-strict-aliasing \
               -fstack-protector-strong -fstack-clash-protection -fPIE

ifeq ($(DEBUG),1)
  BASE_CFLAGS += -O0 -g3 -DDEBUG=1
else
  BASE_CFLAGS += -O2 -g -DNDEBUG -D_FORTIFY_SOURCE=2
endif

ifeq ($(WERROR),1)
  BASE_CFLAGS += -Werror
endif

ifeq ($(SANITIZE),1)
  BASE_CFLAGS += -O1 -g $(NEURA_SAN)
  MODE_LDFLAGS += -fsanitize=address,undefined
endif

# NEURA_PROFILE=asan 时即使没开 SANITIZE 也必须带 sanitizer 运行时，
# 否则链接 libs2s.a 里的 __asan_* 会 undefined。
ifeq ($(NEURA_PROFILE),asan)
  ifneq ($(SANITIZE),1)
    $(warning [safe-http] NEURA_PROFILE=asan：自动追加 -fsanitize=address,undefined)
    BASE_CFLAGS += $(NEURA_SAN)
    MODE_LDFLAGS += -fsanitize=address,undefined
  endif
endif

CFLAGS  += $(BASE_CFLAGS)
LDFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie $(MODE_LDFLAGS)
LDLIBS  += $(NEURA_LIB) $(LIBSODIUM_LIB) -lpthread -lm

# 启用 sanitizer 时先探测运行时是否真的存在（容器/精简工具链常缺）
SAN_PREREQ := $(if $(findstring -fsanitize,$(MODE_LDFLAGS)),check-sanitize,)

# -----------------------------------------------------------------------------
# 默认目标
# -----------------------------------------------------------------------------
.PHONY: all
all: $(BIN)
	@printf '\033[32m[%s]\033[0m 构建完成: %s (MODE=%s, NEURA=%s)\n' \
	    "$(PROJECT)" "$(BIN)" "$(MODE_UC)" "$(NEURA_PROFILE)"

# -----------------------------------------------------------------------------
# 依赖检查：库缺失时给出可执行的提示，而不是裸链接错误
# -----------------------------------------------------------------------------
.PHONY: check-neura
check-neura:
	@miss=0; \
	for f in "$(NEURA_LIB)" "$(LIBSODIUM_LIB)"; do \
	    [ -f "$$f" ] || { printf '\033[31m缺失:\033[0m %s\n' "$$f"; miss=1; }; \
	done; \
	if [ $$miss -ne 0 ]; then \
	    printf '\033[31m错误:\033[0m Neura-S2S 依赖不完整\n'; \
	    printf '      1) 构建发布库: (cd %s && make release)\n' "$(NEURA_ROOT)"; \
	    printf '      2) 构建 libsodium: (cd %s && make libsodium)\n' "$(NEURA_ROOT)"; \
	    printf '      3) 或指定路径: make NEURA_ROOT=/path/to/c-s2s\n'; \
	    exit 1; \
	fi; \
	[ -d "$(NEURA_INC)/neura" ] || { printf '\033[31m错误:\033[0m 找不到 %s/neura\n' "$(NEURA_INC)"; exit 1; }

.PHONY: check-sanitize
check-sanitize:
	@mkdir -p $(BUILD_DIR)
	@printf 'int main(void){return 0;}\n' > $(BUILD_DIR)/san_probe.c
	@$(CC) $(BASE_CFLAGS) $(BUILD_DIR)/san_probe.c -o $(BUILD_DIR)/san_probe \
	    $(MODE_LDFLAGS) 2>/dev/null || { \
	    rm -f $(BUILD_DIR)/san_probe.c; \
	    printf '\033[31m错误:\033[0m 当前工具链缺少 sanitizer 运行时（libasan/libubsan）\n'; \
	    printf '        可选方案：\n'; \
	    printf '          make ... NEURA_PROFILE=release    # 生产/普通调试\n'; \
	    printf '          或安装运行时：dnf install libasan libubsan\n'; \
	    exit 1; }
	@rm -f $(BUILD_DIR)/san_probe $(BUILD_DIR)/san_probe.c

check-main:
	@test -f src/main.c || { \
	    printf '\033[33m[暂停]\033[0m src/main.c 尚未实现（当前阶段只到骨架）。\n'; \
	    printf '        可先执行: make headers-check / make link-check\n'; \
	    exit 1; }

# -----------------------------------------------------------------------------
# 编译
# -----------------------------------------------------------------------------
$(BIN): $(OBJS) | check-neura check-main $(SAN_PREREQ)
	@printf '[LD] %s\n' "$@"
	@$(CC) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@
	@printf '[OK] %s (%s)\n' "$@" "$(MODE_UC)"

$(OBJ_DIR)/%.o: src/%.c | $(OBJ_DIR)
	@printf '[CC] %s\n' "$<"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

-include $(DEPS)

# -----------------------------------------------------------------------------
# 头文件自检：两种模式下逐个头文件独立编译（不需要 libs2s 也能跑）
# -----------------------------------------------------------------------------
.PHONY: headers-check
headers-check:
	@mkdir -p $(BUILD_ROOT)
	@for mode in STANDALONE PROXY; do \
	    def=$$( [ "$$mode" = "STANDALONE" ] && echo -DSAFE_HTTP_STANDALONE=1 || echo -DSAFE_HTTP_PROXY=1 ); \
	    for h in config.h util.h log.h network.h security.h http.h \
	             config_parser.h waf.h neura_proxy.h standalone.h safe_http.h; do \
	        printf '#include "%s"\n' "$$h" > $(BUILD_ROOT)/hdr_probe.c; \
	        $(CC) -std=c11 -D_GNU_SOURCE $$def \
	            -Iinclude -I$(NEURA_INC) -I$(LIBSODIUM_INC) \
	            -Wall -Wextra -Werror -fsyntax-only $(BUILD_ROOT)/hdr_probe.c || { \
	                printf '\033[31m[FAIL]\033[0m %s (%s)\n' "$$h" "$$mode"; exit 1; }; \
	    done; \
	    printf '\033[32m[OK]\033[0m 11 个头文件 (%s)\n' "$$mode"; \
	done
	@rm -f $(BUILD_ROOT)/hdr_probe.c

# -----------------------------------------------------------------------------
# 链接自检：编译 src/*.c + tests/link_check.c，链接 libs2s.a + libsodium.a 并运行。
# 验证：头文件 ABI、库路径、libsodium 版本、secure_alloc(mlock+DONTDUMP)、
#       SHA-512 锚点指纹派生（布局与 install.sh 的 openssl 复算一致）。
# -----------------------------------------------------------------------------
.PHONY: link-check
link-check: $(OBJS) tests/link_check.c | check-neura $(SAN_PREREQ)
	@mkdir -p $(BUILD_DIR)
	@printf '[CC] tests/link_check.c\n'
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c tests/link_check.c -o $(BUILD_DIR)/link_check.o
	@printf '[LD] link-check (libs2s.a + libsodium.a)\n'
	@$(CC) $(OBJS_NOMAIN) $(BUILD_DIR)/link_check.o $(LDFLAGS) $(LDLIBS) \
	    -o $(BUILD_DIR)/link-check
	@printf '\033[32m[RUN]\033[0m %s/link-check\n' "$(BUILD_DIR)"
	@$(BUILD_DIR)/link-check

# -----------------------------------------------------------------------------
# 端到端测试：两个 reactor（服务端/客户端）真实 epoll + TCP + KEM worker，
# 跑通 hello/ack/finish/ready → 明文回显 → 0.3s 棘轮。
# -----------------------------------------------------------------------------
.PHONY: e2e-check
e2e-check: $(OBJS) tests/e2e_handshake.c | check-neura $(SAN_PREREQ)
	@mkdir -p $(BUILD_DIR)
	@printf '[CC] tests/e2e_handshake.c\n'
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c tests/e2e_handshake.c -o $(BUILD_DIR)/e2e_handshake.o
	@printf '[LD] e2e (libs2s.a + libsodium.a)\n'
	@$(CC) $(OBJS_NOMAIN) $(BUILD_DIR)/e2e_handshake.o $(LDFLAGS) $(LDLIBS) \
	    -o $(BUILD_DIR)/e2e-handshake
	@printf '\033[32m[RUN]\033[0m %s/e2e-handshake\n' "$(BUILD_DIR)"
	@$(BUILD_DIR)/e2e-handshake

# -----------------------------------------------------------------------------
# Neura-S2S 客户端探针：真实加密通道联调（不参与 make check，按需构建）
#   build/<mode>/neura-probe --host H --port P --root-key FILE --path /echo
# -----------------------------------------------------------------------------
.PHONY: neura-probe
neura-probe: $(OBJS_NOMAIN) tests/neura_probe.c | check-neura $(SAN_PREREQ)
	@mkdir -p $(BUILD_DIR)
	@printf '[CC] tests/neura_probe.c\n'
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c tests/neura_probe.c -o $(BUILD_DIR)/neura_probe.o
	@printf '[LD] neura-probe\n'
	@$(CC) $(OBJS_NOMAIN) $(BUILD_DIR)/neura_probe.o $(LDFLAGS) $(LDLIBS) \
	    -o $(BUILD_DIR)/neura-probe
	@printf '\033[32m[OK]\033[0m %s/neura-probe\n' "$(BUILD_DIR)"

# -----------------------------------------------------------------------------
# 浏览器边缘接入（80 端口）：WASM 客户端 + 会话级密钥协商 + 加密取页
#   make MODE=PROXY neura-browser-edge
#   build/<mode>/neura-browser-edge --listen 0.0.0.0:80 \
#       --upstream 127.0.0.1:19080 --host test.jqlhtm.cn \
#       --sdk-dir build/sdk --page sdk/index.html --id /etc/safe-http/id.xwing
# -----------------------------------------------------------------------------
.PHONY: neura-browser-edge
neura-browser-edge: $(OBJS_NOMAIN) tools/neura_browser_edge.c | check-neura $(SAN_PREREQ)
	@mkdir -p $(BUILD_DIR)
	@printf '[CC] tools/neura_browser_edge.c\n'
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c tools/neura_browser_edge.c \
	    -o $(BUILD_DIR)/neura_browser_edge.o
	@printf '[LD] neura-browser-edge\n'
	@$(CC) $(OBJS_NOMAIN) $(BUILD_DIR)/neura_browser_edge.o $(LDFLAGS) $(LDLIBS) \
	    -o $(BUILD_DIR)/neura-browser-edge
	@printf '\033[32m[OK]\033[0m %s/neura-browser-edge\n' "$(BUILD_DIR)"

# -----------------------------------------------------------------------------
# 浏览器端 SDK：把 Neura-S2S 编成 WebAssembly（wasm32-wasi）
#   依赖 wasi-sdk（默认 /opt/wasi-sdk-24.0-x86_64-linux）与已为 wasm 编好的
#   libsodium（libs2s/third_party/libsodium-src 里 configure --host=wasm32-wasi）。
#   make MODE=PROXY sdk-wasm
# -----------------------------------------------------------------------------
WASI_SDK   ?= /opt/wasi-sdk-24.0-x86_64-linux
S2S_ROOT   ?= /opt/neura/c-s2s
SODIUM_WASM_SRC ?= $(S2S_ROOT)/third_party/libsodium-src
WASM_BLD   := $(BUILD_ROOT)/sdk
WASI_CC    := $(WASI_SDK)/bin/clang
WASI_CFLAGS := --target=wasm32-wasi -O2 -DNDEBUG \
    -I$(S2S_ROOT)/include \
    -I$(SODIUM_WASM_SRC)/src/libsodium/include \
    -I$(SODIUM_WASM_SRC)/include
WASM_OBJS  := $(WASM_BLD)/s2s_crypto.o $(WASM_BLD)/s2s_frame.o \
              $(WASM_BLD)/s2s_session.o $(WASM_BLD)/neura_client.o

.PHONY: sdk-wasm
sdk-wasm:
	@mkdir -p $(WASM_BLD)
	@printf '[WASM] s2s core + client shim\n'
	@$(WASI_CC) $(WASI_CFLAGS) -c $(S2S_ROOT)/src/s2s_crypto.c -o $(WASM_BLD)/s2s_crypto.o
	@$(WASI_CC) $(WASI_CFLAGS) -c $(S2S_ROOT)/src/s2s_frame.c -o $(WASM_BLD)/s2s_frame.o
	@$(WASI_CC) $(WASI_CFLAGS) -c $(S2S_ROOT)/src/s2s_session.c -o $(WASM_BLD)/s2s_session.o
	@$(WASI_CC) $(WASI_CFLAGS) -c sdk/wasm/neura_client.c -o $(WASM_BLD)/neura_client.o
	@printf '[WASM] link neura-crypto.wasm\n'
	@$(WASI_CC) --target=wasm32-wasi -Wl,--no-entry -Wl,--allow-undefined \
	    -Wl,--export=nw_init -Wl,--export=nw_boot -Wl,--export=nw_finish \
	    -Wl,--export=nw_seal -Wl,--export=nw_open -Wl,--export=nw_fp \
	    -Wl,--export=nw_scratch -Wl,--export=nw_scratch_max \
	    -Wl,--export=malloc -Wl,--export=free \
	    -o $(WASM_BLD)/neura-crypto.wasm \
	    $(WASM_OBJS) $(SODIUM_WASM_SRC)/src/libsodium/.libs/libsodium.a
	@printf '\033[32m[OK]\033[0m %s/neura-crypto.wasm\n' "$(WASM_BLD)"
#   浏览器/curl --明文--> gateway --Neura-S2S--> 站点
#   make MODE=PROXY neura-gateway
#   build/<mode>/neura-gateway --listen 127.0.0.1:8899 --server 127.0.0.1:18081 \
#       --root-key /etc/safe-http/rootkey.hex --host test.jqlhtm.cn
# -----------------------------------------------------------------------------
.PHONY: neura-gateway
neura-gateway: $(OBJS_NOMAIN) tools/neura_gateway.c | check-neura $(SAN_PREREQ)
	@mkdir -p $(BUILD_DIR)
	@printf '[CC] tools/neura_gateway.c\n'
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c tools/neura_gateway.c -o $(BUILD_DIR)/neura_gateway.o
	@printf '[LD] neura-gateway\n'
	@$(CC) $(OBJS_NOMAIN) $(BUILD_DIR)/neura_gateway.o $(LDFLAGS) $(LDLIBS) \
	    -o $(BUILD_DIR)/neura-gateway
	@printf '\033[32m[OK]\033[0m %s/neura-gateway\n' "$(BUILD_DIR)"

# -----------------------------------------------------------------------------
# 纯 C 上游测试桩（替代 /tmp/up.py；单次 write 输出 + TCP_NODELAY，
# 避免 Python http.server 的 Nagle/延迟 ACK 造成 ~40ms 假尖峰）
#   make MODE=PROXY upstream-stub
#   build/<mode>/upstream-stub --listen 127.0.0.1:19080
# -----------------------------------------------------------------------------
.PHONY: upstream-stub
upstream-stub:
	@mkdir -p $(BUILD_DIR)
	@printf '[CC] tests/upstream_stub.c\n'
	@$(CC) $(CPPFLAGS) -O2 -g -Wall -Wextra tests/upstream_stub.c \
	    -o $(BUILD_DIR)/upstream-stub
	@printf '\033[32m[OK]\033[0m %s/upstream-stub\n' "$(BUILD_DIR)"

# -----------------------------------------------------------------------------
# 纯 C 断言验证（取代已废弃删除的 scripts/verify-crypto.sh）
#   明文/加密矩阵断言 + 状态码 + P50 延迟，全部由 neura-probe 自己完成，
#   不使用 shell/python/jq 解析响应。
#   make MODE=PROXY verify
#   make MODE=PROXY verify VERIFY_PORT=18443
# -----------------------------------------------------------------------------
VERIFY_HOST     ?= 127.0.0.1
VERIFY_PORT     ?= 18081
VERIFY_HOST_HDR ?= test.jqlhtm.cn
VERIFY_ROOT_KEY ?= /etc/safe-http/rootkey.hex
BENCH_LOOP      ?= 100
BENCH_WARMUP    ?= 10

# verify：确定性断言（状态码 + neura 字段），每次都应全绿
.PHONY: verify
verify: neura-probe
	@$(BUILD_DIR)/neura-probe --suite \
	    --host $(VERIFY_HOST) --port $(VERIFY_PORT) \
	    --host-header $(VERIFY_HOST_HDR) --root-key $(VERIFY_ROOT_KEY)

# bench：加密通道稳态延迟（P50/P90/P99）。注意：长时间 keep-alive 会
#   命中服务端棘轮期的解密抖动（已知缺陷，见 SH_RATCHET_GRACE_MS 未实现），
#   本目标只做测量，不参与 verify 断言。
.PHONY: bench
bench: neura-probe
	@$(BUILD_DIR)/neura-probe \
	    --host $(VERIFY_HOST) --port $(VERIFY_PORT) \
	    --host-header $(VERIFY_HOST_HDR) --root-key $(VERIFY_ROOT_KEY) \
	    --path /echo --loop $(BENCH_LOOP) --warmup $(BENCH_WARMUP) \
	    --assert-neura --expect-status 200


# -----------------------------------------------------------------------------
# 两种模式全量编译（发布前/CI 使用）
# -----------------------------------------------------------------------------

.PHONY: both
both:
	@$(MAKE) --no-print-directory MODE=STANDALONE all
	@$(MAKE) --no-print-directory MODE=PROXY all

# -----------------------------------------------------------------------------
# WASM SDK（纯 C -> wasm32，供 sdk/neura-crypto.wasm 使用）
# -----------------------------------------------------------------------------
WASM_OUT  := sdk/neura-crypto.wasm
WASM_SRCS := $(wildcard src/wasm/*.c)
WASM_EXPORTS := '["_sh_wasm_init","_sh_wasm_handshake","_sh_wasm_seal","_sh_wasm_open","_sh_wasm_matchlang_eval","_malloc","_free"]'

.PHONY: wasm
wasm:
	@command -v $(WASM_CC) >/dev/null 2>&1 || { \
	    printf '\033[33m跳过 wasm:\033[0m 未找到 %s（安装 emsdk 后重试）\n' "$(WASM_CC)"; \
	    exit 1; }
	@test -n "$(WASM_SRCS)" || { \
	    printf '\033[33m跳过 wasm:\033[0m src/wasm/*.c 尚未创建\n'; exit 1; }
	@printf '[WASM] %s\n' "$(WASM_OUT)"
	@$(WASM_CC) $(WASM_SRCS) -Iinclude -DSAFE_HTTP_WASM=1 \
	    -O3 -flto -s STANDALONE_WASM=1 -s WASM=1 \
	    -s EXPORTED_FUNCTIONS=$(WASM_EXPORTS) \
	    -s ALLOW_MEMORY_GROWTH=1 -s INITIAL_MEMORY=1048576 \
	    -s FILESYSTEM=0 --no-entry \
	    -o $(WASM_OUT)
	@printf '\033[32m[OK]\033[0m %s\n' "$(WASM_OUT)"

.PHONY: sdk-check
sdk-check:
	@for f in sdk/safe-http.js sdk/sw.js; do \
	    if [ -f "$$f" ]; then printf '[SDK] %s\n' "$$f"; \
	    else printf '\033[33m[WARN]\033[0m 缺少 %s\n' "$$f"; fi; \
	done
	@if command -v node >/dev/null 2>&1; then \
	    for f in sdk/safe-http.js sdk/sw.js; do \
	        [ -f "$$f" ] && node --check "$$f" && printf '[SDK] %s 语法正确\n' "$$f"; \
	    done; \
	fi

# -----------------------------------------------------------------------------
# 测试
# -----------------------------------------------------------------------------
.PHONY: test
test:
	@if [ -x tests/run_tests.sh ]; then tests/run_tests.sh; \
	else printf '\033[33m[WARN]\033[0m tests/run_tests.sh 不存在，跳过\n'; fi

# -----------------------------------------------------------------------------
# 安装（install.sh 会调用本目标，也可手工执行）
# -----------------------------------------------------------------------------
.PHONY: install
install: all
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 "$(BIN)" "$(DESTDIR)$(BINDIR)/$(PROJECT)"
	@if [ -f config/config.ncf ]; then \
	    $(INSTALL) -d "$(DESTDIR)$(SYSCONFDIR)"; \
	    if [ -f "$(DESTDIR)$(SYSCONFDIR)/config.ncf" ]; then \
	        printf '\033[33m[跳过]\033[0m 已存在 %s/config.ncf，未覆盖\n' "$(DESTDIR)$(SYSCONFDIR)"; \
	    else \
	        $(INSTALL) -m 0640 config/config.ncf "$(DESTDIR)$(SYSCONFDIR)/config.ncf"; \
	        printf '[INSTALL] $(DESTDIR)$(SYSCONFDIR)/config.ncf\n'; \
	    fi; \
	else \
	    printf '\033[33m[WARN]\033[0m config/config.ncf 不存在，跳过配置安装\n'; \
	fi
	@if [ -f "$(UNIT_SRC)" ]; then \
	    $(INSTALL) -d "$(DESTDIR)$(UNITDIR)"; \
	    sed -e 's|@BINDIR@|$(BINDIR)|g' -e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' \
	        "$(UNIT_SRC)" > "$(DESTDIR)$(UNITDIR)/$(PROJECT).service"; \
	    printf '[INSTALL] $(DESTDIR)$(UNITDIR)/$(PROJECT).service\n'; \
	fi
	@printf '\033[32m[OK]\033[0m 安装完成: $(DESTDIR)$(BINDIR)/$(PROJECT) (MODE=%s)\n' "$(MODE_UC)"

.PHONY: uninstall
uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(PROJECT)"
	rm -f "$(DESTDIR)$(UNITDIR)/$(PROJECT).service"
	@printf '[OK] 已卸载二进制与 systemd 单元（保留 %s 下的配置）\n' "$(DESTDIR)$(SYSCONFDIR)"

# -----------------------------------------------------------------------------
# 清理
# -----------------------------------------------------------------------------
.PHONY: clean
clean:
	@rm -rf "$(BUILD_DIR)"
	@printf '[OK] 已清理 build/%s\n' "$(MODE_TAG)"

.PHONY: distclean
distclean:
	@rm -rf "$(BUILD_ROOT)" sdk/neura-crypto.wasm
	@printf '[OK] 已清理全部构建产物\n'

# -----------------------------------------------------------------------------
# 辅助目标
# -----------------------------------------------------------------------------
.PHONY: print-config
print-config:
	@printf 'PROJECT        = %s\n' "$(PROJECT)"
	@printf 'MODE           = %s (%s)\n' "$(MODE_UC)" "$(MODE_TAG)"
	@printf 'BUILD_DIR      = %s\n' "$(BUILD_DIR)"
	@printf 'BIN            = %s\n' "$(BIN)"
	@printf 'CC             = %s\n' "$(CC)"
	@printf 'CPPFLAGS       = %s\n' "$(CPPFLAGS)"
	@printf 'CFLAGS         = %s\n' "$(CFLAGS)"
	@printf 'LDFLAGS        = %s\n' "$(LDFLAGS)"
	@printf 'LDLIBS         = %s\n' "$(LDLIBS)"
	@printf 'NEURA_ROOT     = %s\n' "$(NEURA_ROOT)"
	@printf 'NEURA_PROFILE  = %s -> %s%s\n' "$(NEURA_PROFILE)" "$(NEURA_BUILD)" \
	    "$(if $(wildcard $(NEURA_LIB)),, (缺失!) )"
	@printf 'LIBSODIUM      = %s%s\n' "$(LIBSODIUM_LIB)" \
	    "$(if $(wildcard $(LIBSODIUM_LIB)),, (缺失!) )"
	@printf 'SRCS           = %s\n' "$(SRCS)"

.PHONY: config-check
config-check: all
	@if [ -f config/config.ncf ]; then \
	    "$(BIN)" --check-config config/config.ncf; \
	else \
	    printf '\033[33m[WARN]\033[0m config/config.ncf 不存在\n'; fi

.PHONY: check
check: headers-check link-check e2e-check

.PHONY: help
help:
	@printf '%s %s — 双模式条件编译\n\n' "$(PROJECT)" "1.0.0"
	@printf '用法: make MODE=<STANDALONE|PROXY> [目标] [变量=值]\n\n'
	@printf '目标:\n'
	@printf '  all            编译当前模式（默认目标）\n'
	@printf '  both           两种模式各编译一遍\n'
	@printf '  headers-check  逐个头文件在两种模式下做语法检查\n'
	@printf '  link-check     链接 libs2s.a + libsodium.a 并运行加密层自检\n'
	@printf '  e2e-check      双 reactor 真实网络端到端（握手/回显/棘轮）\n'
	@printf '  wasm           编译 sdk/neura-crypto.wasm（需 emcc）\n'
	@printf '  sdk-check      校验 SDK 的 JS 文件\n'
	@printf '  test           运行 tests/run_tests.sh\n'
	@printf '  config-check   校验 config/config.ncf 语法\n'
	@printf '  install        安装二进制/配置/systemd 单元\n'
	@printf '  uninstall      卸载\n'
	@printf '  clean          清理当前模式的产物\n'
	@printf '  distclean      清理全部产物\n'
	@printf '  print-config   打印最终编译参数\n'
	@printf '  help           显示本帮助\n\n'
	@printf '变量:\n'
	@printf '  MODE=STANDALONE|PROXY   运行模式（默认 STANDALONE）\n'
	@printf '  NEURA_ROOT=<path>       libs2s 源码根（默认 /opt/neura/c-s2s）\n'
	@printf '  NEURA_PROFILE=release|asan  链接哪个 libs2s.a（默认 release）\n'
	@printf '  DEBUG=1                 -O0 -g3\n'
	@printf '  SANITIZE=1              ASan + UBSan（需 NEURA_PROFILE=asan）\n'
	@printf '  WERROR=1                警告即错误\n'
	@printf '  PREFIX=/usr/local       安装前缀\n'
	@printf '  CC=clang                编译器\n'

.DEFAULT_GOAL := all
