#!/usr/bin/env bash
# 自动安装依赖 
if ! command -v gcc >/dev/null; then 
    yum install -y gcc make openssl-devel libsodium-devel || apt-get install -y gcc make libssl-dev libsodium-dev 
fi
# =============================================================================
# Safe-HTTP 一键安装脚本
#
#   对生产环境保持敬畏：任何配置改动前先备份，改完必须校验，失败立刻回滚。
#
# 用法：
#   sudo ./install.sh                     # 交互式选择模式
#   sudo ./install.sh --mode standalone   # 独立模式（停 Nginx/Apache）
#   sudo ./install.sh --mode proxy        # 网关模式（注入 Nginx 反代）
#   sudo ./install.sh --mode proxy --force  # 强制重写整个 Nginx 配置（危险）
#   ./install.sh --dry-run                # 只打印将要执行的动作
#
# 可选参数：
#   --mode standalone|proxy   运行模式
#   --anchor-host HOST        发布 DNS TXT 的域名（默认 hostname -f）
#   --upstream HOST:PORT      Proxy 模式的上游（默认 127.0.0.1:8080）
#   --listen HOST:PORT        覆盖监听地址
#   --force                   允许重写整个 Nginx 配置（会丢失旧配置）
#   --yes                     非交互确认
#   --dry-run                 只演示，不落盘
# =============================================================================
set -euo pipefail

VERSION="1.0.0"
PROJECT="safe-http"
SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

MODE=""
FORCE=0
ASSUME_YES=0
DRY_RUN=0
ANCHOR_HOST=""
UPSTREAM=""
LISTEN=""

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc/safe-http}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
SERVICE_USER="${SERVICE_USER:-neura}"
BIN="${PREFIX}/bin/${PROJECT}"
ROOTKEY_FILE="${SYSCONFDIR}/rootkey.hex"
CONFIG_FILE="${SYSCONFDIR}/config.ncf"
SERVICE_FILE="${UNIT_DIR}/${PROJECT}.service"

MARK_BEGIN="# BEGIN NEURA S2S"
MARK_END="# END NEURA S2S"
NEURA_ROOT="${NEURA_ROOT:-/opt/neura/c-s2s}"

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
    C_YEL=$'\033[33m'; C_CYN=$'\033[36m'; C_BLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BLD=""
fi

step() { printf '%s==>%s %s\n' "$C_CYN" "$C_RESET" "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_GRN" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YEL" "$C_RESET" "$*" >&2; }
die()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

run_sh() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] sh -c %q\n' "$1"
        return 0
    fi
    bash -c "$1"
}

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ "$DRY_RUN" -eq 1 ] && return 0
    local ans
    printf '%s?%s %s [y/N] ' "$C_YEL" "$C_RESET" "$1"
    read -r ans </dev/tty || return 1
    case "$ans" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# -----------------------------------------------------------------------------
# 参数解析
# -----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --mode|-m)     MODE="${2:-}"; shift 2 ;;
        --anchor-host) ANCHOR_HOST="${2:-}"; shift 2 ;;
        --upstream)    UPSTREAM="${2:-}"; shift 2 ;;
        --listen)      LISTEN="${2:-}"; shift 2 ;;
        --force|-f)    FORCE=1; shift ;;
        --yes|-y)      ASSUME_YES=1; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --help|-h)     usage ;;
        *) die "未知参数: $1（用 --help 查看用法）" ;;
    esac
done

printf '%s%s%s %s 安装程序\n' "$C_BLD" "Safe-HTTP" "$C_RESET" "$VERSION"

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "需要 root 权限：请用 sudo 运行（或加 --dry-run 预览）"
fi

# -----------------------------------------------------------------------------
# 1. 模式选择
# -----------------------------------------------------------------------------
if [ -z "$MODE" ]; then
    printf '\n请选择运行模式：\n'
    printf '  1) Standalone 独立模式  监听 80/443，替代 Nginx/Apache\n'
    printf '  2) Proxy      网关模式  监听 127.0.0.1:5362，挂在现有 Nginx 之前\n'
    if [ "$DRY_RUN" -eq 1 ] || [ ! -t 0 ]; then
        MODE="standalone"
        warn "非交互环境，默认使用 standalone"
    else
        printf '请输入 [1/2]，默认 1: '
        read -r choice </dev/tty || choice=1
        case "${choice:-1}" in
            2|proxy|PROXY) MODE="proxy" ;;
            *)             MODE="standalone" ;;
        esac
    fi
fi

case "$MODE" in
    standalone|STANDALONE|1) MODE="standalone" ;;
    proxy|PROXY|2)           MODE="proxy" ;;
    *) die "非法模式 '$MODE'（只支持 standalone 或 proxy）" ;;
esac
MODE_UC="$(printf '%s' "$MODE" | tr '[:lower:]' '[:upper:]')"

if [ "$MODE" = "proxy" ]; then
    [ -n "$UPSTREAM" ] || UPSTREAM="127.0.0.1:8080"
    [ -n "$LISTEN" ]   || LISTEN="127.0.0.1:5362"
else
    [ -n "$LISTEN" ]   || LISTEN="0.0.0.0:80"
fi

if [ -z "$ANCHOR_HOST" ]; then
    ANCHOR_HOST="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"
fi

step "运行模式：${MODE_UC}（监听 ${LISTEN}，锚点域名 ${ANCHOR_HOST}）"

# -----------------------------------------------------------------------------
# 2. 环境依赖
# -----------------------------------------------------------------------------
step "检查编译与运行依赖"
for cmd in make cc openssl; do
    command -v "$cmd" >/dev/null 2>&1 || die "缺少命令: $cmd"
done
if ! command -v systemctl >/dev/null 2>&1; then
    warn "未检测到 systemd，将跳过服务安装"
    HAVE_SYSTEMD=0
else
    HAVE_SYSTEMD=1
fi

if [ ! -f "${NEURA_ROOT}/build-release/libs2s.a" ]; then
    die "找不到 ${NEURA_ROOT}/build-release/libs2s.a
      请先执行: (cd ${NEURA_ROOT} && make release && make libsodium)"
fi
ok "依赖齐全（libs2s.a + libsodium + openssl）"

# -----------------------------------------------------------------------------
# 3. 编译与安装（先清理旧产物，避免模式串味）
# -----------------------------------------------------------------------------
step "编译 Safe-HTTP（MODE=${MODE_UC}）"
run_sh "cd '$SRC_DIR' && make MODE='$MODE_UC' clean && make MODE='$MODE_UC' -j\"\$(nproc)\" NEURA_PROFILE=release"

step "安装二进制与默认配置"
run_sh "cd '$SRC_DIR' && make MODE='$MODE_UC' install PREFIX='$PREFIX' SYSCONFDIR='$SYSCONFDIR'"
[ "$DRY_RUN" -eq 1 ] || [ -x "$BIN" ] || die "安装后仍找不到 $BIN"
if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] 跳过安装校验"; else ok "已安装 $BIN"; fi

# -----------------------------------------------------------------------------
# 4. RootKey 与信任锚指纹
# -----------------------------------------------------------------------------
step "生成/读取 RootKey（信任锚根）"
if [ ! -f "$ROOTKEY_FILE" ]; then
    run mkdir -p "$SYSCONFDIR"
    run chmod 0750 "$SYSCONFDIR"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] openssl rand -hex 32 > %s（0600）\n' "$ROOTKEY_FILE"
        ROOTKEY_HEX="$(openssl rand -hex 32)"
    else
        ( umask 077; openssl rand -hex 32 > "$ROOTKEY_FILE" )
        ROOTKEY_HEX="$(tr -d ' \r\n' < "$ROOTKEY_FILE")"
        ok "已生成 $ROOTKEY_FILE（0600）"
    fi
else
    ROOTKEY_HEX="$(tr -d ' \r\n' < "$ROOTKEY_FILE")"
    ok "复用已有 $ROOTKEY_FILE"
fi

[ "${#ROOTKEY_HEX}" -eq 64 ] || die "RootKey 长度非法（需 64 位 hex）"

# 指纹布局必须与 src/security.c 的 sh_anchor_fingerprint() 一致：
#   fp = SHA-512("safe-http/trust-anchor/v1:" || rootkey)[0..31]
compute_fp() {
    local key="$1" digest
    digest="$(
        { printf '%s' 'safe-http/trust-anchor/v1:'; printf '%s' "$key" | xxd -r -p; } \
        | openssl dgst -sha512 -binary \
        | od -An -tx1 | tr -d ' \n'
    )"
    printf '%s' "${digest:0:64}"
}

if [ -x "$BIN" ] && "$BIN" --print-fingerprint "$ROOTKEY_FILE" >/tmp/.sh_fp 2>/dev/null; then
    ANCHOR_FP="$(tr -d ' \r\n' </tmp/.sh_fp)"
    rm -f /tmp/.sh_fp
else
    ANCHOR_FP="$(compute_fp "$ROOTKEY_HEX")"
fi
[ "${#ANCHOR_FP}" -eq 64 ] || die "指纹计算失败"

TXT_NAME="_neura-s2s.${ANCHOR_HOST}"
TXT_VALUE="v=ns2s1; fp=${ANCHOR_FP}"

# -----------------------------------------------------------------------------
# 5. 系统服务用户
# -----------------------------------------------------------------------------
step "准备低权限服务用户"
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    ok "用户 $SERVICE_USER 已存在"
else
    run useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] useradd $SERVICE_USER"; else ok "已创建系统用户 $SERVICE_USER"; fi
fi
run mkdir -p /var/log/safe-http
[ "$DRY_RUN" -eq 1 ] || chown "${SERVICE_USER}:${SERVICE_USER}" /var/log/safe-http 2>/dev/null || true
[ "$DRY_RUN" -eq 1 ] || chmod 0750 /var/log/safe-http

# -----------------------------------------------------------------------------
# 6. 既有 Web 服务器处理
# -----------------------------------------------------------------------------
NGINX_CONF=""
detect_nginx() {
    local c
    for c in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf /etc/openresty/nginx.conf; do
        if [ -f "$c" ]; then NGINX_CONF="$c"; return 0; fi
    done
    return 1
}

if [ "$MODE" = "standalone" ]; then
    step "Standalone：停止系统现有 Web 服务器"
    for svc in nginx apache2 httpd; do
        if command -v systemctl >/dev/null 2>&1 && \
           systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${svc}\.service"; then
            if systemctl is-active --quiet "$svc"; then
                warn "检测到 $svc 正在运行，即将停止（未禁用，可随时 systemctl start $svc 恢复）"
                run systemctl stop "$svc"
                ok "已停止 $svc"
            fi
        fi
    done
else
    step "Proxy：探测 Nginx 配置"
    detect_nginx || die "未找到 Nginx 配置。Proxy 模式需要宿主机已安装 Nginx；也可用 --force 重建配置"
    ok "Nginx 主配置: $NGINX_CONF"

    if [ -d /etc/nginx/conf.d ]; then
        TARGET_CONF="/etc/nginx/conf.d/safe-http-neura.conf"
        APPEND_ONLY=1
    else
        TARGET_CONF="$NGINX_CONF"
        APPEND_ONLY=0
    fi

    if [ "$FORCE" -eq 1 ]; then
        printf '\n%s!! 警告 !!%s --force 将重写整个 %s，旧配置会丢失（已备份 .bak）\n' \
            "$C_RED" "$C_RESET" "$NGINX_CONF" >&2
        confirm "确认强制重写 Nginx 配置？" || die "用户取消"
    fi

    # 备份（保留原文件权限属主）
    if [ -f "$TARGET_CONF" ]; then
        BACKUP="${TARGET_CONF}.bak"
        if [ -f "$BACKUP" ]; then BACKUP="${BACKUP}.$(date +%Y%m%d%H%M%S)"; fi

        run cp -a "$TARGET_CONF" "$BACKUP"
        ok "已备份 $TARGET_CONF -> $BACKUP"
    else
        BACKUP=""
    fi

    TMP_BLOCK="$(mktemp)"
    cat >"$TMP_BLOCK" <<EOF
${MARK_BEGIN}
# 由 Safe-HTTP install.sh 生成：明文入口 -> Neura-S2S 网关
upstream safe_http_neura {
    server ${LISTEN};
    keepalive 32;
}

server {
    listen 80 default_server;
    server_name ${ANCHOR_HOST};

    location / {
        proxy_pass http://safe_http_neura;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
        proxy_buffering off;
    }
}
${MARK_END}
EOF

    if [ "$FORCE" -eq 1 ]; then
        step "强制重写：生成最小可用 Nginx 配置"
        FORCE_CONF="$(mktemp)"
        cat >"$FORCE_CONF" <<EOF
# 由 Safe-HTTP install.sh --force 生成
worker_processes auto;
events { worker_connections 4096; }
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    include ${TMP_BLOCK};
}
EOF
        [ "$DRY_RUN" -eq 1 ] || cat "$FORCE_CONF" > "$NGINX_CONF"
        rm -f "$FORCE_CONF"
    elif [ "$APPEND_ONLY" -eq 1 ] && [ "$TARGET_CONF" != "$NGINX_CONF" ]; then
        # conf.d 下的独立文件：整文件替换（幂等）
        [ "$DRY_RUN" -eq 1 ] || cat "$TMP_BLOCK" > "$TARGET_CONF"
    else
        # 注入主配置/单文件：用标记包裹，重复安装时替换标记之间的内容
        if grep -qF "$MARK_BEGIN" "$TARGET_CONF" 2>/dev/null; then
            step "检测到已有 NEURA S2S 标记块，原地替换"
            if [ "$DRY_RUN" -eq 0 ]; then
                awk -v b="$MARK_BEGIN" -v e="$MARK_END" -v blk="$TMP_BLOCK" '
                    index($0, b) { while ((getline line < blk) > 0) print line; skip=1; next }
                    index($0, e) { skip=0; next }
                    !skip { print }
                ' "$TARGET_CONF" > "${TARGET_CONF}.new"
                cat "${TARGET_CONF}.new" > "$TARGET_CONF"
                rm -f "${TARGET_CONF}.new"
            fi
        else
            if [ "$DRY_RUN" -eq 0 ]; then
                cat "$TMP_BLOCK" >> "$TARGET_CONF"
            fi
        fi
    fi
    rm -f "$TMP_BLOCK"
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] 未修改 $TARGET_CONF"; else ok "已写入反代规则（$MARK_BEGIN .. $MARK_END）"; fi

    # 语法检查：失败立刻回滚
    step "校验 Nginx 配置（nginx -t）"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] nginx -t"
    else
        if ! nginx -t 2>/tmp/.sh_nginx_t; then
            cat /tmp/.sh_nginx_t >&2
            if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
                cp -a "$BACKUP" "$TARGET_CONF"
                warn "已回滚到 $BACKUP"
            else
                rm -f "$TARGET_CONF"
                warn "已删除新写入的 $TARGET_CONF"
            fi
            rm -f /tmp/.sh_nginx_t
            die "nginx -t 失败，配置已回滚，未重启 Nginx"
        fi
        cat /tmp/.sh_nginx_t >/dev/null 2>&1 || true
        rm -f /tmp/.sh_nginx_t
        ok "nginx -t 通过"
        run systemctl reload nginx 2>/dev/null || run nginx -s reload
    fi
fi

# -----------------------------------------------------------------------------
# 7. Systemd 服务（最小权限）
# -----------------------------------------------------------------------------
if [ "$HAVE_SYSTEMD" -eq 1 ]; then
    step "生成 systemd 服务（最小权限）"
    UNIT_TMP="$(mktemp)"
    EXTRA_ARGS="--config ${CONFIG_FILE} --root-key ${ROOTKEY_FILE} --anchor-host ${ANCHOR_HOST} --foreground --no-trust-anchor"
    if [ "$MODE" = "proxy" ]; then
        EXTRA_ARGS="${EXTRA_ARGS} --listen ${LISTEN} --upstream ${UPSTREAM}"
    else
        EXTRA_ARGS="${EXTRA_ARGS} --listen ${LISTEN}"
    fi
    cat >"$UNIT_TMP" <<EOF
[Unit]
Description=Safe-HTTP secure gateway (${MODE_UC})
Documentation=https://github.com/safe-http/safe-http
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${BIN} ${EXTRA_ARGS}
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

# ---- 系统服务隔离 ----
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
ReadWritePaths=/var/log/safe-http /run
RuntimeDirectory=safe-http
LogsDirectory=safe-http
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] install -m 0644 $UNIT_TMP $SERVICE_FILE"
    else
        install -m 0644 "$UNIT_TMP" "$SERVICE_FILE"
    fi
    rm -f "$UNIT_TMP"
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] 未写入 $SERVICE_FILE"; else ok "已写入 $SERVICE_FILE"; fi

    run systemctl daemon-reload
    run systemctl enable "$PROJECT" >/dev/null 2>&1 || true
    run systemctl restart "$PROJECT"

    step "检查服务状态"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] systemctl is-active $PROJECT"
    elif systemctl is-active --quiet "$PROJECT"; then
        ok "服务运行中：$PROJECT"
    else
        warn "服务未启动成功，最近日志："
        systemctl status "$PROJECT" --no-pager -l | tail -20 >&2 || true
        die "安装未完成：服务启动失败"
    fi
else
    warn "无 systemd：请手工后台运行 $BIN ${EXTRA_ARGS:-}"
fi

# -----------------------------------------------------------------------------
# 8. 收尾
# -----------------------------------------------------------------------------
printf '\n'
printf '%s============================================================%s\n' "$C_GRN" "$C_RESET"
printf '%s  Safe-HTTP 安装成功（MODE=%s）%s\n' "$C_GRN" "$MODE_UC" "$C_RESET"
printf '%s============================================================%s\n' "$C_GRN" "$C_RESET"
printf '  二进制      : %s\n' "$BIN"
printf '  配置        : %s\n' "$CONFIG_FILE"
printf '  RootKey     : %s（0600）\n' "$ROOTKEY_FILE"
if [ "$MODE" = "proxy" ]; then printf '  上游        : %s\n' "$UPSTREAM"; fi

[ "$MODE" = "proxy" ] && printf '  上游        : %s\n' "$UPSTREAM"
printf '\n'
printf '%s  服务器公钥（信任锚）指纹%s\n' "$C_BLD" "$C_RESET"
printf '    %s\n' "$ANCHOR_FP"
printf '\n'
printf '%s  请到 DNS 添加 TXT 记录（DNSSEC 必须开启）%s\n' "$C_BLD" "$C_RESET"
printf '    记录名: %s\n' "$TXT_NAME"
printf '    记录值: "%s"\n' "$TXT_VALUE"
printf '    TTL   : 3600\n'
printf '\n'
printf '%s  客户端首次连接前需带外配置同一把 RootKey：%s\n' "$C_BLD" "$C_RESET"
printf '    安全复制: scp root@%s:%s ./rootkey.hex\n' "$ANCHOR_HOST" "$ROOTKEY_FILE"
printf '    SDK 会通过 DoH 拉取上述 TXT 并校验 DNSSEC(AD 位)，\n'
printf '    指纹不一致时拒绝握手（防首次连接中间人）。\n'
printf '\n'
printf '  常用命令: systemctl status %s | journalctl -u %s -f\n' "$PROJECT" "$PROJECT"
printf '  校验配置: %s --check-config %s\n' "$BIN" "$CONFIG_FILE"
printf '  查看指纹: %s --print-fingerprint %s\n' "$BIN" "$ROOTKEY_FILE"
printf '%s============================================================%s\n' "$C_GRN" "$C_RESET"
