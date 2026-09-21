#!/usr/bin/env bash

###############################################################################
# Shadowsocks-Rust 多用户管理脚本
#
# 功能：
#   1. 自动安装 Shadowsocks-Rust
#   2. 多用户独立端口
#   3. 每个用户独立 30 天流量周期
#   4. created_at 永久固定
#   5. 手动重置流量不会修改 created_at
#   6. 流量超限自动禁用
#   7. 用户到期永久禁用
#   8. 新周期自动恢复“流量超限”用户
#   9. iptables 统计 TCP + UDP 流量
#  10. 流量累计保存，iptables 重建不会丢失已使用流量
#  11. systemd 管理 Shadowsocks-Rust
#  12. Cron 每 5 分钟自动检查
#  13. 自动获取服务器公网 IPv4
#  14. 自动生成 ss:// 导入链接
#  15. 支持导出全部用户导入链接
#  16. 自动安装 /usr/local/bin/ss-manager
#
# Debian / Ubuntu 推荐
#
# 使用：
#   bash ss-manager.sh
#
# 安装后：
#   ss-manager
#
###############################################################################

set -u
set -o pipefail


###############################################################################
# 基础配置
###############################################################################

APP_NAME="ss-manager"

# 管理脚本安装位置
MANAGER_PATH="/usr/local/bin/ss-manager"

# Shadowsocks 配置目录
CONFIG_DIR="/etc/shadowsocks-rust"

# 用户数据库
USERS_FILE="${CONFIG_DIR}/users.json"

# Shadowsocks 配置文件
SS_CONFIG="${CONFIG_DIR}/config.json"

# 管理日志
LOG_FILE="${CONFIG_DIR}/manager.log"

# systemd
SERVICE_NAME="shadowsocks-rust"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Shadowsocks 二进制
BIN_PATH="/usr/local/bin/ssserver"

# 每个用户一个 30 天周期
RESET_DAYS=30
RESET_SECONDS=$((RESET_DAYS * 86400))

# 默认加密方式
DEFAULT_METHOD="aes-256-gcm"

# Shadowsocks-Rust GitHub API
GITHUB_API="https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest"

# Cron
CRON_FILE="/etc/cron.d/ss-manager"

# 默认端口
DEFAULT_PORT=8388


###############################################################################
# 颜色
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'


###############################################################################
# 输出函数
###############################################################################

info() {
    echo -e "${BLUE}[信息]${RESET} $*"
}

ok() {
    echo -e "${GREEN}[成功]${RESET} $*"
}

warn() {
    echo -e "${YELLOW}[警告]${RESET} $*"
}

err() {
    echo -e "${RED}[错误]${RESET} $*" >&2
}

die() {
    err "$*"
    exit 1
}


###############################################################################
# 检查 root
###############################################################################

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "请使用 root 用户运行此脚本。"
    fi
}


###############################################################################
# 时间函数
###############################################################################

now_ts() {
    date +%s
}


format_ts() {
    local ts="${1:-0}"

    if [[ "${ts}" =~ ^[0-9]+$ ]] && (( ts > 0 )); then
        date -d "@${ts}" '+%Y-%m-%d %H:%M:%S'
    else
        echo "-"
    fi
}


remaining_time() {
    local target="$1"
    local now
    local diff
    local days
    local hours
    local minutes

    now="$(now_ts)"
    diff=$((target - now))

    if (( diff <= 0 )); then
        echo "已到期"
        return
    fi

    days=$((diff / 86400))
    diff=$((diff % 86400))

    hours=$((diff / 3600))
    diff=$((diff % 3600))

    minutes=$((diff / 60))

    if (( days > 0 )); then
        echo "${days}天${hours}小时"
    elif (( hours > 0 )); then
        echo "${hours}小时${minutes}分钟"
    else
        echo "${minutes}分钟"
    fi
}


###############################################################################
# 字节格式化
###############################################################################

bytes_to_human() {
    local bytes="${1:-0}"

    if ! [[ "${bytes}" =~ ^[0-9]+$ ]]; then
        bytes=0
    fi

    if (( bytes < 1024 )); then
        echo "${bytes} B"
    elif (( bytes < 1024 * 1024 )); then
        awk -v b="${bytes}" 'BEGIN {printf "%.2f KB", b/1024}'
    elif (( bytes < 1024 * 1024 * 1024 )); then
        awk -v b="${bytes}" 'BEGIN {printf "%.2f MB", b/1024/1024}'
    elif (( bytes < 1024 * 1024 * 1024 * 1024 )); then
        awk -v b="${bytes}" 'BEGIN {printf "%.2f GB", b/1024/1024/1024}'
    else
        awk -v b="${bytes}" 'BEGIN {printf "%.2f TB", b/1024/1024/1024/1024}'
    fi
}


###############################################################################
# 流量限制转换
#
# 支持：
#   100
#   100M
#   100G
#   1T
#   0
#
# 返回字节
###############################################################################

parse_limit() {
    local input
    local number
    local unit

    input="$(echo "${1:-0}" | tr '[:lower:]' '[:upper:]')"

    if [[ "${input}" == "0" || -z "${input}" ]]; then
        echo 0
        return
    fi

    if [[ "${input}" =~ ^([0-9]+([.][0-9]+)?)([KMGT]?)B?$ ]]; then

        number="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[3]}"

        case "${unit}" in
            "")
                awk -v n="${number}" 'BEGIN {printf "%.0f", n}'
                ;;

            K)
                awk -v n="${number}" 'BEGIN {printf "%.0f", n*1024}'
                ;;

            M)
                awk -v n="${number}" 'BEGIN {printf "%.0f", n*1024*1024}'
                ;;

            G)
                awk -v n="${number}" 'BEGIN {printf "%.0f", n*1024*1024*1024}'
                ;;

            T)
                awk -v n="${number}" 'BEGIN {printf "%.0f", n*1024*1024*1024*1024}'
                ;;

            *)
                echo 0
                ;;
        esac

    else
        echo 0
    fi
}


###############################################################################
# 随机密码
###############################################################################

random_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24
    echo
}


###############################################################################
# 初始化目录
###############################################################################

init_dirs() {
    mkdir -p "${CONFIG_DIR}"

    chmod 700 "${CONFIG_DIR}"

    if [[ ! -f "${USERS_FILE}" ]]; then
        echo '[]' > "${USERS_FILE}"
        chmod 600 "${USERS_FILE}"
    fi

    touch "${LOG_FILE}"
    chmod 600 "${LOG_FILE}"
}


###############################################################################
# 自动安装自身
#
# 如果当前脚本可以读取，则复制到：
#
#   /usr/local/bin/ss-manager
#
# curl | bash 情况下可能没有可复制的源文件，
# 此时跳过即可。
###############################################################################

install_self() {

    local current_script=""

    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        current_script="${BASH_SOURCE[0]}"
    fi

    if [[ -n "${current_script}" && -f "${current_script}" ]]; then

        if [[ "$(readlink -f "${current_script}")" != "$(readlink -f "${MANAGER_PATH}" 2>/dev/null || true)" ]]; then

            cp -f "${current_script}" "${MANAGER_PATH}"
            chmod 755 "${MANAGER_PATH}"

            ok "管理脚本已安装：${MANAGER_PATH}"
        fi

    fi
}


###############################################################################
# 安装依赖
###############################################################################

install_dependencies() {

    local need_install=()

    command -v curl >/dev/null 2>&1 || need_install+=("curl")
    command -v jq >/dev/null 2>&1 || need_install+=("jq")
    command -v iptables >/dev/null 2>&1 || need_install+=("iptables")
    command -v tar >/dev/null 2>&1 || need_install+=("tar")
    command -v xz >/dev/null 2>&1 || need_install+=("xz-utils")
    command -v base64 >/dev/null 2>&1 || need_install+=("coreutils")

    if (( ${#need_install[@]} == 0 )); then
        return
    fi

    info "正在安装依赖：${need_install[*]}"

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y

    apt-get install -y "${need_install[@]}"
}


###############################################################################
# 检查依赖
###############################################################################

check_dependencies() {

    local commands=(
        curl
        jq
        iptables
        tar
        xz
        base64
        systemctl
        awk
        sed
        grep
    )

    local cmd

    for cmd in "${commands[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            die "缺少依赖：${cmd}"
        fi
    done
}


###############################################################################
# 获取 Shadowsocks-Rust 最新版本
###############################################################################

get_latest_version() {

    local version

    version="$(
        curl -fsSL \
            --connect-timeout 10 \
            --max-time 30 \
            "${GITHUB_API}" 2>/dev/null |
        jq -r '.tag_name // empty'
    )"

    if [[ -z "${version}" ]]; then
        return 1
    fi

    echo "${version}"
}


###############################################################################
# 获取系统架构
###############################################################################

get_target_arch() {

    case "$(uname -m)" in

        x86_64|amd64)
            echo "x86_64"
            ;;

        aarch64|arm64)
            echo "aarch64"
            ;;

        *)
            return 1
            ;;
    esac
}


###############################################################################
# 安装 Shadowsocks-Rust
###############################################################################

install_shadowsocks() {

    local version
    local arch
    local tmp_dir
    local archive
    local url
    local extracted_bin

    info "正在获取 Shadowsocks-Rust 最新版本..."

    version="$(get_latest_version)" || die "无法获取 Shadowsocks-Rust 最新版本。"

    arch="$(get_target_arch)" || die "暂不支持当前 CPU 架构：$(uname -m)"

    info "最新版本：${version}"
    info "系统架构：${arch}"

    tmp_dir="$(mktemp -d)"

    archive="${tmp_dir}/shadowsocks-rust.tar.xz"

    url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${version}/shadowsocks-v${version#v}.${arch}-unknown-linux-gnu.tar.xz"

    info "下载：${url}"

    if ! curl -fL \
        --connect-timeout 15 \
        --max-time 300 \
        --retry 3 \
        -o "${archive}" \
        "${url}"; then

        rm -rf "${tmp_dir}"

        die "Shadowsocks-Rust 下载失败。"
    fi

    info "正在解压..."

    tar -xJf "${archive}" -C "${tmp_dir}"

    extracted_bin="$(find "${tmp_dir}" -type f -name 'ssserver' | head -n 1)"

    if [[ -z "${extracted_bin}" || ! -f "${extracted_bin}" ]]; then
        rm -rf "${tmp_dir}"
        die "下载包中没有找到 ssserver。"
    fi

    chmod 755 "${extracted_bin}"

    if [[ -f "${BIN_PATH}" ]]; then
        cp -f "${BIN_PATH}" "${BIN_PATH}.bak"
    fi

    cp -f "${extracted_bin}" "${BIN_PATH}"

    chmod 755 "${BIN_PATH}"

    rm -rf "${tmp_dir}"

    if ! "${BIN_PATH}" --version >/dev/null 2>&1; then

        if [[ -f "${BIN_PATH}.bak" ]]; then
            mv -f "${BIN_PATH}.bak" "${BIN_PATH}"
        fi

        die "Shadowsocks-Rust 安装验证失败。"
    fi

    rm -f "${BIN_PATH}.bak"

    ok "Shadowsocks-Rust 安装完成。"
    "${BIN_PATH}" --version || true
}


###############################################################################
# 获取用户数量
###############################################################################

get_user_count() {

    jq 'length' "${USERS_FILE}" 2>/dev/null || echo 0
}


###############################################################################
# 判断是否存在用户
###############################################################################

has_users() {

    [[ "$(get_user_count)" -gt 0 ]]
}


###############################################################################
# 判断是否存在启用用户
###############################################################################

has_enabled_users() {

    jq -e 'any(.[]; (.enabled // true) == true)' \
        "${USERS_FILE}" >/dev/null 2>&1
}


###############################################################################
# 用户数据迁移
#
# 给旧版本用户补齐新字段。
###############################################################################

migrate_users() {

    local tmp

    [[ -f "${USERS_FILE}" ]] || echo '[]' > "${USERS_FILE}"

    if ! jq empty "${USERS_FILE}" >/dev/null 2>&1; then
        warn "users.json 数据异常，正在重新初始化。"
        echo '[]' > "${USERS_FILE}"
        return
    fi

    tmp="$(mktemp)"

    jq '
        map(
            .created_at = (.created_at // now | floor) |
            .next_reset = (.next_reset // ((.created_at // now | floor) + 2592000)) |
            .used = (.used // 0) |
            .limit = (.limit // 0) |
            .expire = (.expire // 0) |
            .enabled = (.enabled // true) |
            .disabled_reason = (.disabled_reason // "") |
            .last_reset = (.last_reset // 0) |
            .method = (.method // "aes-256-gcm")
        )
    ' "${USERS_FILE}" > "${tmp}"

    mv -f "${tmp}" "${USERS_FILE}"

    chmod 600 "${USERS_FILE}"
}


###############################################################################
# 保存用户数据
###############################################################################

save_users() {

    local tmp

    tmp="$(mktemp)"

    jq '.' "${USERS_FILE}" > "${tmp}" || {
        rm -f "${tmp}"
        die "保存 users.json 失败。"
    }

    mv -f "${tmp}" "${USERS_FILE}"

    chmod 600 "${USERS_FILE}"
}


###############################################################################
# 根据 created_at 计算下一个 30 天周期
#
# 注意：
#   不使用“当前时间 + 30天”
#   而是一直从 created_at 往后推。
#
# 例如：
#
# created_at = 1月1日
#
# 周期：
# 1月1日
# 1月31日
# 3月2日
# ...
#
# 这样即使服务器某天长时间关闭，也不会改变用户原来的周期基准。
###############################################################################

calculate_next_reset() {

    local created_at="$1"
    local current="$2"
    local next

    if (( created_at <= 0 )); then
        echo $((current + RESET_SECONDS))
        return
    fi

    next=$((created_at + RESET_SECONDS))

    while (( next <= current )); do
        next=$((next + RESET_SECONDS))
    done

    echo "${next}"
}


###############################################################################
# 获取公网 IPv4
#
# 按顺序尝试多个服务。
#
# 只接受 IPv4。
###############################################################################

get_public_ipv4() {

    local ip=""

    # 第一优先级
    ip="$(
        curl -4 -fsSL \
            --connect-timeout 5 \
            --max-time 10 \
            https://api.ipify.org 2>/dev/null |
        tr -d '[:space:]'
    )"

    if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "${ip}"
        return 0
    fi

    # 第二优先级
    ip="$(
        curl -4 -fsSL \
            --connect-timeout 5 \
            --max-time 10 \
            https://ifconfig.me/ip 2>/dev/null |
        tr -d '[:space:]'
    )"

    if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "${ip}"
        return 0
    fi

    # 第三优先级
    ip="$(
        curl -4 -fsSL \
            --connect-timeout 5 \
            --max-time 10 \
            https://ipv4.icanhazip.com 2>/dev/null |
        tr -d '[:space:]'
    )"

    if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "${ip}"
        return 0
    fi

    return 1
}


###############################################################################
# URL 编码
###############################################################################

url_encode() {

    local value="$1"

    if command -v jq >/dev/null 2>&1; then
        printf '%s' "${value}" | jq -sRr @uri
    else
        printf '%s' "${value}"
    fi
}


###############################################################################
# 生成 Shadowsocks ss:// 导入链接
#
# 标准格式：
#
# ss://BASE64(method:password)@server:port#tag
#
###############################################################################

generate_ss_link() {

    local port="$1"
    local password="$2"
    local method="$3"
    local name="$4"
    local server="${5:-}"

    if [[ -z "${server}" ]]; then
        server="$(get_public_ipv4 2>/dev/null || true)"
    fi

    if [[ -z "${server}" ]]; then
        return 1
    fi

    # method:password
    local userinfo="${method}:${password}"

    # URL-safe Base64
    local encoded

    encoded="$(
        printf '%s' "${userinfo}" |
        base64 -w 0 |
        tr '+/' '-_' |
        tr -d '='
    )"

    local tag

    tag="$(url_encode "${name}")"

    echo "ss://${encoded}@${server}:${port}#${tag}"
}


###############################################################################
# 显示单个用户 SS 链接
###############################################################################

show_user_ss_link() {

    local username="$1"

    local user_json
    local port
    local password
    local method

    user_json="$(
        jq -c --arg n "${username}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    if [[ -z "${user_json}" ]]; then
        err "用户不存在：${username}"
        return 1
    fi

    port="$(jq -r '.port' <<<"${user_json}")"
    password="$(jq -r '.password' <<<"${user_json}")"
    method="$(jq -r '.method // "aes-256-gcm"' <<<"${user_json}")"

    local ip

    ip="$(get_public_ipv4 2>/dev/null || true)"

    if [[ -z "${ip}" ]]; then
        err "无法自动获取服务器公网 IPv4。"
        return 1
    fi

    echo
    echo -e "${CYAN}用户：${username}${RESET}"
    echo -e "${CYAN}服务器：${ip}${RESET}"
    echo -e "${CYAN}端口：${port}${RESET}"
    echo -e "${CYAN}加密：${method}${RESET}"
    echo
    echo "ss:// 导入链接："
    generate_ss_link \
        "${port}" \
        "${password}" \
        "${method}" \
        "${username}" \
        "${ip}"
    echo
}


###############################################################################
# iptables 链名称
###############################################################################

in_chain() {
    echo "ss-${1}-in"
}

out_chain() {
    echo "ss-${1}-out"
}


###############################################################################
# 删除某用户流量规则
###############################################################################

remove_traffic_rules() {

    local port="$1"

    local in_chain_name
    local out_chain_name

    in_chain_name="$(in_chain "${port}")"
    out_chain_name="$(out_chain "${port}")"

    # 删除 INPUT 跳转
    iptables -D INPUT -p tcp --dport "${port}" -j "${in_chain_name}" 2>/dev/null || true
    iptables -D INPUT -p udp --dport "${port}" -j "${in_chain_name}" 2>/dev/null || true

    # 删除 OUTPUT 跳转
    iptables -D OUTPUT -p tcp --sport "${port}" -j "${out_chain_name}" 2>/dev/null || true
    iptables -D OUTPUT -p udp --sport "${port}" -j "${out_chain_name}" 2>/dev/null || true

    # 清空链
    iptables -F "${in_chain_name}" 2>/dev/null || true
    iptables -F "${out_chain_name}" 2>/dev/null || true

    # 删除链
    iptables -X "${in_chain_name}" 2>/dev/null || true
    iptables -X "${out_chain_name}" 2>/dev/null || true
}


###############################################################################
# 删除某用户所有 iptables 规则
###############################################################################

remove_port_rules() {

    local port="$1"

    local in_chain_name
    local out_chain_name

    in_chain_name="$(in_chain "${port}")"
    out_chain_name="$(out_chain "${port}")"

    # 流量规则
    remove_traffic_rules "${port}"

    # DROP 规则
    iptables -D INPUT -p tcp --dport "${port}" -j DROP 2>/dev/null || true
    iptables -D INPUT -p udp --dport "${port}" -j DROP 2>/dev/null || true

    iptables -D OUTPUT -p tcp --sport "${port}" -j DROP 2>/dev/null || true
    iptables -D OUTPUT -p udp --sport "${port}" -j DROP 2>/dev/null || true

    iptables -D INPUT -p tcp --dport "${port}" -j "${in_chain_name}" 2>/dev/null || true
    iptables -D INPUT -p udp --dport "${port}" -j "${in_chain_name}" 2>/dev/null || true

    iptables -D OUTPUT -p tcp --sport "${port}" -j "${out_chain_name}" 2>/dev/null || true
    iptables -D OUTPUT -p udp --sport "${port}" -j "${out_chain_name}" 2>/dev/null || true

    iptables -F "${in_chain_name}" 2>/dev/null || true
    iptables -F "${out_chain_name}" 2>/dev/null || true

    iptables -X "${in_chain_name}" 2>/dev/null || true
    iptables -X "${out_chain_name}" 2>/dev/null || true
}


###############################################################################
# 创建流量统计规则
#
# INPUT：
#   客户端 -> Shadowsocks
#
# OUTPUT：
#   Shadowsocks -> 客户端
#
# TCP + UDP 都统计。
###############################################################################

add_traffic_rules() {

    local port="$1"

    local in_chain_name
    local out_chain_name

    in_chain_name="$(in_chain "${port}")"
    out_chain_name="$(out_chain "${port}")"

    # 先删除旧规则
    remove_traffic_rules "${port}"

    # 创建链
    iptables -N "${in_chain_name}"
    iptables -N "${out_chain_name}"

    # INPUT
    iptables -A INPUT \
        -p tcp \
        --dport "${port}" \
        -j "${in_chain_name}"

    iptables -A INPUT \
        -p udp \
        --dport "${port}" \
        -j "${in_chain_name}"

    # OUTPUT
    iptables -A OUTPUT \
        -p tcp \
        --sport "${port}" \
        -j "${out_chain_name}"

    iptables -A OUTPUT \
        -p udp \
        --sport "${port}" \
        -j "${out_chain_name}"

    # 统计链直接 ACCEPT
    iptables -A "${in_chain_name}" -j ACCEPT
    iptables -A "${out_chain_name}" -j ACCEPT
}


###############################################################################
# 创建阻断规则
###############################################################################

add_block_rules() {

    local port="$1"

    # 先删除流量统计规则
    remove_traffic_rules "${port}"

    # 防止重复
    iptables -D INPUT -p tcp --dport "${port}" -j DROP 2>/dev/null || true
    iptables -D INPUT -p udp --dport "${port}" -j DROP 2>/dev/null || true

    iptables -D OUTPUT -p tcp --sport "${port}" -j DROP 2>/dev/null || true
    iptables -D OUTPUT -p udp --sport "${port}" -j DROP 2>/dev/null || true

    # 入站阻断
    iptables -I INPUT 1 \
        -p tcp \
        --dport "${port}" \
        -j DROP

    iptables -I INPUT 1 \
        -p udp \
        --dport "${port}" \
        -j DROP

    # 出站阻断
    iptables -I OUTPUT 1 \
        -p tcp \
        --sport "${port}" \
        -j DROP

    iptables -I OUTPUT 1 \
        -p udp \
        --sport "${port}" \
        -j DROP
}


###############################################################################
# 获取某端口当前 iptables 统计流量
#
# 返回：
#   INPUT bytes + OUTPUT bytes
###############################################################################

get_port_traffic() {

    local port="$1"

    local in_chain_name
    local out_chain_name

    local in_bytes=0
    local out_bytes=0

    in_chain_name="$(in_chain "${port}")"
    out_chain_name="$(out_chain "${port}")"

    # INPUT
    if iptables -L "${in_chain_name}" -n -v -x >/dev/null 2>&1; then

        in_bytes="$(
            iptables -L "${in_chain_name}" -n -v -x 2>/dev/null |
            awk 'NR > 2 && $1 ~ /^[0-9]+$/ {sum += $2} END {print sum+0}'
        )"
    fi

    # OUTPUT
    if iptables -L "${out_chain_name}" -n -v -x >/dev/null 2>&1; then

        out_bytes="$(
            iptables -L "${out_chain_name}" -n -v -x 2>/dev/null |
            awk 'NR > 2 && $1 ~ /^[0-9]+$/ {sum += $2} END {print sum+0}'
        )"
    fi

    [[ "${in_bytes}" =~ ^[0-9]+$ ]] || in_bytes=0
    [[ "${out_bytes}" =~ ^[0-9]+$ ]] || out_bytes=0

    echo $((in_bytes + out_bytes))
}


###############################################################################
# 获取用户当前总使用流量
#
# used：
#   已经持久化的历史流量
#
# iptables：
#   当前规则链尚未同步的实时流量
###############################################################################

get_user_total_traffic() {

    local username="$1"

    local user_json
    local used
    local port
    local current

    user_json="$(
        jq -c --arg n "${username}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    [[ -z "${user_json}" ]] && return 1

    used="$(jq -r '.used // 0' <<<"${user_json}")"
    port="$(jq -r '.port' <<<"${user_json}")"

    [[ "${used}" =~ ^[0-9]+$ ]] || used=0

    current="$(get_port_traffic "${port}")"

    echo $((used + current))
}


###############################################################################
# 同步用户当前 iptables 流量
#
# 这是流量统计可靠性的关键。
#
# 例如：
#
# JSON used = 20 GB
# iptables 当前链 = 3 GB
#
# 同步后：
#
# JSON used = 23 GB
# iptables 当前链重新从 0 开始
#
# 因此即使：
#   - 重建 iptables
#   - 重启脚本
#   - 添加/删除用户
#   - 更新配置
#
# 也不会因为计数器归零而丢掉已经统计的流量。
###############################################################################

sync_user_traffic() {

    local username="$1"

    local user_json
    local port
    local enabled
    local reason
    local current
    local used
    local total

    user_json="$(
        jq -c --arg n "${username}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    [[ -z "${user_json}" ]] && return 0

    port="$(jq -r '.port' <<<"${user_json}")"
    enabled="$(jq -r '(.enabled // true)' <<<"${user_json}")"
    reason="$(jq -r '.disabled_reason // ""' <<<"${user_json}")"

    # 被阻断的用户没有流量统计链
    if [[ "${enabled}" != "true" ]]; then
        return 0
    fi

    if [[ "${reason}" != "" ]]; then
        return 0
    fi

    # 当前 iptables 计数
    current="$(get_port_traffic "${port}")"

    [[ "${current}" =~ ^[0-9]+$ ]] || current=0

    # 当前没有流量，不需要重建
    if (( current == 0 )); then
        return 0
    fi

    used="$(jq -r --arg n "${username}" \
        '.[] | select(.name == $n) | (.used // 0)' \
        "${USERS_FILE}" |
        head -n 1)"

    [[ "${used}" =~ ^[0-9]+$ ]] || used=0

    total=$((used + current))

    # 写入累计值
    local tmp

    tmp="$(mktemp)"

    jq --arg n "${username}" \
       --argjson total "${total}" \
       'map(
            if .name == $n
            then .used = $total
            else .
            end
        )' \
        "${USERS_FILE}" > "${tmp}"

    mv -f "${tmp}" "${USERS_FILE}"

    # 重新创建统计链，使计数器从 0 开始
    add_traffic_rules "${port}"
}


###############################################################################
# 重建全部 iptables
#
# 重建之前先同步已有流量，避免计数器归零造成数据丢失。
###############################################################################

rebuild_iptables() {

    info "正在重建 iptables 流量统计规则..."

    local username
    local port
    local enabled
    local reason

    while IFS= read -r username; do

        [[ -z "${username}" ]] && continue

        # 先同步当前计数
        sync_user_traffic "${username}"

        port="$(
            jq -r --arg n "${username}" \
                '.[] | select(.name == $n) | .port' \
                "${USERS_FILE}" |
            head -n 1
        )"

        enabled="$(
            jq -r --arg n "${username}" \
                '.[] | select(.name == $n) | (.enabled // true)' \
                "${USERS_FILE}" |
            head -n 1
        )"

        reason="$(
            jq -r --arg n "${username}" \
                '.[] | select(.name == $n) | (.disabled_reason // "")' \
                "${USERS_FILE}" |
            head -n 1
        )"

        [[ -z "${port}" || "${port}" == "null" ]] && continue

        # 先清理
        remove_port_rules "${port}"

        if [[ "${enabled}" == "true" && -z "${reason}" ]]; then
            add_traffic_rules "${port}"
        else
            add_block_rules "${port}"
        fi

    done < <(jq -r '.[].name' "${USERS_FILE}")

    save_users
}


###############################################################################
# 生成 Shadowsocks-Rust config.json
###############################################################################

generate_config() {

    # 没有用户：
    # 不生成空服务器配置。
    if ! has_users; then
        rm -f "${SS_CONFIG}"
        return 0
    fi

    local tmp

    tmp="$(mktemp)"

    jq '
    {
        servers:
        [
            .[] |
            {
                server: "0.0.0.0",
                server_port: (.port | tonumber),
                password: .password,
                method: (.method // "aes-256-gcm")
            }
            +
            (
                if (.enabled // true) == false
                then
                    {
                        disabled: true
                    }
                else
                    {}
                end
            )
        ]
    }
    ' "${USERS_FILE}" > "${tmp}" || {
        rm -f "${tmp}"
        die "生成 Shadowsocks 配置失败。"
    }

    mv -f "${tmp}" "${SS_CONFIG}"

    chmod 600 "${SS_CONFIG}"
}


###############################################################################
# 验证 Shadowsocks 配置
###############################################################################

validate_ss_config() {

    # 没有用户时不需要验证
    if ! has_users; then
        return 0
    fi

    [[ -x "${BIN_PATH}" ]] || {
        err "找不到 ssserver：${BIN_PATH}"
        return 1
    }

    [[ -f "${SS_CONFIG}" ]] || {
        err "找不到配置文件：${SS_CONFIG}"
        return 1
    }

    if ! jq empty "${SS_CONFIG}" >/dev/null 2>&1; then
        err "config.json JSON 格式错误。"
        return 1
    fi

    local count

    count="$(jq '.servers | length' "${SS_CONFIG}")"

    if (( count <= 0 )); then
        err "config.json 中没有服务器。"
        return 1
    fi

    return 0
}


###############################################################################
# 创建 systemd 服务
###############################################################################

create_systemd_service() {

    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Shadowsocks Rust Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

ExecStart=${BIN_PATH} -c ${SS_CONFIG}

Restart=always
RestartSec=3

LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SERVICE_FILE}"

    systemctl daemon-reload
}


###############################################################################
# 停止 Shadowsocks
###############################################################################

stop_shadowsocks() {

    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

    # 防止 systemd 停止后还有残留进程
    pkill -TERM -x ssserver 2>/dev/null || true

    sleep 1

    pkill -KILL -x ssserver 2>/dev/null || true
}


###############################################################################
# 启动 Shadowsocks
###############################################################################

start_shadowsocks_if_needed() {

    # 没有用户：
    # 不启动 Shadowsocks。
    if ! has_users; then

        stop_shadowsocks

        rm -f "${SS_CONFIG}"

        return 0
    fi

    generate_config

    validate_ss_config || return 1

    systemctl daemon-reload

    systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1

    systemctl restart "${SERVICE_NAME}"

    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}"; then

        ok "Shadowsocks-Rust 已启动。"

        return 0
    fi

    err "Shadowsocks-Rust 启动失败。"

    echo
    echo "当前配置："
    jq '.' "${SS_CONFIG}" 2>/dev/null || true

    echo
    echo "最近日志："

    journalctl \
        -u "${SERVICE_NAME}" \
        -n 30 \
        --no-pager 2>/dev/null || true

    return 1
}


###############################################################################
# 创建 Cron
###############################################################################

setup_cron() {

    cat > "${CRON_FILE}" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

*/5 * * * * root ${MANAGER_PATH} traffic-check >> ${LOG_FILE} 2>&1
EOF

    chmod 644 "${CRON_FILE}"

    # 尝试启动 cron
    systemctl enable cron 2>/dev/null || true
    systemctl restart cron 2>/dev/null || true
}


###############################################################################
# 检查用户周期
###############################################################################

process_user_cycle() {

    local username="$1"

    local user_json
    local now
    local created_at
    local next_reset
    local expire
    local enabled
    local reason
    local new_next

    user_json="$(
        jq -c --arg n "${username}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    [[ -z "${user_json}" ]] && return 0

    now="$(now_ts)"

    created_at="$(jq -r '.created_at // 0' <<<"${user_json}")"
    next_reset="$(jq -r '.next_reset // 0' <<<"${user_json}")"
    expire="$(jq -r '.expire // 0' <<<"${user_json}")"
    enabled="$(jq -r '(.enabled // true)' <<<"${user_json}")"
    reason="$(jq -r '.disabled_reason // ""' <<<"${user_json}")"

    ###########################################################################
    # 第一优先级：账号到期
    #
    # 到期用户永久禁用。
    ###########################################################################

    if (( expire > 0 && now >= expire )); then

        if [[ "${enabled}" == "true" || "${reason}" != "expired" ]]; then

            local port

            port="$(jq -r '.port' <<<"${user_json}")"

            remove_port_rules "${port}"
            add_block_rules "${port}"

            local tmp

            tmp="$(mktemp)"

            jq --arg n "${username}" \
               '
               map(
                   if .name == $n
                   then
                       .enabled = false |
                       .disabled_reason = "expired"
                   else
                       .
                   end
               )
               ' "${USERS_FILE}" > "${tmp}"

            mv -f "${tmp}" "${USERS_FILE}"
        fi

        return 0
    fi

    ###########################################################################
    # 周期还没到
    ###########################################################################

    if (( now < next_reset )); then
        return 0
    fi

    ###########################################################################
    # 新周期
    #
    # 注意：
    #
    # created_at 永远不变。
    #
    # next_reset：
    #   根据 created_at 往后计算。
    ###########################################################################

    new_next="$(calculate_next_reset "${created_at}" "${now}")"

    local port

    port="$(jq -r '.port' <<<"${user_json}")"

    # 清理旧规则
    remove_port_rules "${port}"

    # 流量归零
    # 同时保留 created_at
    local tmp

    tmp="$(mktemp)"

    jq --arg n "${username}" \
       --argjson next "${new_next}" \
       '
       map(
           if .name == $n
           then
               .used = 0 |
               .last_reset = now |
               .next_reset = $next |
               (
                   if .disabled_reason == "traffic"
                   then
                       .enabled = true |
                       .disabled_reason = ""
                   else
                       .
                   end
               )
           else
               .
           end
       )
       ' "${USERS_FILE}" > "${tmp}"

    mv -f "${tmp}" "${USERS_FILE}"

    # 如果不是过期状态，
    # 新周期恢复正常统计。
    add_traffic_rules "${port}"
}


###############################################################################
# 检查用户流量
###############################################################################

check_user_traffic() {

    local username="$1"

    local user_json
    local enabled
    local reason
    local limit
    local port
    local used
    local current
    local total

    user_json="$(
        jq -c --arg n "${username}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    [[ -z "${user_json}" ]] && return 0

    enabled="$(jq -r '(.enabled // true)' <<<"${user_json}")"
    reason="$(jq -r '.disabled_reason // ""' <<<"${user_json}")"

    # 已经禁用，不继续统计
    if [[ "${enabled}" != "true" ]]; then
        return 0
    fi

    # 已经是其他禁用状态
    if [[ -n "${reason}" ]]; then
        return 0
    fi

    limit="$(jq -r '.limit // 0' <<<"${user_json}")"
    port="$(jq -r '.port' <<<"${user_json}")"
    used="$(jq -r '.used // 0' <<<"${user_json}")"

    [[ "${limit}" =~ ^[0-9]+$ ]] || limit=0
    [[ "${used}" =~ ^[0-9]+$ ]] || used=0

    # 0 = 不限制
    if (( limit == 0 )); then
        return 0
    fi

    # 当前链实时流量
    current="$(get_port_traffic "${port}")"

    [[ "${current}" =~ ^[0-9]+$ ]] || current=0

    total=$((used + current))

    ###########################################################################
    # 超过限制
    ###########################################################################

    if (( total >= limit )); then

        # 先把当前计数写入 JSON
        local tmp

        tmp="$(mktemp)"

        jq --arg n "${username}" \
           --argjson total "${total}" \
           '
           map(
               if .name == $n
               then
                   .used = $total |
                   .enabled = false |
                   .disabled_reason = "traffic"
               else
                   .
               end
           )
           ' "${USERS_FILE}" > "${tmp}"

        mv -f "${tmp}" "${USERS_FILE}"

        # 阻断端口
        add_block_rules "${port}"

        warn "用户 ${username} 已达到流量限制：$(bytes_to_human "${total}")"

        return 0
    fi
}


###############################################################################
# 自动流量检查
###############################################################################

traffic_check() {

    init_dirs
    migrate_users

    # 没有用户
    if ! has_users; then

        stop_shadowsocks

        rm -f "${SS_CONFIG}"

        exit 0
    fi

    local username

    ###########################################################################
    # 第一步：
    # 先同步所有用户的 iptables 计数。
    #
    # 这样后续周期重置、规则重建都不会丢流量。
    ###########################################################################

    while IFS= read -r username; do

        [[ -z "${username}" ]] && continue

        sync_user_traffic "${username}"

    done < <(jq -r '.[].name' "${USERS_FILE}")


    ###########################################################################
    # 第二步：
    # 检查 30 天周期。
    ###########################################################################

    while IFS= read -r username; do

        [[ -z "${username}" ]] && continue

        process_user_cycle "${username}"

    done < <(jq -r '.[].name' "${USERS_FILE}")


    ###########################################################################
    # 第三步：
    # 检查流量限制。
    ###########################################################################

    while IFS= read -r username; do

        [[ -z "${username}" ]] && continue

        check_user_traffic "${username}"

    done < <(jq -r '.[].name' "${USERS_FILE}")


    save_users

    ###########################################################################
    # 第四步：
    # 更新 Shadowsocks 配置。
    #
    # 只有用户状态变化时才真正需要 systemd reload。
    # 这里直接生成配置，然后如果服务没启动则启动。
    ###########################################################################

    generate_config

    if ! systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then

        if has_users; then
            start_shadowsocks_if_needed >/dev/null 2>&1 || true
        fi

    fi
}


###############################################################################
# 检查端口是否已经被其他用户使用
###############################################################################

port_exists() {

    local port="$1"

    jq -e --argjson p "${port}" \
        'any(.[]; (.port | tonumber) == $p)' \
        "${USERS_FILE}" >/dev/null 2>&1
}


###############################################################################
# 获取下一个可用端口
###############################################################################

get_next_port() {

    local port="${DEFAULT_PORT}"

    while port_exists "${port}"; do
        port=$((port + 1))
    done

    echo "${port}"
}


###############################################################################
# 添加用户
###############################################################################

add_user() {

    echo
    echo "========================================"
    echo " 添加 Shadowsocks 用户"
    echo "========================================"
    echo

    local name
    local port
    local password
    local method
    local limit_input
    local limit
    local expire_days
    local now
    local next_reset
    local expire

    read -r -p "用户名： " name

    if [[ -z "${name}" ]]; then
        err "用户名不能为空。"
        return 1
    fi

    if jq -e --arg n "${name}" \
        'any(.[]; .name == $n)' \
        "${USERS_FILE}" >/dev/null 2>&1; then

        err "用户已存在：${name}"
        return 1
    fi

    local suggested_port

    suggested_port="$(get_next_port)"

    read -r -p "端口 [${suggested_port}]： " port

    port="${port:-${suggested_port}}"

    if ! [[ "${port}" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        err "端口无效。"
        return 1
    fi

    if port_exists "${port}"; then
        err "端口 ${port} 已被其他用户使用。"
        return 1
    fi

    read -r -p "密码 [自动生成]： " password

    if [[ -z "${password}" ]]; then
        password="$(random_password)"
    fi

    read -r -p "加密方式 [${DEFAULT_METHOD}]： " method

    method="${method:-${DEFAULT_METHOD}}"

    read -r -p "流量限制 [例如 100G，0=不限]： " limit_input

    limit_input="${limit_input:-0}"

    limit="$(parse_limit "${limit_input}")"

    if [[ "${limit}" == "0" && "${limit_input}" != "0" && -n "${limit_input}" ]]; then
        warn "无法识别流量限制，将设置为不限。"
        limit=0
    fi

    read -r -p "账号有效天数 [0=永久]： " expire_days

    expire_days="${expire_days:-0}"

    if ! [[ "${expire_days}" =~ ^[0-9]+$ ]]; then
        err "有效天数必须是数字。"
        return 1
    fi

    now="$(now_ts)"

    next_reset=$((now + RESET_SECONDS))

    if (( expire_days > 0 )); then
        expire=$((now + expire_days * 86400))
    else
        expire=0
    fi

    ###########################################################################
    # 写入用户
    ###########################################################################

    local tmp

    tmp="$(mktemp)"

    jq \
        --arg name "${name}" \
        --arg password "${password}" \
        --arg method "${method}" \
        --argjson port "${port}" \
        --argjson limit "${limit}" \
        --argjson created_at "${now}" \
        --argjson next_reset "${next_reset}" \
        --argjson expire "${expire}" \
        '
        . + [
            {
                name: $name,
                port: $port,
                password: $password,
                method: $method,

                limit: $limit,
                used: 0,

                created_at: $created_at,
                next_reset: $next_reset,
                last_reset: 0,

                expire: $expire,

                enabled: true,
                disabled_reason: ""
            }
        ]
        ' "${USERS_FILE}" > "${tmp}" || {
            rm -f "${tmp}"
            err "写入用户失败。"
            return 1
        }

    mv -f "${tmp}" "${USERS_FILE}"

    chmod 600 "${USERS_FILE}"

    ###########################################################################
    # 创建流量统计规则
    ###########################################################################

    add_traffic_rules "${port}"

    ###########################################################################
    # 生成配置
    ###########################################################################

    generate_config

    start_shadowsocks_if_needed || return 1

    save_users

    ###########################################################################
    # 获取公网 IP
    ###########################################################################

    local server_ip

    server_ip="$(get_public_ipv4 2>/dev/null || true)"

    echo
    echo "========================================"
    echo -e "${GREEN} 用户添加成功${RESET}"
    echo "========================================"
    echo
    echo "用户名：${name}"
    echo "服务器：${server_ip:-获取失败}"
    echo "端口：${port}"
    echo "密码：${password}"
    echo "加密：${method}"
    echo "流量：$(
        if (( limit > 0 )); then
            bytes_to_human "${limit}"
        else
            echo "不限"
        fi
    )"
    echo "创建时间：$(format_ts "${now}")"
    echo "下次流量重置：$(format_ts "${next_reset}")"

    if (( expire > 0 )); then
        echo "账号到期：$(format_ts "${expire}")"
    else
        echo "账号到期：永久"
    fi

    echo
    echo "----------------------------------------"
    echo "Shadowsocks 导入链接"
    echo "----------------------------------------"

    if [[ -n "${server_ip}" ]]; then

        generate_ss_link \
            "${port}" \
            "${password}" \
            "${method}" \
            "${name}" \
            "${server_ip}"

    else

        warn "无法自动获取公网 IPv4。"
        warn "请稍后在“用户详情”中重新获取。"

    fi

    echo
    echo "========================================"
    echo
}


###############################################################################
# 删除用户
###############################################################################

delete_user() {

    echo

    local name

    read -r -p "请输入要删除的用户名： " name

    if [[ -z "${name}" ]]; then
        return
    fi

    if ! jq -e --arg n "${name}" \
        'any(.[]; .name == $n)' \
        "${USERS_FILE}" >/dev/null 2>&1; then

        err "用户不存在：${name}"
        return 1
    fi

    local port

    port="$(
        jq -r --arg n "${name}" \
            '.[] | select(.name == $n) | .port' \
            "${USERS_FILE}" |
        head -n 1
    )"

    echo
    warn "即将删除用户：${name}"
    read -r -p "确定删除？输入 YES： " confirm

    [[ "${confirm}" == "YES" ]] || {
        echo "已取消。"
        return
    }

    # 删除 iptables
    remove_port_rules "${port}"

    # 删除 JSON
    local tmp

    tmp="$(mktemp)"

    jq --arg n "${name}" \
       'map(select(.name != $n))' \
       "${USERS_FILE}" > "${tmp}"

    mv -f "${tmp}" "${USERS_FILE}"

    save_users

    ###########################################################################
    # 如果已经没有用户：
    # 停止 Shadowsocks
    ###########################################################################

    if ! has_users; then

        stop_shadowsocks

        rm -f "${SS_CONFIG}"

        ok "用户已删除。"
        ok "已经没有用户，Shadowsocks-Rust 已停止。"

        return
    fi

    ###########################################################################
    # 还有用户
    ###########################################################################

    rebuild_iptables
    generate_config
    start_shadowsocks_if_needed

    ok "用户 ${name} 已删除。"
}


###############################################################################
# 重置单个用户流量
#
# 注意：
#   不修改 created_at
#   不修改 expire
#   next_reset 仍然按照 created_at 计算
###############################################################################

reset_user_traffic() {

    echo

    local name

    read -r -p "请输入用户名： " name

    if [[ -z "${name}" ]]; then
        return
    fi

    local user_json

    user_json="$(
        jq -c --arg n "${name}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    if [[ -z "${user_json}" ]]; then
        err "用户不存在。"
        return 1
    fi

    local expire
    local now
    local created_at
    local next_reset
    local port
    local enabled
    local reason

    expire="$(jq -r '.expire // 0' <<<"${user_json}")"
    created_at="$(jq -r '.created_at // 0' <<<"${user_json}")"
    port="$(jq -r '.port' <<<"${user_json}")"
    enabled="$(jq -r '(.enabled // true)' <<<"${user_json}")"
    reason="$(jq -r '.disabled_reason // ""' <<<"${user_json}")"

    now="$(now_ts)"

    ###########################################################################
    # 已过期：
    # 即使手动重置流量，也不能恢复账号。
    ###########################################################################

    if (( expire > 0 && now >= expire )); then

        warn "该用户账号已经到期。"
        warn "手动重置流量不会恢复已过期账号。"

        remove_port_rules "${port}"
        add_block_rules "${port}"

        local tmp

        tmp="$(mktemp)"

        jq --arg n "${name}" \
           '
           map(
               if .name == $n
               then
                   .used = 0 |
                   .enabled = false |
                   .disabled_reason = "expired"
               else
                   .
               end
           )
           ' "${USERS_FILE}" > "${tmp}"

        mv -f "${tmp}" "${USERS_FILE}"

        save_users

        return
    fi

    ###########################################################################
    # 计算 next_reset
    #
    # 永远从 created_at 计算。
    ###########################################################################

    next_reset="$(calculate_next_reset "${created_at}" "${now}")"

    ###########################################################################
    # 删除旧计数规则
    ###########################################################################

    remove_port_rules "${port}"

    ###########################################################################
    # 重置 JSON 流量
    ###########################################################################

    local tmp

    tmp="$(mktemp)"

    jq --arg n "${name}" \
       --argjson next "${next_reset}" \
       '
       map(
           if .name == $n
           then
               .used = 0 |
               .last_reset = now |
               .next_reset = $next |
               .enabled = true |
               .disabled_reason = ""
           else
               .
           end
       )
       ' "${USERS_FILE}" > "${tmp}"

    mv -f "${tmp}" "${USERS_FILE}"

    # 新统计链
    add_traffic_rules "${port}"

    save_users

    generate_config

    start_shadowsocks_if_needed

    ok "用户 ${name} 流量已重置。"
    info "created_at：$(format_ts "${created_at}")"
    info "下次周期重置：$(format_ts "${next_reset}")"
}


###############################################################################
# 重置全部用户流量
###############################################################################

reset_all_traffic() {

    echo
    warn "即将重置所有未过期用户流量。"
    warn "created_at 不会修改。"
    echo

    read -r -p "确定继续？输入 YES： " confirm

    [[ "${confirm}" == "YES" ]] || {
        echo "已取消。"
        return
    }

    local username

    while IFS= read -r username; do

        [[ -z "${username}" ]] && continue

        # 使用内部逻辑直接重置
        local user_json
        local expire
        local created_at
        local now
        local next_reset
        local port

        user_json="$(
            jq -c --arg n "${username}" \
                '.[] | select(.name == $n)' \
                "${USERS_FILE}" |
            head -n 1
        )"

        [[ -z "${user_json}" ]] && continue

        expire="$(jq -r '.expire // 0' <<<"${user_json}")"
        created_at="$(jq -r '.created_at // 0' <<<"${user_json}")"
        port="$(jq -r '.port' <<<"${user_json}")"

        now="$(now_ts)"

        # 已过期用户保持禁用
        if (( expire > 0 && now >= expire )); then

            remove_port_rules "${port}"
            add_block_rules "${port}"

            local tmp_expired

            tmp_expired="$(mktemp)"

            jq --arg n "${username}" \
               '
               map(
                   if .name == $n
                   then
                       .enabled = false |
                       .disabled_reason = "expired"
                   else
                       .
                   end
               )
               ' "${USERS_FILE}" > "${tmp_expired}"

            mv -f "${tmp_expired}" "${USERS_FILE}"

            continue
        fi

        next_reset="$(calculate_next_reset "${created_at}" "${now}")"

        remove_port_rules "${port}"

        local tmp

        tmp="$(mktemp)"

        jq --arg n "${username}" \
           --argjson next "${next_reset}" \
           '
           map(
               if .name == $n
               then
                   .used = 0 |
                   .last_reset = now |
                   .next_reset = $next |
                   .enabled = true |
                   .disabled_reason = ""
               else
                   .
               end
           )
           ' "${USERS_FILE}" > "${tmp}"

        mv -f "${tmp}" "${USERS_FILE}"

        add_traffic_rules "${port}"

    done < <(jq -r '.[].name' "${USERS_FILE}")

    save_users

    generate_config

    start_shadowsocks_if_needed

    ok "所有未过期用户流量已重置。"
}


###############################################################################
# 用户列表
###############################################################################

list_users() {

    echo
    echo "================================================================================"
    echo " Shadowsocks 用户列表"
    echo "================================================================================"

    if ! has_users; then
        echo
        echo "暂无用户。"
        echo
        return
    fi

    local server_ip

    server_ip="$(get_public_ipv4 2>/dev/null || true)"

    echo

    printf "%-16s %-7s %-13s %-13s %-18s %-16s\n" \
        "用户名" \
        "端口" \
        "已使用" \
        "流量限制" \
        "下次重置" \
        "状态"

    echo "--------------------------------------------------------------------------------"

    local username

    while IFS= read -r username; do

        local json

        json="$(
            jq -c --arg n "${username}" \
                '.[] | select(.name == $n)' \
                "${USERS_FILE}" |
            head -n 1
        )"

        local port
        local used
        local limit
        local next_reset
        local expire
        local enabled
        local reason
        local current
        local total
        local status

        port="$(jq -r '.port' <<<"${json}")"
        used="$(jq -r '.used // 0' <<<"${json}")"
        limit="$(jq -r '.limit // 0' <<<"${json}")"
        next_reset="$(jq -r '.next_reset // 0' <<<"${json}")"
        expire="$(jq -r '.expire // 0' <<<"${json}")"
        enabled="$(jq -r '(.enabled // true)' <<<"${json}")"
        reason="$(jq -r '.disabled_reason // ""' <<<"${json}")"

        [[ "${used}" =~ ^[0-9]+$ ]] || used=0

        current="$(get_port_traffic "${port}")"

        [[ "${current}" =~ ^[0-9]+$ ]] || current=0

        total=$((used + current))

        if [[ "${enabled}" == "true" ]]; then

            status="正常"

        elif [[ "${reason}" == "traffic" ]]; then

            status="流量超限"

        elif [[ "${reason}" == "expired" ]]; then

            status="账号到期"

        else

            status="已禁用"

        fi

        local used_text
        local limit_text

        used_text="$(bytes_to_human "${total}")"

        if (( limit > 0 )); then
            limit_text="$(bytes_to_human "${limit}")"
        else
            limit_text="不限"
        fi

        printf "%-16s %-7s %-13s %-13s %-18s %-16s\n" \
            "${username}" \
            "${port}" \
            "${used_text}" \
            "${limit_text}" \
            "$(format_ts "${next_reset}")" \
            "${status}"

    done < <(jq -r '.[].name' "${USERS_FILE}")

    echo
}


###############################################################################
# 显示用户详情
###############################################################################

show_user() {

    echo

    local name

    read -r -p "请输入用户名： " name

    [[ -z "${name}" ]] && return

    local json

    json="$(
        jq -c --arg n "${name}" \
            '.[] | select(.name == $n)' \
            "${USERS_FILE}" |
        head -n 1
    )"

    if [[ -z "${json}" ]]; then
        err "用户不存在。"
        return 1
    fi

    local port
    local password
    local method
    local limit
    local used
    local created_at
    local next_reset
    local expire
    local enabled
    local reason
    local current
    local total
    local ip

    port="$(jq -r '.port' <<<"${json}")"
    password="$(jq -r '.password' <<<"${json}")"
    method="$(jq -r '.method // "aes-256-gcm"' <<<"${json}")"
    limit="$(jq -r '.limit // 0' <<<"${json}")"
    used="$(jq -r '.used // 0' <<<"${json}")"
    created_at="$(jq -r '.created_at // 0' <<<"${json}")"
    next_reset="$(jq -r '.next_reset // 0' <<<"${json}")"
    expire="$(jq -r '.expire // 0' <<<"${json}")"
    enabled="$(jq -r '(.enabled // true)' <<<"${json}")"
    reason="$(jq -r '.disabled_reason // ""' <<<"${json}")"

    current="$(get_port_traffic "${port}")"

    [[ "${current}" =~ ^[0-9]+$ ]] || current=0
    [[ "${used}" =~ ^[0-9]+$ ]] || used=0

    total=$((used + current))

    ip="$(get_public_ipv4 2>/dev/null || true)"

    echo
    echo "========================================"
    echo " 用户详情"
    echo "========================================"
    echo

    echo "用户名：${name}"
    echo "服务器：${ip:-获取失败}"
    echo "端口：${port}"
    echo "密码：${password}"
    echo "加密：${method}"

    echo
    echo "流量："

    if (( limit > 0 )); then
        echo "  已使用：$(bytes_to_human "${total}")"
        echo "  限制：$(bytes_to_human "${limit}")"

        local percent

        percent="$(
            awk \
                -v used="${total}" \
                -v limit="${limit}" \
                'BEGIN {
                    if (limit <= 0) print 0;
                    else printf "%.2f", used / limit * 100
                }'
        )"

        echo "  使用率：${percent}%"

    else

        echo "  已使用：$(bytes_to_human "${total}")"
        echo "  限制：不限"

    fi

    echo
    echo "创建时间：$(format_ts "${created_at}")"
    echo "下次周期重置：$(format_ts "${next_reset}")"

    if (( expire > 0 )); then
        echo "账号到期：$(format_ts "${expire}")"
        echo "剩余：$(remaining_time "${expire}")"
    else
        echo "账号到期：永久"
    fi

    echo

    if [[ "${enabled}" == "true" ]]; then
        echo "状态：正常"
    elif [[ "${reason}" == "traffic" ]]; then
        echo "状态：流量超限"
    elif [[ "${reason}" == "expired" ]]; then
        echo "状态：账号已到期"
    else
        echo "状态：已禁用"
    fi

    echo
    echo "----------------------------------------"
    echo "Shadowsocks 导入链接"
    echo "----------------------------------------"

    if [[ -n "${ip}" ]]; then

        generate_ss_link \
            "${port}" \
            "${password}" \
            "${method}" \
            "${name}" \
            "${ip}"

    else

        warn "无法获取服务器公网 IPv4。"

    fi

    echo
}


###############################################################################
# 导出全部用户 SS 链接
###############################################################################

export_all_links() {

    echo
    echo "========================================"
    echo " Shadowsocks 用户导入链接"
    echo "========================================"
    echo

    if ! has_users; then
        warn "当前没有用户。"
        return
    fi

    local server_ip

    server_ip="$(get_public_ipv4 2>/dev/null || true)"

    if [[ -z "${server_ip}" ]]; then
        err "无法获取服务器公网 IPv4。"
        return 1
    fi

    echo "服务器 IP：${server_ip}"
    echo

    local username

    while IFS= read -r username; do

        [[ -z "${username}" ]] && continue

        local json
        local port
        local password
        local method
        local enabled
        local reason

        json="$(
            jq -c --arg n "${username}" \
                '.[] | select(.name == $n)' \
                "${USERS_FILE}" |
            head -n 1
        )"

        port="$(jq -r '.port' <<<"${json}")"
        password="$(jq -r '.password' <<<"${json}")"
        method="$(jq -r '.method // "aes-256-gcm"' <<<"${json}")"
        enabled="$(jq -r '(.enabled // true)' <<<"${json}")"
        reason="$(jq -r '.disabled_reason // ""' <<<"${json}")"

        echo "----------------------------------------"
        echo "用户：${username}"

        if [[ "${enabled}" == "true" ]]; then
            echo "状态：正常"
        elif [[ "${reason}" == "traffic" ]]; then
            echo "状态：流量超限"
        elif [[ "${reason}" == "expired" ]]; then
            echo "状态：账号到期"
        else
            echo "状态：已禁用"
        fi

        echo "端口：${port}"
        echo
        generate_ss_link \
            "${port}" \
            "${password}" \
            "${method}" \
            "${username}" \
            "${server_ip}"

        echo

    done < <(jq -r '.[].name' "${USERS_FILE}")

    echo "========================================"
    echo
}


###############################################################################
# Shadowsocks 服务状态
###############################################################################

service_status() {

    echo
    echo "========================================"
    echo " Shadowsocks-Rust 服务状态"
    echo "========================================"
    echo

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "服务状态：${GREEN}运行中${RESET}"
    else
        echo -e "服务状态：${RED}未运行${RESET}"
    fi

    echo

    systemctl status \
        "${SERVICE_NAME}" \
        --no-pager \
        -l 2>/dev/null || true

    echo
}


###############################################################################
# 查看日志
###############################################################################

show_logs() {

    echo
    echo "========================================"
    echo " Shadowsocks-Rust 日志"
    echo "========================================"
    echo

    journalctl \
        -u "${SERVICE_NAME}" \
        -n 100 \
        --no-pager 2>/dev/null || true

    echo
}


###############################################################################
# 更新 Shadowsocks-Rust
###############################################################################

update_shadowsocks() {

    echo
    echo "========================================"
    echo " 更新 Shadowsocks-Rust"
    echo "========================================"
    echo

    if ! [[ -x "${BIN_PATH}" ]]; then
        install_shadowsocks
        create_systemd_service
        generate_config
        start_shadowsocks_if_needed
        return
    fi

    local old_version

    old_version="$(
        "${BIN_PATH}" --version 2>/dev/null |
        head -n 1
    )"

    info "当前版本：${old_version}"

    install_shadowsocks

    create_systemd_service

    if has_users; then

        generate_config
        start_shadowsocks_if_needed

    else

        stop_shadowsocks
        rm -f "${SS_CONFIG}"

    fi

    ok "更新完成。"
}


###############################################################################
# 安装全部组件
###############################################################################

install_all() {

    echo
    echo "========================================"
    echo " Shadowsocks-Rust 多用户管理器"
    echo " 首次安装"
    echo "========================================"
    echo

    install_dependencies

    check_dependencies

    init_dirs

    migrate_users

    ###########################################################################
    # 如果没有 ssserver，安装。
    ###########################################################################

    if [[ ! -x "${BIN_PATH}" ]]; then

        install_shadowsocks

    else

        info "检测到已有 Shadowsocks-Rust，跳过重复安装。"

    fi

    ###########################################################################
    # 创建 systemd
    ###########################################################################

    create_systemd_service

    ###########################################################################
    # 创建 Cron
    ###########################################################################

    setup_cron

    ###########################################################################
    # 初始化 iptables
    ###########################################################################

    if has_users; then

        rebuild_iptables

        generate_config

        start_shadowsocks_if_needed

    else

        #######################################################################
        # 关键：
        #
        # 首次安装没有用户：
        #
        #   不启动 ssserver
        #   不生成空 config.json
        #
        # 但是安装完成以后仍然进入管理菜单。
        #######################################################################

        stop_shadowsocks

        rm -f "${SS_CONFIG}"

        info "当前没有用户。"
        info "Shadowsocks-Rust 暂不启动。"

    fi

    ok "安装完成。"
}


###############################################################################
# 卸载
###############################################################################

uninstall() {

    echo
    echo "========================================"
    echo " 卸载 Shadowsocks-Rust 多用户管理器"
    echo "========================================"
    echo

    warn "此操作将删除："
    echo "  - Shadowsocks-Rust"
    echo "  - 所有用户配置"
    echo "  - systemd 服务"
    echo "  - Cron"
    echo "  - iptables 流量规则"
    echo "  - ss-manager"
    echo

    read -r -p "确认卸载？请输入 YES： " confirm

    if [[ "${confirm}" != "YES" ]]; then
        echo "已取消。"
        return
    fi

    info "停止 Shadowsocks-Rust..."

    ###########################################################################
    # 必须先停止 systemd
    #
    # 否则：
    #
    # Restart=always
    #
    # 删除文件以后 systemd 可能继续尝试拉起服务。
    ###########################################################################

    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

    ###########################################################################
    # 删除 systemd
    ###########################################################################

    rm -f "${SERVICE_FILE}"

    systemctl daemon-reload

    ###########################################################################
    # 杀掉残留进程
    ###########################################################################

    pkill -TERM -x ssserver 2>/dev/null || true

    sleep 1

    pkill -KILL -x ssserver 2>/dev/null || true

    ###########################################################################
    # 删除 Cron
    ###########################################################################

    rm -f "${CRON_FILE}"

    systemctl restart cron 2>/dev/null || true

    ###########################################################################
    # 清理 iptables
    ###########################################################################

    if [[ -f "${USERS_FILE}" ]]; then

        while IFS= read -r port; do

            [[ -z "${port}" ]] && continue

            remove_port_rules "${port}"

        done < <(
            jq -r '.[].port' "${USERS_FILE}" 2>/dev/null
        )

    fi

    ###########################################################################
    # 删除 Shadowsocks
    ###########################################################################

    rm -f "${BIN_PATH}"
    rm -f "${BIN_PATH}.bak"

    ###########################################################################
    # 删除配置
    ###########################################################################

    rm -rf "${CONFIG_DIR}"

    ###########################################################################
    # 再次确保 systemd 不会复活
    ###########################################################################

    systemctl daemon-reload
    systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

    ###########################################################################
    # 删除管理脚本
    ###########################################################################

    rm -f "${MANAGER_PATH}"

    ok "卸载完成。"

    exit 0
}


###############################################################################
# 主菜单
###############################################################################

main_menu() {

    while true; do

        clear

        echo
        echo "╔══════════════════════════════════════════════════╗"
        echo "║       Shadowsocks-Rust 多用户管理器             ║"
        echo "╠══════════════════════════════════════════════════╣"
        echo "║  1. 添加用户                                    ║"
        echo "║  2. 删除用户                                    ║"
        echo "║  3. 用户列表                                    ║"
        echo "║  4. 用户详情                                    ║"
        echo "║  5. 重置用户流量                                ║"
        echo "║  6. 重置全部流量                                ║"
        echo "║  7. 导出全部 SS 导入链接                        ║"
        echo "║  8. 查看服务状态                                ║"
        echo "║  9. 查看日志                                    ║"
        echo "║ 10. 更新 Shadowsocks-Rust                       ║"
        echo "║ 11. 手动执行流量检查                            ║"
        echo "║ 12. 重建 iptables 规则                          ║"
        echo "║ 13. 卸载                                        ║"
        echo "║  0. 退出                                        ║"
        echo "╚══════════════════════════════════════════════════╝"
        echo

        local choice

        read -r -p "请选择 [0-13]： " choice

        case "${choice}" in

            1)
                add_user
                read -r -p "按回车继续..."
                ;;

            2)
                delete_user
                read -r -p "按回车继续..."
                ;;

            3)
                list_users
                read -r -p "按回车继续..."
                ;;

            4)
                show_user
                read -r -p "按回车继续..."
                ;;

            5)
                reset_user_traffic
                read -r -p "按回车继续..."
                ;;

            6)
                reset_all_traffic
                read -r -p "按回车继续..."
                ;;

            7)
                export_all_links
                read -r -p "按回车继续..."
                ;;

            8)
                service_status
                read -r -p "按回车继续..."
                ;;

            9)
                show_logs
                read -r -p "按回车继续..."
                ;;

            10)
                update_shadowsocks
                read -r -p "按回车继续..."
                ;;

            11)
                traffic_check
                ok "流量检查完成。"
                read -r -p "按回车继续..."
                ;;

            12)
                rebuild_iptables
                ok "iptables 重建完成。"
                read -r -p "按回车继续..."
                ;;

            13)
                uninstall
                ;;

            0)
                clear
                exit 0
                ;;

            *)
                warn "无效选项。"
                sleep 1
                ;;

        esac

    done
}


###############################################################################
# 命令行模式
#
# Cron 使用：
#
#   ss-manager traffic-check
#
###############################################################################

case "${1:-}" in

    traffic-check)

        check_root
        init_dirs
        check_dependencies
        migrate_users
        traffic_check

        exit 0
        ;;

    add)

        check_root
        init_dirs
        check_dependencies
        migrate_users
        add_user

        exit 0
        ;;

    list)

        check_root
        init_dirs
        check_dependencies
        migrate_users
        list_users

        exit 0
        ;;

    status)

        check_root
        service_status

        exit 0
        ;;

    logs)

        check_root
        show_logs

        exit 0
        ;;

    update)

        check_root
        init_dirs
        check_dependencies
        update_shadowsocks

        exit 0
        ;;

    uninstall)

        check_root
        uninstall

        exit 0
        ;;

esac


###############################################################################
# 程序入口
###############################################################################

main() {

    check_root

    ###########################################################################
    # 尝试把当前脚本安装到 /usr/local/bin
    ###########################################################################

    install_self

    ###########################################################################
    # 初始化
    ###########################################################################

    init_dirs

    ###########################################################################
    # 安装依赖
    ###########################################################################

    install_dependencies

    check_dependencies

    migrate_users

    ###########################################################################
    # 判断是否已经安装
    ###########################################################################

    if [[ ! -x "${BIN_PATH}" || ! -f "${SERVICE_FILE}" ]]; then

        #######################################################################
        # 第一次安装
        #######################################################################

        install_all

    else

        #######################################################################
        # 已经安装
        #
        # 不重复安装 Shadowsocks-Rust。
        #######################################################################

        create_systemd_service

        setup_cron

        if has_users; then

            # 确保配置存在
            generate_config

            # 确保 iptables 存在
            rebuild_iptables

            # 如果服务没运行则启动
            if ! systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
                start_shadowsocks_if_needed
            fi

        else

            ###################################################################
            # 已安装但没有用户：
            #
            # 不启动 Shadowsocks。
            ###################################################################

            stop_shadowsocks

            rm -f "${SS_CONFIG}"

        fi

    fi

    ###########################################################################
    # 无论首次安装还是已有安装，
    # 最终都进入管理菜单。
    ###########################################################################

    main_menu
}


###############################################################################
# 启动
###############################################################################

main "$@"
