#!/bin/sh
# Nym VPN Installer for OpenWrt/Linux (musl)
# Usage: curl -fsSL https://sh.dialout.net | sh
#
# Environment variables:
#   NYM_VERSION  - Version to install (default: latest)
#   NYM_ARCH     - Override architecture detection
#   NYM_NO_START - Set to 1 to skip starting the service

set -e

REPO="dial0ut/nym-vpn-client"
INSTALL_DIR_DAEMON="/usr/sbin"
INSTALL_DIR_CLIENT="/usr/bin"
CONFIG_DIR="/etc/config"
INIT_DIR="/etc/init.d"
DATA_DIR="/var/lib/nym-vpn"

# Colors (disabled if not tty)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

log_step() {
    printf "${BLUE}==>${NC} %s\n" "$1"
}

detect_arch() {
    if [ -n "$NYM_ARCH" ]; then
        echo "$NYM_ARCH"
        return
    fi

    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        i686|i586|i486|i386)
            echo "i686"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        armv7l|armv7)
            echo "armv7"
            ;;
        # NOTE: mips, mipsel, riscv64 are Rust Tier 3 targets and currently unsupported
        # due to build-std dependency conflicts. See cross-compile-musl.sh for details.
        *)
            log_error "Unsupported architecture: $arch"
            log_error "Supported: x86_64, i686, aarch64, armv7"
            log_error "Override with NYM_ARCH environment variable if needed"
            exit 1
            ;;
    esac
}

detect_init_system() {
    if [ -f /etc/openwrt_release ]; then
        echo "procd"
    elif command -v systemctl >/dev/null 2>&1; then
        echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    else
        echo "none"
    fi
}

get_latest_version() {
    if [ -n "$NYM_VERSION" ]; then
        echo "$NYM_VERSION"
        return
    fi

    local version
    if command -v curl >/dev/null 2>&1; then
        version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        version=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget found. Please install one."
        exit 1
    fi

    if [ -z "$version" ]; then
        log_error "Failed to get latest version"
        exit 1
    fi

    echo "$version"
}

download_file() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_wireguard() {
    if ! modprobe wireguard 2>/dev/null; then
        log_warn "WireGuard kernel module not available"
        log_warn "Make sure your kernel supports WireGuard (Linux 5.6+)"
        log_warn "Or install: opkg install kmod-wireguard"
    else
        log_info "WireGuard kernel module loaded"
    fi
}

install_binaries() {
    local arch="$1"
    local version="$2"
    local base_url="https://github.com/${REPO}/releases/download/${version}"

    log_step "Downloading nym-vpnd..."
    download_file "${base_url}/nym-vpnd-${arch}" "/tmp/nym-vpnd"

    log_step "Downloading nym-vpnc..."
    download_file "${base_url}/nym-vpnc-${arch}" "/tmp/nym-vpnc"

    log_step "Installing binaries..."
    mkdir -p "$INSTALL_DIR_DAEMON" "$INSTALL_DIR_CLIENT"

    install -m 755 /tmp/nym-vpnd "$INSTALL_DIR_DAEMON/nym-vpnd"
    install -m 755 /tmp/nym-vpnc "$INSTALL_DIR_CLIENT/nym-vpnc"

    rm -f /tmp/nym-vpnd /tmp/nym-vpnc

    log_info "Installed nym-vpnd to $INSTALL_DIR_DAEMON/nym-vpnd"
    log_info "Installed nym-vpnc to $INSTALL_DIR_CLIENT/nym-vpnc"
}

install_procd_init() {
    log_step "Installing OpenWrt procd init script..."

    mkdir -p "$INIT_DIR"
    cat > "$INIT_DIR/nym-vpnd" << 'INITEOF'
#!/bin/sh /etc/rc.common
# Nym VPN Daemon init script for OpenWrt

START=90
STOP=10
USE_PROCD=1

PROG=/usr/sbin/nym-vpnd
CONFIG_DIR=/var/lib/nym-vpn

start_service() {
    local enabled
    config_load 'nym-vpn'
    config_get_bool enabled 'settings' 'enabled' '0'

    [ "$enabled" -eq 0 ] && return 0

    mkdir -p "$CONFIG_DIR"

    procd_open_instance
    procd_set_param command "$PROG"
    procd_append_param command --config-dir "$CONFIG_DIR"
    procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param user root
    procd_set_param pidfile /var/run/nym-vpnd.pid
    procd_close_instance
}

stop_service() {
    /usr/bin/nym-vpnc disconnect 2>/dev/null || true
}

reload_service() {
    stop
    start
}

service_triggers() {
    procd_add_reload_trigger "nym-vpn"
}
INITEOF

    chmod 755 "$INIT_DIR/nym-vpnd"
    log_info "Installed init script to $INIT_DIR/nym-vpnd"
}

install_systemd_unit() {
    log_step "Installing systemd service..."

    cat > /etc/systemd/system/nym-vpnd.service << 'UNITEOF'
[Unit]
Description=Nym VPN Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/nym-vpnd --config-dir /var/lib/nym-vpn
ExecStop=/usr/bin/nym-vpnc disconnect
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

    systemctl daemon-reload
    log_info "Installed systemd unit"
}

install_config() {
    local init_system="$1"

    mkdir -p "$DATA_DIR"

    if [ "$init_system" = "procd" ]; then
        mkdir -p "$CONFIG_DIR"
        if [ ! -f "$CONFIG_DIR/nym-vpn" ]; then
            cat > "$CONFIG_DIR/nym-vpn" << 'CONFEOF'
# Nym VPN Configuration

config nym-vpn 'settings'
    # Enable/disable the VPN daemon
    option enabled '0'

    # Network: 'mainnet' or 'canary'
    option network 'mainnet'
CONFEOF
            log_info "Created config at $CONFIG_DIR/nym-vpn"
        else
            log_info "Config already exists at $CONFIG_DIR/nym-vpn"
        fi
    fi
}

enable_service() {
    local init_system="$1"

    case "$init_system" in
        procd)
            "$INIT_DIR/nym-vpnd" enable
            log_info "Service enabled (run '/etc/init.d/nym-vpnd start' to start)"
            ;;
        systemd)
            systemctl enable nym-vpnd
            log_info "Service enabled (run 'systemctl start nym-vpnd' to start)"
            ;;
    esac
}

print_success() {
    local init_system="$1"

    echo ""
    printf "${GREEN}========================================${NC}\n"
    printf "${GREEN}  Nym VPN installed successfully!${NC}\n"
    printf "${GREEN}========================================${NC}\n"
    echo ""

    case "$init_system" in
        procd)
            echo "To enable and start:"
            echo "  uci set nym-vpn.settings.enabled='1'"
            echo "  uci commit nym-vpn"
            echo "  /etc/init.d/nym-vpnd start"
            echo ""
            echo "Or use the CLI:"
            echo "  nym-vpnc status"
            echo "  nym-vpnc connect"
            ;;
        systemd)
            echo "To start:"
            echo "  systemctl start nym-vpnd"
            echo ""
            echo "Or use the CLI:"
            echo "  nym-vpnc status"
            echo "  nym-vpnc connect"
            ;;
        *)
            echo "Start the daemon manually:"
            echo "  nym-vpnd --config-dir /var/lib/nym-vpn &"
            echo ""
            echo "Then use the CLI:"
            echo "  nym-vpnc status"
            echo "  nym-vpnc connect"
            ;;
    esac

    echo ""
    echo "Documentation: https://github.com/${REPO}"
    echo ""
}

main() {
    echo ""
    printf "${BLUE}Nym VPN Installer${NC}\n"
    printf "${BLUE}==================${NC}\n"
    echo ""

    check_root

    log_step "Detecting system..."
    local arch
    arch=$(detect_arch)
    log_info "Architecture: $arch"

    local init_system
    init_system=$(detect_init_system)
    log_info "Init system: $init_system"

    log_step "Getting latest version..."
    local version
    version=$(get_latest_version)
    log_info "Version: $version"

    check_wireguard

    install_binaries "$arch" "$version"

    case "$init_system" in
        procd)
            install_procd_init
            install_config "$init_system"
            enable_service "$init_system"
            ;;
        systemd)
            install_systemd_unit
            install_config "$init_system"
            enable_service "$init_system"
            ;;
        *)
            log_warn "Unknown init system, skipping service installation"
            ;;
    esac

    print_success "$init_system"
}

main "$@"
