#!/usr/bin/env bash
set -e

# Gateway Installer Script
# Usage:
#   ./install.sh --client   (Install Gateway CLI client only - no server/systemd setup)
#   ./install.sh --server   (Install Gateway server daemon + systemd service + /etc/gateway config)

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

MODE="server"

for arg in "$@"; do
    case "$arg" in
        --client|-c)
            MODE="client"
            ;;
        --server|-s)
            MODE="server"
            ;;
        --help|-h)
            echo "Gateway Installer"
            echo "Usage:"
            echo "  ./install.sh --client    Install CLI client only (no systemd/server config)"
            echo "  ./install.sh --server    Install full daemon + systemd service (default)"
            exit 0
            ;;
    esac
done

echo -e "${BOLD}${CYAN}=== Gateway Installer (${MODE} mode) ===${NC}\n"

# Determine binary installation path
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_BIN="/usr/local/bin/gateway"
else
    if [ "$MODE" = "server" ]; then
        echo -e "${RED}[ERROR] Server daemon installation requires root privileges (run with sudo).${NC}"
        echo -e "${YELLOW}For client-only installation without root, run: ./install.sh --client${NC}"
        exit 1
    fi
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    INSTALL_BIN="$INSTALL_DIR/gateway"
fi

# Detect OS & Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    i386|i686) ARCH="386" ;;
    *)
        echo -e "${RED}[ERROR] Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${CYAN}[INFO] System detected: ${OS}/${ARCH}${NC}"

# Find or build binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -f "$PROJECT_ROOT/bin/gateway" ]; then
    echo -e "${CYAN}[INFO] Installing binary from bin/gateway...${NC}"
    cp "$PROJECT_ROOT/bin/gateway" "$INSTALL_BIN"
elif command -v go >/dev/null 2>&1 && [ -f "$PROJECT_ROOT/go.mod" ]; then
    echo -e "${CYAN}[INFO] Building Gateway binary with local Go compiler...${NC}"
    (cd "$PROJECT_ROOT" && go build -o "$INSTALL_BIN" ./cmd/gateway)
elif [ -f "$PROJECT_ROOT/dist/gateway-${OS}-${ARCH}" ]; then
    echo -e "${CYAN}[INFO] Installing release binary from dist/gateway-${OS}-${ARCH}...${NC}"
    cp "$PROJECT_ROOT/dist/gateway-${OS}-${ARCH}" "$INSTALL_BIN"
else
    echo -e "${RED}[ERROR] No pre-built binary found and 'go' compiler is not installed.${NC}"
    echo -e "${YELLOW}Please run 'make build' or 'go build -o bin/gateway ./cmd/gateway' first.${NC}"
    exit 1
fi

# Create Client Configuration Directory
USER_CONFIG_DIR="${HOME:-/root}/.config/gateway"
mkdir -p "$USER_CONFIG_DIR"
if [ ! -f "$USER_CONFIG_DIR/config.yaml" ]; then
    cat <<EOF > "$USER_CONFIG_DIR/config.yaml"
# Gateway Client Configuration
active_site: "default"
sites:
  default:
    url: "http://127.0.0.1:9090"
EOF
    echo -e "${GREEN}[SUCCESS] Created client config at $USER_CONFIG_DIR/config.yaml${NC}"
else
    echo -e "${CYAN}[INFO] Preserved existing client config at $USER_CONFIG_DIR/config.yaml${NC}"
fi

# If Client-only mode, stop here!
if [ "$MODE" = "client" ]; then
    echo -e "\n${BOLD}${GREEN}=== Client Installation Complete! ===${NC}"
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  1. Target a remote server: ${BOLD}gateway site use <site_name>${NC}"
    echo -e "  2. Check status:           ${BOLD}gateway status${NC}"
    echo -e "  3. Stream remote logs:     ${BOLD}gateway site logs${NC}"
    echo -e ""
    exit 0
fi

# Server Mode Setup (Root only)
echo -e "\n${CYAN}[INFO] Configuring server daemon services...${NC}"

CONFIG_DIR="/etc/gateway"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/server.yaml" ]; then
    if [ -f "$SCRIPT_DIR/server.yaml" ]; then
        cp "$SCRIPT_DIR/server.yaml" "$CONFIG_DIR/server.yaml"
    else
        cat <<EOF > "$CONFIG_DIR/server.yaml"
api:
  listen: "127.0.0.1:9090"
database: "/var/lib/gateway/gateway.db"
public: false
firewall:
  driver: "auto"
  protected_ports:
    - 22
    - 9090
log:
  level: "info"
EOF
    fi
    echo -e "${GREEN}[SUCCESS] Created default config at $CONFIG_DIR/server.yaml${NC}"
else
    echo -e "${CYAN}[INFO] Preserved existing config at $CONFIG_DIR/server.yaml${NC}"
fi

DATA_DIR="/var/lib/gateway"
mkdir -p "$DATA_DIR"
chmod 755 "$DATA_DIR"
echo -e "${GREEN}[SUCCESS] Ensured data directory at $DATA_DIR${NC}"

if command -v systemctl >/dev/null 2>&1; then
    SYSTEMD_UNIT="/etc/systemd/system/gateway.service"
    if [ -f "$SCRIPT_DIR/gateway.service" ]; then
        cp "$SCRIPT_DIR/gateway.service" "$SYSTEMD_UNIT"
    else
        cat <<EOF > "$SYSTEMD_UNIT"
[Unit]
Description=Gateway Reverse Proxy & Stream Routing Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_BIN daemon --config $CONFIG_DIR/server.yaml
Restart=always
RestartSec=5s
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    echo -e "${GREEN}[SUCCESS] Installed systemd unit to $SYSTEMD_UNIT${NC}"

    echo -e "\n${BOLD}${CYAN}Enabling and starting gateway.service...${NC}"
    systemctl enable gateway.service
    systemctl restart gateway.service
    echo -e "${GREEN}[SUCCESS] Gateway daemon active and running!${NC}"
else
    echo -e "${YELLOW}[WARN] systemd not detected on this system. Service unit was not installed.${NC}"
fi

echo -e "\n${BOLD}${GREEN}=== Server Installation Complete! ===${NC}"
echo -e "${CYAN}Next Steps:${NC}"
echo -e "  1. Verify daemon status:      ${BOLD}gateway status${NC} (or systemctl status gateway)"
echo -e "  2. Stream live system logs:   ${BOLD}gateway site logs${NC}"
echo -e "  3. Expose your first service: ${BOLD}gateway serve app.domain.com 3000${NC}"
echo -e ""
