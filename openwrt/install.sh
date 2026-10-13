#!/bin/sh
# OpenVPN-WRT Gateway - One-Line Installer for OpenWrt
set -e

REPO="hermanescode/openvpn-wrt"
INSTALL_DIR="/usr/bin"
CONF_DIR="/etc/openvpn-wrt"
CONFIGS_DIR="/etc/openvpn-wrt/configs"
INIT_DIR="/etc/init.d"

echo "=== Installing OpenVPN-WRT Gateway on OpenWrt ==="

# 1. Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
    armv7*|armv7l)
        TARGET="linux-armv7"
        ;;
    aarch64*|arm64)
        TARGET="linux-arm64"
        ;;
    x86_64)
        TARGET="linux-amd64"
        ;;
    mips)
        TARGET="linux-mips"
        ;;
    mipsel|mipsle)
        TARGET="linux-mipsle"
        ;;
    *)
        echo "Detected architecture: $ARCH -> defaulting to linux-armv7 (Google Wifi AC1304)"
        TARGET="linux-armv7"
        ;;
esac

echo "Target architecture: $ARCH -> using binary: $TARGET"

# 2. Check & Install openvpn-openssl if missing
if ! command -v openvpn >/dev/null 2>&1; then
    echo "Installing required openvpn package..."
    opkg update || true
    opkg install openvpn-openssl curl ca-bundle || true
fi

# 3. Download Binary
mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$CONFIGS_DIR"

# Stop existing running instance so binary is not locked (avoids ETXTBSY error)
killall openvpn-wrt 2>/dev/null || true
rm -f "$INSTALL_DIR/openvpn-wrt"

LATEST_URL="https://github.com/$REPO/releases/latest/download/openvpn-wrt-$TARGET"
echo "Downloading binary from $LATEST_URL..."

TMP_BIN="/tmp/openvpn_wrt_download"
rm -f "$TMP_BIN"

if command -v curl >/dev/null 2>&1; then
    curl -sSL "$LATEST_URL" -o "$TMP_BIN" || true
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_BIN" "$LATEST_URL" || true
elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O "$TMP_BIN" "$LATEST_URL" || true
fi

if [ ! -s "$TMP_BIN" ]; then
    echo "Direct download failed or release not yet published."
    exit 1
fi

mv "$TMP_BIN" "$INSTALL_DIR/openvpn-wrt"
chmod +x "$INSTALL_DIR/openvpn-wrt"

# 4. Setup Default Config if missing
if [ ! -f "$CONF_DIR/config.json" ]; then
    cat << 'EOF' > "$CONF_DIR/config.json"
{
  "web_listen": ":8085",
  "web_password": "admin",
  "active_profile": "",
  "configs_dir": "/etc/openvpn-wrt/configs",
  "auto_connect": true,
  "gateway_mode": true,
  "routing_mode": "full",
  "selective_routes": ["youtube.com", "*.googlevideo.com", "twitter.com", "x.com", "t.me", "telegram.org", "instagram.com", "1.1.1.1", "8.8.8.8"],
  "blocked_destinations": [],
  "kill_switch": false,
  "custom_dns": "1.1.1.1,8.8.8.8",
  "log_level": "info"
}
EOF
fi

# 5. Setup Procd Service
cat << 'EOF' > "$INIT_DIR/openvpn-wrt"
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

PROG=/usr/bin/openvpn-wrt
CONF=/etc/openvpn-wrt/config.json

start_service() {
    [ -x "$PROG" ] || return 1
    mkdir -p /etc/openvpn-wrt/configs

    procd_open_instance
    procd_set_param command "$PROG" -config "$CONF"
    procd_set_param env GOMEMLIMIT="32MiB" GOGC="30"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    killall openvpn-wrt 2>/dev/null
    killall openvpn 2>/dev/null
}

reload_service() {
    stop
    start
}
EOF

chmod +x "$INIT_DIR/openvpn-wrt"

# 6. Enable and start service
"$INIT_DIR/openvpn-wrt" enable
"$INIT_DIR/openvpn-wrt" restart

ROUTER_IP=$(ip -4 addr show br-lan 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
if [ -z "$ROUTER_IP" ]; then
    ROUTER_IP=$(uci get network.lan.ipaddr 2>/dev/null || echo "192.168.1.1")
fi

PORT=$(cat /tmp/openvpn-wrt.port 2>/dev/null || echo ":8085")
echo "===================================================="
echo "✅ OpenVPN-WRT Gateway installed and running!"
echo "Web Dashboard: http://$ROUTER_IP$PORT"
echo "Default Password: admin"
echo "(If 8085 was busy, next available port was auto-selected)"
echo "===================================================="
