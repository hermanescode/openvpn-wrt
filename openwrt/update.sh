#!/bin/sh
# OpenVPN-WRT Gateway - One-Line Updater for OpenWrt
set -e

REPO="hermanescode/openvpn-wrt"
INSTALL_DIR="/usr/bin"
INIT_DIR="/etc/init.d"

echo "=== Updating OpenVPN-WRT Gateway ==="

ARCH=$(uname -m)
case "$ARCH" in
    armv7*|armv7l) TARGET="linux-armv7" ;;
    aarch64*|arm64) TARGET="linux-arm64" ;;
    x86_64) TARGET="linux-amd64" ;;
    mips) TARGET="linux-mips" ;;
    mipsel|mipsle) TARGET="linux-mipsle" ;;
    *) TARGET="linux-armv7" ;;
esac

LATEST_URL="https://github.com/$REPO/releases/latest/download/openvpn-wrt-$TARGET"
TMP_BIN="/tmp/openvpn_wrt_update"

echo "Downloading update for $TARGET..."
rm -f "$TMP_BIN"

if command -v curl >/dev/null 2>&1; then
    curl -sSL "$LATEST_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_BIN" "$LATEST_URL"
elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O "$TMP_BIN" "$LATEST_URL"
fi

if [ ! -s "$TMP_BIN" ]; then
    echo "Update download failed or release not found."
    exit 1
fi

# Stop service to avoid ETXTBSY
"$INIT_DIR/openvpn-wrt" stop 2>/dev/null || killall openvpn-wrt 2>/dev/null || true

# Atomic inode rename replaces running binary without locking issues
chmod +x "$TMP_BIN"
mv "$TMP_BIN" "$INSTALL_DIR/openvpn-wrt"

# Restart service
"$INIT_DIR/openvpn-wrt" start

echo "✅ Update completed! OpenVPN-WRT Gateway restarted."
