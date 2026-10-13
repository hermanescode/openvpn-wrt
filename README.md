# OpenVPN-WRT Gateway

> **Ultra-lightweight, password-protected Web Panel & Gateway Router for OpenWrt.**  
> Purpose-built for low-resource embedded routers like the **Google Wifi AC1304 (Qualcomm IPQ4019, ARMv7-A Cortex-A7)** to route all router and Wi-Fi client traffic through OpenVPN tunnels with zero overhead.

---

## ✨ Features

- **🌐 Whole-Router / Wi-Fi Gateway Routing**:
  - Automatically configures OpenWrt firewall NAT (Masquerade) and LAN forwarding so all connected devices (phones, PCs, smart TVs) route through OpenVPN without manual iptables/nftables headaches.
  - Native support for both **OpenWrt 22+/24+ `nftables` (fw4)** and **legacy `iptables` (fw3)**.
  - **🛡️ Kill Switch**: Optional toggle to block non-local LAN egress if the VPN disconnects.
- **🔐 Password Protected Web Panel**:
  - Constant-time password comparison (`subtle.ConstantTimeCompare`).
  - Safe status polling pattern (no frozen UI / false-logout traps).
  - Change password directly from the Web UI.
- **📁 Multi-Profile Manager (.ovpn)**:
  - Drag-and-drop `.ovpn` upload or direct config text pasting.
  - 1-click active profile switching.
  - View config file contents and delete profiles directly in the dashboard.
  - Includes **8 optimized anti-censorship profiles** out-of-the-box (FakeQUIC, FakeNTP, DoT, Anti-DPI Fragmented, Cloudflare SSL, Fake HTTP).
- **🚀 Embedded Memory & CPU Optimized**:
  - Single standalone binary (static HTML/CSS/JS embedded via `go:embed`).
  - Tuned for 512MB RAM routers: soft heap cap `GOMEMLIMIT=32MiB`, proactive `GOGC=30`, and periodic `debug.FreeOSMemory()` reclamation.
  - Non-blocking ring buffer for logs (capped at 300 entries).
- **🔄 Robust Process Supervision**:
  - Full OpenWrt `procd` service integration (`/etc/init.d/openvpn-wrt`) with automatic crash respawn.

---

## ⚡ Quick Installation on OpenWrt

### Method 1: One-Line Installer (Recommended)

Run this command inside your OpenWrt router terminal (via SSH):

```sh
sh -c "$(curl -sSL https://raw.githubusercontent.com/hermanescode/openvpn-wrt/main/openwrt/install.sh)"
```

*Or with wget:*
```sh
sh -c "$(wget -qO- https://raw.githubusercontent.com/hermanescode/openvpn-wrt/main/openwrt/install.sh)"
```

The installer will:
1. Detect router architecture (`linux-armv7` for Google Wifi AC1304).
2. Install `openvpn-openssl`, `curl`, and `ca-bundle` if missing.
3. Place binary in `/usr/bin/openvpn-wrt`.
4. Configure `/etc/openvpn-wrt/config.json`.
5. Enable and start the service via OpenWrt `procd`.

---

### Method 2: Manual Transfer via SCP (Direct from PC / Server)

If your router does not have direct access to download from GitHub:

1. Copy the compiled ARMv7 binary from this workspace to your router:
   ```sh
   scp dist/openvpn-wrt-linux-armv7 root@192.168.1.1:/usr/bin/openvpn-wrt
   ```
2. SSH into your router:
   ```sh
   ssh root@192.168.1.1
   ```
3. Set permissions, directories, and dependencies:
   ```sh
   chmod +x /usr/bin/openvpn-wrt
   mkdir -p /etc/openvpn-wrt/configs
   opkg update && opkg install openvpn-openssl
   ```
4. Copy the service init script (`openwrt/etc/init.d/openvpn-wrt`) to `/etc/init.d/openvpn-wrt`:
   ```sh
   chmod +x /etc/init.d/openvpn-wrt
   /etc/init.d/openvpn-wrt enable
   /etc/init.d/openvpn-wrt start
   ```

---

## 🔄 Easy Update on Router

To update the service to the latest version on your OpenWrt router:

```sh
sh -c "$(curl -sSL https://raw.githubusercontent.com/hermanescode/openvpn-wrt/main/openwrt/update.sh)"
```

*Or manually:*
```sh
/etc/init.d/openvpn-wrt stop
# Copy / download new binary to /usr/bin/openvpn-wrt
chmod +x /usr/bin/openvpn-wrt
/etc/init.d/openvpn-wrt start
```

---

## 🖥️ Web Dashboard Usage

Once installed, open your browser and navigate to:
```
http://<router-ip>:8080
```
*(e.g., `http://192.168.1.1:8080`)*

- **Default Password**: `admin` (changeable in Settings ⚙️).
- **Connect / Disconnect**: Tap **⚡ Connect** or **🛑 Disconnect**.
- **Whole-Router Wi-Fi Mode**: Toggle the switch **Whole-Router Wi-Fi / LAN Gateway Mode** to instantly route all connected devices through the VPN.
- **Profiles**: Click **Use** next to any profile, or tap **+ Upload / Add** to upload new `.ovpn` files.
- **Diagnostics**: Use **🔄** next to Public IP to test external connectivity, or tap **📶 Ping Test** to check latency to `1.1.1.1` or `8.8.8.8`.

---

## 🛠️ Cross-Compilation Matrix

Build from source on any Linux machine with Go 1.24+:

| Target Architecture | Target Device | Command |
|---|---|---|
| **ARMv7 (32-bit)** | Google Wifi AC1304 (Qualcomm IPQ4019 Cortex-A7) | `make build-linux-armv7` |
| **ARM64 (64-bit)** | NanoPi R4S, Raspberry Pi 4 | `make build-linux-arm64` |
| **x86_64** | Mini PC / Proxmox VM OpenWrt | `make build-linux-amd64` |
| **MIPSLE** | MediaTek MT7621 routers | `make build-linux-mipsle` |

---

## 📁 Directory Structure & Configuration

- Configuration file: `/etc/openvpn-wrt/config.json`
- Profiles folder: `/etc/openvpn-wrt/configs/*.ovpn`
- Procd init script: `/etc/init.d/openvpn-wrt`
- Binary: `/usr/bin/openvpn-wrt`

Example `/etc/openvpn-wrt/config.json`:
```json
{
  "web_listen": ":8080",
  "web_password": "admin",
  "active_profile": "01_UDP_443_FakeQUIC.ovpn",
  "configs_dir": "/etc/openvpn-wrt/configs",
  "auto_connect": true,
  "gateway_mode": true,
  "kill_switch": false,
  "custom_dns": "1.1.1.1,8.8.8.8",
  "log_level": "info"
}
```
