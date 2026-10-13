package vpn

import (
	"fmt"
	"os/exec"
	"strings"
)

// IsGatewayEnabled checks if whole-router transparent forwarding rules exist.
func IsGatewayEnabled() bool {
	checkCmd := `
if command -v nft >/dev/null 2>&1; then
    nft list table inet openvpn_wrt 2>/dev/null | grep -q "openvpn_wrt" && echo 1 || echo 0
elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -L POSTROUTING 2>/dev/null | grep -q "OPENVPN_WRT" && echo 1 || echo 0
else
    echo 0
fi
`
	out, err := exec.Command("sh", "-c", checkCmd).Output()
	return strings.TrimSpace(string(out)) == "1" && err == nil
}

// SetGatewayEnabled configures or clears the OpenWrt firewall rules to route
// all router & Wi-Fi LAN clients through the OpenVPN tun interface with NAT/Masquerade.
func SetGatewayEnabled(enable bool, killSwitch bool) (string, error) {
	if enable {
		// Enable IP forwarding in kernel
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

		ksRuleNft := ""
		ksRuleIpt := ""
		if killSwitch {
			ksRuleNft = `
    nft 'add rule inet openvpn_wrt forward ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } oifname != "tun+" drop'
`
			ksRuleIpt = `
    iptables -A OPENVPN_WRT_FWD ! -o tun+ ! -d 10.0.0.0/8 ! -d 172.16.0.0/12 ! -d 192.168.0.0/16 -j DROP
`
		}

		cmd := fmt.Sprintf(`
if command -v nft >/dev/null 2>&1; then
    nft add table inet openvpn_wrt 2>/dev/null || true
    nft flush table inet openvpn_wrt 2>/dev/null || true
    nft 'add chain inet openvpn_wrt forward { type filter hook forward priority -5; policy accept; }'
    nft 'add rule inet openvpn_wrt forward ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return'
    nft 'add rule inet openvpn_wrt forward oifname "tun+" accept'
    nft 'add rule inet openvpn_wrt forward iifname "tun+" ct state { established, related } accept'
%s
    nft 'add chain inet openvpn_wrt postrouting { type nat hook postrouting priority 100; policy accept; }'
    nft 'add rule inet openvpn_wrt postrouting oifname "tun+" masquerade'
    echo "nftables rules applied successfully"
elif command -v iptables >/dev/null 2>&1; then
    # NAT chain
    iptables -t nat -N OPENVPN_WRT_NAT 2>/dev/null || iptables -t nat -F OPENVPN_WRT_NAT
    iptables -t nat -A OPENVPN_WRT_NAT -o tun+ -j MASQUERADE
    iptables -t nat -D POSTROUTING -j OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -I POSTROUTING 1 -j OPENVPN_WRT_NAT

    # Forward chain
    iptables -t filter -N OPENVPN_WRT_FWD 2>/dev/null || iptables -t filter -F OPENVPN_WRT_FWD
    iptables -t filter -A OPENVPN_WRT_FWD -d 0.0.0.0/8 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 10.0.0.0/8 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 127.0.0.0/8 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 172.16.0.0/12 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 192.168.0.0/16 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -o tun+ -j ACCEPT
    iptables -t filter -A OPENVPN_WRT_FWD -i tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
%s
    iptables -t filter -D FORWARD -j OPENVPN_WRT_FWD 2>/dev/null || true
    iptables -t filter -I FORWARD 1 -j OPENVPN_WRT_FWD
    echo "iptables rules applied successfully"
else
    echo "Neither nft nor iptables found"
    exit 1
fi
`, ksRuleNft, ksRuleIpt)

		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}

	cmd := `
if command -v nft >/dev/null 2>&1; then
    nft delete table inet openvpn_wrt 2>/dev/null || true
    echo "nftables table deleted"
elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D POSTROUTING -j OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -F OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -X OPENVPN_WRT_NAT 2>/dev/null || true

    iptables -t filter -D FORWARD -j OPENVPN_WRT_FWD 2>/dev/null || true
    iptables -t filter -F OPENVPN_WRT_FWD 2>/dev/null || true
    iptables -t filter -X OPENVPN_WRT_FWD 2>/dev/null || true
    echo "iptables rules flushed"
fi
`
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}
