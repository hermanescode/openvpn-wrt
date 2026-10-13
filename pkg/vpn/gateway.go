package vpn

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// IsGatewayEnabled checks if whole-router transparent forwarding rules exist.
func IsGatewayEnabled() bool {
	checkCmd := `
if command -v uci >/dev/null 2>&1 && uci get firewall.@zone[1].device 2>/dev/null | grep -q "tun+"; then
    echo 1
elif command -v nft >/dev/null 2>&1 && nft list table inet fw4 2>/dev/null | grep -q "tun+"; then
    echo 1
elif command -v iptables >/dev/null 2>&1 && iptables -t nat -L POSTROUTING 2>/dev/null | grep -q "tun+"; then
    echo 1
else
    echo 0
fi
`
	out, err := exec.Command("sh", "-c", checkCmd).Output()
	return strings.TrimSpace(string(out)) == "1" && err == nil
}

type ParsedRoutes struct {
	IPs     []string
	Domains []string
	Regexes []string
}

func parseRouteEntries(entries []string) ParsedRoutes {
	var pr ParsedRoutes
	for _, raw := range entries {
		item := strings.TrimSpace(raw)
		if item == "" || strings.HasPrefix(item, "#") {
			continue
		}

		// Check if CIDR or IP
		if _, _, err := net.ParseCIDR(item); err == nil {
			pr.IPs = append(pr.IPs, item)
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			pr.IPs = append(pr.IPs, item)
			continue
		}

		// Check if regex
		if strings.ContainsAny(item, `^$|[]()+?`) {
			if _, err := regexp.Compile(item); err == nil {
				pr.Regexes = append(pr.Regexes, item)
				continue
			}
		}

		// Clean domain
		cleanDomain := strings.TrimPrefix(item, "*.")
		cleanDomain = strings.TrimPrefix(cleanDomain, ".")
		pr.Domains = append(pr.Domains, cleanDomain)

		// Perform proactive DNS resolution
		if ips, err := net.LookupIP(cleanDomain); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					pr.IPs = append(pr.IPs, ip4.String())
				}
			}
		}
	}
	return pr
}

// SetGatewayEnabled configures or clears the OpenWrt firewall rules to route
// router & Wi-Fi LAN clients through OpenVPN using native OpenWrt UCI firewall zone integration.
func SetGatewayEnabled(enable bool, routingMode string, selectiveRoutes []string, blockedRoutes []string, killSwitch bool) (string, error) {
	if enable {
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

		sel := parseRouteEntries(selectiveRoutes)
		blk := parseRouteEntries(blockedRoutes)

		_ = setupDnsmasq(sel.Domains, blk.Domains)

		cmd := `
# 1. Enable IP forwarding in kernel
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# 2. Native OpenWrt UCI Firewall Zone integration:
# Add 'tun+' to OpenWrt's WAN zone so OpenWrt natively handles LAN->WAN forwarding, MASQUERADE, and MSS clamping
if command -v uci >/dev/null 2>&1; then
    # Find the wan zone index or name
    WAN_ZONE=""
    for i in 0 1 2 3; do
        if [ "$(uci -q get firewall.@zone[$i].name)" = "wan" ]; then
            WAN_ZONE="firewall.@zone[$i]"
            break
        fi
    done
    if [ -n "$WAN_ZONE" ]; then
        uci -q del_list "$WAN_ZONE.device=tun+" 2>/dev/null || true
        uci -q add_list "$WAN_ZONE.device=tun+"
        uci commit firewall 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
    fi
fi

# 3. Direct fw4 (nftables) rules insertion as guaranteed fallback
if command -v nft >/dev/null 2>&1; then
    # Check if fw4 table exists
    if nft list table inet fw4 >/dev/null 2>&1; then
        nft add rule inet fw4 forward oifname "tun+" accept 2>/dev/null || true
        nft add rule inet fw4 forward iifname "tun+" accept 2>/dev/null || true
        nft add rule inet fw4 srcnat oifname "tun+" masquerade 2>/dev/null || true
    fi

    # Standalone table fallback
    nft add table inet openvpn_wrt 2>/dev/null || true
    nft flush table inet openvpn_wrt 2>/dev/null || true
    nft 'add chain inet openvpn_wrt forward { type filter hook forward priority -5; policy accept; }'
    nft 'add rule inet openvpn_wrt forward oifname "tun+" accept'
    nft 'add rule inet openvpn_wrt forward iifname "tun+" ct state { established, related } accept'
    nft 'add rule inet openvpn_wrt forward iifname "br-lan" oifname "tun+" accept'
    nft 'add chain inet openvpn_wrt postrouting { type nat hook postrouting priority 100; policy accept; }'
    nft 'add rule inet openvpn_wrt postrouting oifname "tun+" masquerade'
    nft 'add chain inet openvpn_wrt mangle_forward { type filter hook forward priority mangle; policy accept; }'
    nft 'add rule inet openvpn_wrt mangle_forward oifname "tun+" tcp flags syn tcp option maxseg size set rt mtu'
    nft 'add rule inet openvpn_wrt mangle_forward iifname "tun+" tcp flags syn tcp option maxseg size set rt mtu'
fi

# 4. Direct fw3 (iptables) rules insertion
if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -N OPENVPN_WRT_NAT 2>/dev/null || iptables -t nat -F OPENVPN_WRT_NAT
    iptables -t nat -A OPENVPN_WRT_NAT -o tun+ -j MASQUERADE
    iptables -t nat -D POSTROUTING -j OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -I POSTROUTING 1 -j OPENVPN_WRT_NAT

    iptables -I forwarding_rule 1 -o tun+ -j ACCEPT 2>/dev/null || true
    iptables -I forwarding_rule 1 -i tun+ -j ACCEPT 2>/dev/null || true
    iptables -t nat -I postrouting_rule 1 -o tun+ -j MASQUERADE 2>/dev/null || true

    iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
fi

echo "Firewall rules successfully applied"
`
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}

	// Teardown
	teardownCmd := `
# Remove tun+ from OpenWrt UCI WAN zone
if command -v uci >/dev/null 2>&1; then
    for i in 0 1 2 3; do
        if [ "$(uci -q get firewall.@zone[$i].name)" = "wan" ]; then
            uci -q del_list "firewall.@zone[$i].device=tun+" 2>/dev/null || true
            uci commit firewall 2>/dev/null || true
            /etc/init.d/firewall reload 2>/dev/null || true
            break
        fi
    done
fi

# Clean nftables
if command -v nft >/dev/null 2>&1; then
    nft delete table inet openvpn_wrt 2>/dev/null || true
fi

# Clean iptables
if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D POSTROUTING -j OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -F OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -X OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -D forwarding_rule -o tun+ -j ACCEPT 2>/dev/null || true
    iptables -D forwarding_rule -i tun+ -j ACCEPT 2>/dev/null || true
    iptables -t nat -D postrouting_rule -o tun+ -j MASQUERADE 2>/dev/null || true
fi

# Clean dnsmasq
rm -f /tmp/dnsmasq.d/openvpn_wrt.conf
/etc/init.d/dnsmasq reload 2>/dev/null || killall -HUP dnsmasq 2>/dev/null || true
`
	out, err := exec.Command("sh", "-c", teardownCmd).CombinedOutput()
	return string(out), err
}

func formatNFTSetElements(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	var valid []string
	seen := make(map[string]bool)
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			valid = append(valid, ip)
		}
	}
	if len(valid) == 0 {
		return ""
	}
	return fmt.Sprintf("    nft 'add element inet openvpn_wrt vpn_routed_ips { %s }' 2>/dev/null || true", strings.Join(valid, ", "))
}

func setupDnsmasq(selectiveDomains []string, blockedDomains []string) error {
	dir := "/tmp/dnsmasq.d"
	_ = os.MkdirAll(dir, 0755)

	var sb strings.Builder
	sb.WriteString("# Generated by openvpn-wrt\n")

	// Upstream DNS servers through VPN tunnel
	sb.WriteString("server=1.1.1.1\n")
	sb.WriteString("server=8.8.8.8\n")

	// Blocked domains return 0.0.0.0
	for _, d := range blockedDomains {
		d = strings.TrimSpace(d)
		if d != "" {
			sb.WriteString(fmt.Sprintf("address=/%s/0.0.0.0\n", d))
		}
	}

	// Selective domains populate nftset / ipset
	for _, d := range selectiveDomains {
		d = strings.TrimSpace(d)
		if d != "" {
			sb.WriteString(fmt.Sprintf("nftset=/%s/4#inet#openvpn_wrt#vpn_routed_ips\n", d))
			sb.WriteString(fmt.Sprintf("ipset=/%s/vpn_routed_ips\n", d))
		}
	}

	confPath := "/tmp/dnsmasq.d/openvpn_wrt.conf"
	if err := os.WriteFile(confPath, []byte(sb.String()), 0644); err != nil {
		return err
	}

	// Also tell UCI dnsmasq to forward to 1.1.1.1 and 8.8.8.8
	_ = exec.Command("sh", "-c", `
if command -v uci >/dev/null 2>&1; then
    uci -q del_list dhcp.@dnsmasq[0].server="1.1.1.1" 2>/dev/null || true
    uci -q del_list dhcp.@dnsmasq[0].server="8.8.8.8" 2>/dev/null || true
    uci -q add_list dhcp.@dnsmasq[0].server="1.1.1.1" 2>/dev/null || true
    uci -q add_list dhcp.@dnsmasq[0].server="8.8.8.8" 2>/dev/null || true
    uci commit dhcp 2>/dev/null || true
fi
/etc/init.d/dnsmasq restart 2>/dev/null || killall -HUP dnsmasq 2>/dev/null || true
`).Run()

	return nil
}
