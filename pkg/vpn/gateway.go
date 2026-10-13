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

		// Check if regex (contains symbols like ^, $, .*, |, etc.)
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

		// Perform proactive DNS resolution to populate initial IPs
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
// router & Wi-Fi LAN clients through OpenVPN, supporting Full Tunnel and Selective Routing.
func SetGatewayEnabled(enable bool, routingMode string, selectiveRoutes []string, blockedRoutes []string, killSwitch bool) (string, error) {
	if enable {
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

		sel := parseRouteEntries(selectiveRoutes)
		blk := parseRouteEntries(blockedRoutes)

		// 1. Setup dnsmasq rules for domain set population & domain blocking
		_ = setupDnsmasq(sel.Domains, blk.Domains)

		// 2. Build NFT elements
		nftBlockedIPs := formatNFTSetElements(blk.IPs)
		nftSelectiveIPs := formatNFTSetElements(sel.IPs)

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

		// Selective vs Full mode firewall rules
		routingLogicNft := ""
		routingLogicIpt := ""

		if routingMode == "selective" {
			routingLogicNft = fmt.Sprintf(`
    # Selective Mode: Only traffic matching @vpn_routed_ips routes via tun+
    nft 'add chain inet openvpn_wrt prerouting { type filter hook prerouting priority -150; policy accept; }'
    nft 'add rule inet openvpn_wrt prerouting iifname "br-lan" ip daddr @vpn_routed_ips mark set 0x55'
    nft 'add rule inet openvpn_wrt forward ip daddr @vpn_routed_ips oifname "tun+" accept'
    ip rule add fwmark 0x55 table 100 2>/dev/null || true
    ip route replace default dev $(ip -o link show | grep -o 'tun[0-9]*' | head -n1 || echo 'tun0') table 100 2>/dev/null || true
`)
			routingLogicIpt = `
    # Selective Mode with iptables
    iptables -t filter -A OPENVPN_WRT_FWD -m set --match-set vpn_routed_ips dst -o tun+ -j ACCEPT
`
		} else {
			// Full Tunnel mode
			routingLogicNft = `
    # Full Tunnel: All non-local traffic forward to tun+
    nft 'add rule inet openvpn_wrt forward oifname "tun+" accept'
    # Ensure default route exists in main table
    ip route replace 0.0.0.0/1 dev $(ip -o link show | grep -o 'tun[0-9]*' | head -n1 || echo 'tun0') 2>/dev/null || true
    ip route replace 128.0.0.0/1 dev $(ip -o link show | grep -o 'tun[0-9]*' | head -n1 || echo 'tun0') 2>/dev/null || true
`
			routingLogicIpt = `
    iptables -t filter -A OPENVPN_WRT_FWD -o tun+ -j ACCEPT
    ip route replace 0.0.0.0/1 dev $(ip -o link show | grep -o 'tun[0-9]*' | head -n1 || echo 'tun0') 2>/dev/null || true
    ip route replace 128.0.0.0/1 dev $(ip -o link show | grep -o 'tun[0-9]*' | head -n1 || echo 'tun0') 2>/dev/null || true
`
		}

		cmd := fmt.Sprintf(`
if command -v nft >/dev/null 2>&1; then
    nft add table inet openvpn_wrt 2>/dev/null || true
    nft flush table inet openvpn_wrt 2>/dev/null || true

    # Sets
    nft 'add set inet openvpn_wrt blocked_ips { type ipv4_addr; flags interval; }'
    nft 'add set inet openvpn_wrt vpn_routed_ips { type ipv4_addr; flags interval; }'
%s
%s

    # Forward chain
    nft 'add chain inet openvpn_wrt forward { type filter hook forward priority -5; policy accept; }'
    
    # 1. Blocked destinations drop rule
    nft 'add rule inet openvpn_wrt forward ip daddr @blocked_ips drop'

    # 2. Local LAN exemptions
    nft 'add rule inet openvpn_wrt forward ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return'
    nft 'add rule inet openvpn_wrt forward iifname "tun+" ct state { established, related } accept'

%s
%s

    # MSS Clamping (Crucial for OpenVPN tunnels: prevents TCP packet dropping due to MTU mismatch)
    nft 'add chain inet openvpn_wrt mangle_forward { type filter hook forward priority mangle; policy accept; }'
    nft 'add rule inet openvpn_wrt mangle_forward oifname "tun+" tcp flags syn tcp option maxseg size set rt mtu'
    nft 'add rule inet openvpn_wrt mangle_forward iifname "tun+" tcp flags syn tcp option maxseg size set rt mtu'

    # DNS Interception: Ensure all DNS queries (port 53) from LAN clients reach local dnsmasq
    nft 'add chain inet openvpn_wrt nat_prerouting { type nat hook prerouting priority -100; policy accept; }'
    nft 'add rule inet openvpn_wrt nat_prerouting iifname "br-lan" udp dport 53 redirect to :53'
    nft 'add rule inet openvpn_wrt nat_prerouting iifname "br-lan" tcp dport 53 redirect to :53'

    # Postrouting NAT
    nft 'add chain inet openvpn_wrt postrouting { type nat hook postrouting priority 100; policy accept; }'
    nft 'add rule inet openvpn_wrt postrouting oifname "tun+" masquerade'
    echo "nftables rules applied successfully"
elif command -v iptables >/dev/null 2>&1; then
    # NAT chain
    iptables -t nat -N OPENVPN_WRT_NAT 2>/dev/null || iptables -t nat -F OPENVPN_WRT_NAT
    iptables -t nat -A OPENVPN_WRT_NAT -o tun+ -j MASQUERADE
    iptables -t nat -D POSTROUTING -j OPENVPN_WRT_NAT 2>/dev/null || true
    iptables -t nat -I POSTROUTING 1 -j OPENVPN_WRT_NAT

    # DNS Redirection to local router
    iptables -t nat -D PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t nat -I PREROUTING 1 -i br-lan -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -D PREROUTING -i br-lan -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t nat -I PREROUTING 2 -i br-lan -p tcp --dport 53 -j REDIRECT --to-ports 53

    # MSS Clamping for iptables
    iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    # Forward chain
    iptables -t filter -N OPENVPN_WRT_FWD 2>/dev/null || iptables -t filter -F OPENVPN_WRT_FWD
    iptables -t filter -A OPENVPN_WRT_FWD -d 0.0.0.0/8 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 10.0.0.0/8 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 127.0.0.0/8 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 172.16.0.0/12 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -d 192.168.0.0/16 -j RETURN
    iptables -t filter -A OPENVPN_WRT_FWD -i tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

%s
%s

    iptables -t filter -D FORWARD -j OPENVPN_WRT_FWD 2>/dev/null || true
    iptables -t filter -I FORWARD 1 -j OPENVPN_WRT_FWD
    echo "iptables rules applied successfully"
else
    echo "Neither nft nor iptables found"
    exit 1
fi
`, nftBlockedIPs, nftSelectiveIPs, ksRuleNft, routingLogicNft, ksRuleIpt, routingLogicIpt)

		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}

	// Teardown
	_ = os.Remove("/tmp/dnsmasq.d/openvpn_wrt.conf")
	_ = exec.Command("sh", "-c", "killall -HUP dnsmasq 2>/dev/null || true").Run()
	_ = exec.Command("sh", "-c", "ip rule del fwmark 0x55 table 100 2>/dev/null || true").Run()

	cmd := `
# Clear DNS redirection & mangle
if command -v nft >/dev/null 2>&1; then
    nft delete table inet openvpn_wrt 2>/dev/null || true
    echo "nftables table deleted"
elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t nat -D PREROUTING -i br-lan -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || true
    iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

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

	// Ensure DNS queries are forwarded upstream reliably through tunnel
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

	// Reload dnsmasq gracefully
	_ = exec.Command("sh", "-c", "/etc/init.d/dnsmasq reload 2>/dev/null || killall -HUP dnsmasq 2>/dev/null || true").Run()
	return nil
}
