package vpn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hermanescode/openvpn-wrt/pkg/config"
)

type TestResult struct {
	Profile   string `json:"profile"`
	Success   bool   `json:"success"`
	LatencyMs int64  `json:"latency_ms"`
	PingMs    int64  `json:"ping_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type ConnectionState string

const (
	StateDisconnected ConnectionState = "disconnected"
	StateConnecting   ConnectionState = "connecting"
	StateConnected    ConnectionState = "connected"
	StateError        ConnectionState = "error"
)

type ProfileInfo struct {
	Name     string    `json:"name"`
	IsActive bool      `json:"is_active"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mod_time"`
	Remote   string    `json:"remote,omitempty"`
	Proto    string    `json:"proto,omitempty"`
}

type StatusDTO struct {
	State         ConnectionState `json:"state"`
	ActiveProfile string          `json:"active_profile"`
	TunnelIP      string          `json:"tunnel_ip"`
	RemoteServer  string          `json:"remote_server"`
	Protocol      string          `json:"protocol"`
	BytesIn       uint64          `json:"bytes_in"`
	BytesOut      uint64          `json:"bytes_out"`
	ConnectedAt   string          `json:"connected_at"`
	UptimeSeconds int64           `json:"uptime_seconds"`
	GatewayMode   bool            `json:"gateway_mode"`
	RoutingMode   string          `json:"routing_mode"`
	KillSwitch    bool            `json:"kill_switch"`
	LastError     string          `json:"last_error,omitempty"`
}

type VPNManager struct {
	cfg        *config.Config
	state      ConnectionState
	cmd        *exec.Cmd
	startedAt  time.Time
	tunnelIP   string
	remoteHost string
	remotePort string
	proto      string
	lastErr    string

	// Decoupled log mutex to avoid deadlocks
	logsMu sync.RWMutex
	logs   []string

	mu sync.RWMutex
}

func NewVPNManager(cfg *config.Config) *VPNManager {
	return &VPNManager{
		cfg:   cfg,
		state: StateDisconnected,
		logs:  make([]string, 0, 300),
	}
}

func (m *VPNManager) AddLog(msg string) {
	m.logsMu.Lock()
	defer m.logsMu.Unlock()

	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", ts, strings.TrimSpace(msg))
	if len(m.logs) >= 300 {
		m.logs = m.logs[1:]
	}
	m.logs = append(m.logs, entry)
}

func (m *VPNManager) GetLogs() []string {
	m.logsMu.RLock()
	defer m.logsMu.RUnlock()

	res := make([]string, len(m.logs))
	copy(res, m.logs)
	return res
}

func (m *VPNManager) ClearLogs() {
	m.logsMu.Lock()
	defer m.logsMu.Unlock()
	m.logs = make([]string, 0, 300)
}

func (m *VPNManager) GetState() ConnectionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *VPNManager) Connect(profileName string) error {
	m.mu.Lock()
	if m.state == StateConnected || m.state == StateConnecting {
		m.mu.Unlock()
		return fmt.Errorf("openvpn is already running or connecting")
	}

	if profileName == "" {
		profileName = m.cfg.Get().ActiveProfile
	}
	if profileName == "" {
		m.mu.Unlock()
		return fmt.Errorf("no profile selected")
	}

	profilePath := filepath.Join(m.cfg.Get().ConfigsDir, profileName)
	if _, err := os.Stat(profilePath); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("profile file not found: %s", profileName)
	}

	// Update active profile in config
	_ = m.cfg.Update(func(c *config.Config) {
		c.ActiveProfile = profileName
	})

	m.state = StateConnecting
	m.lastErr = ""
	m.tunnelIP = ""
	m.remoteHost = ""
	m.remotePort = ""
	m.proto = ""

	// Extract remote host and proto from profile for quick display
	m.parseProfileMetadata(profilePath)
	m.mu.Unlock()

	m.AddLog("Starting OpenVPN with profile: " + profileName)

	go m.runProcess(profilePath)
	return nil
}

func (m *VPNManager) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		m.AddLog("Stopping OpenVPN process...")
		_ = m.cmd.Process.Signal(os.Interrupt)
		time.Sleep(200 * time.Millisecond)
		_ = m.cmd.Process.Kill()
		m.cmd = nil
	}

	m.state = StateDisconnected
	m.tunnelIP = ""
	m.startedAt = time.Time{}
	m.AddLog("OpenVPN disconnected.")
	return nil
}

func (m *VPNManager) runProcess(profilePath string) {
	statusFile := "/tmp/openvpn-wrt-status.log"
	pidFile := "/tmp/openvpn-wrt.pid"

	args := []string{
		"--config", profilePath,
		"--status", statusFile, "2",
		"--writepid", pidFile,
		"--mssfix", "1300",
		"--verb", "3",
		"--suppress-timestamps",
	}

	cfg := m.cfg.Get()
	if cfg.RoutingMode == "selective" {
		// In selective mode, do NOT pull default gateway redirect from server!
		// Let OpenVPN only bring up tun0 and its subnet, while our firewall routes designated targets.
		args = append(args, "--pull-filter", "ignore", "redirect-gateway")
	}

	cmd := exec.Command("openvpn", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.handleProcessFailure("Failed to get stdout pipe: " + err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout

	m.mu.Lock()
	m.cmd = cmd
	m.mu.Unlock()

	if err := cmd.Start(); err != nil {
		m.handleProcessFailure("Failed to start openvpn binary: " + err.Error() + ". Is openvpn installed (opkg install openvpn-openssl)?")
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		m.AddLog(line)
		m.analyzeLogLine(line)
	}

	_ = cmd.Wait()

	m.mu.Lock()
	m.state = StateDisconnected
	m.AddLog("OpenVPN process exited.")
	m.cmd = nil
	m.mu.Unlock()

	// Clear gateway forwarding rules when OpenVPN process exits so LAN doesn't blackhole
	exitCfg := m.cfg.Get()
	if !exitCfg.KillSwitch {
		_, _ = SetGatewayEnabled(false, "", nil, nil, false)
	}
}

func (m *VPNManager) analyzeLogLine(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.Contains(line, "Initialization Sequence Completed") {
		m.state = StateConnected
		m.startedAt = time.Now()
		m.AddLog("Tunnel UP! Connection successfully established.")

		// Apply gateway routing if enabled in config
		cfg := m.cfg.Get()
		if cfg.GatewayMode {
			go func() {
				// Wait 1 second for tun interface to fully initialize routing
				time.Sleep(1 * time.Second)
				_, err := SetGatewayEnabled(true, cfg.RoutingMode, cfg.SelectiveRoutes, cfg.BlockedDestinations, cfg.KillSwitch)
				if err != nil {
					m.AddLog("Warning: Failed to apply gateway routing rules: " + err.Error())
				} else {
					m.AddLog(fmt.Sprintf("Gateway firewall rules applied (%s mode): Wi-Fi and LAN traffic active", cfg.RoutingMode))
				}
			}()
		}
	} else if strings.Contains(line, "AUTH_FAILED") {
		m.state = StateError
		m.lastErr = "Authentication failed (invalid credentials/certs)"
	} else if strings.Contains(line, "TLS Error: TLS handshake failed") {
		m.state = StateError
		m.lastErr = "TLS Handshake failed (server unreachable, port blocked or DPI dropped packets)"
	} else if strings.Contains(line, "Restart pause") || strings.Contains(line, "SIGUSR1") {
		m.state = StateConnecting
	}
}

func (m *VPNManager) handleProcessFailure(errMsg string) {
	m.mu.Lock()
	m.state = StateError
	m.lastErr = errMsg
	m.mu.Unlock()
	m.AddLog("ERROR: " + errMsg)
}

func (m *VPNManager) parseProfileMetadata(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "remote ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				m.remoteHost = parts[1]
			}
			if len(parts) >= 3 {
				m.remotePort = parts[2]
			}
		} else if strings.HasPrefix(line, "proto ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				m.proto = strings.ToUpper(parts[1])
			}
		}
	}
}

func (m *VPNManager) GetStatus() StatusDTO {
	m.mu.RLock()
	cfg := m.cfg.Get()
	state := m.state
	activeProf := cfg.ActiveProfile
	remoteHost := m.remoteHost
	remotePort := m.remotePort
	proto := m.proto
	startedAt := m.startedAt
	lastErr := m.lastErr
	m.mu.RUnlock()

	var uptime int64
	var connAtStr string
	if state == StateConnected && !startedAt.IsZero() {
		uptime = int64(time.Since(startedAt).Seconds())
		connAtStr = startedAt.Format("15:04:05")
	}

	remoteServer := ""
	if remoteHost != "" {
		if remotePort != "" {
			remoteServer = fmt.Sprintf("%s:%s", remoteHost, remotePort)
		} else {
			remoteServer = remoteHost
		}
	}

	tunIP := m.detectTunnelIP()
	bytesIn, bytesOut := m.readTrafficBytes()

	return StatusDTO{
		State:         state,
		ActiveProfile: activeProf,
		TunnelIP:      tunIP,
		RemoteServer:  remoteServer,
		Protocol:      proto,
		BytesIn:       bytesIn,
		BytesOut:      bytesOut,
		ConnectedAt:   connAtStr,
		UptimeSeconds: uptime,
		GatewayMode:   cfg.GatewayMode,
		RoutingMode:   cfg.RoutingMode,
		KillSwitch:    cfg.KillSwitch,
		LastError:     lastErr,
	}
}

func (m *VPNManager) detectTunnelIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "tun") {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						return ipNet.IP.String()
					}
				}
			}
		}
	}
	// Fallback to reading 'ip -4 addr show dev tun0'
	out, err := exec.Command("sh", "-c", "ip -4 addr show | grep -A2 'tun[0-9]*' | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return strings.TrimSpace(string(out))
	}

	return ""
}

func (m *VPNManager) readTrafficBytes() (uint64, uint64) {
	// 1. Try reading /tmp/openvpn-wrt-status.log
	statusPath := "/tmp/openvpn-wrt-status.log"
	if data, err := os.ReadFile(statusPath); err == nil {
		lines := strings.Split(string(data), "\n")
		var rx, tx uint64
		for _, l := range lines {
			if strings.HasPrefix(l, "TUN/TAP read bytes,") {
				parts := strings.Split(l, ",")
				if len(parts) >= 2 {
					tx, _ = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
				}
			} else if strings.HasPrefix(l, "TUN/TAP write bytes,") {
				parts := strings.Split(l, ",")
				if len(parts) >= 2 {
					rx, _ = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
				}
			}
		}
		if rx > 0 || tx > 0 {
			return rx, tx
		}
	}

	// 2. Fallback to /proc/net/dev for tun interfaces
	if devData, err := os.ReadFile("/proc/net/dev"); err == nil {
		lines := strings.Split(string(devData), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "tun") {
				fields := strings.Fields(l)
				if len(fields) >= 10 {
					rx, _ := strconv.ParseUint(fields[1], 10, 64)
					tx, _ := strconv.ParseUint(fields[9], 10, 64)
					return rx, tx
				}
			}
		}
	}

	return 0, 0
}

func (m *VPNManager) ListProfiles() ([]ProfileInfo, error) {
	cfg := m.cfg.Get()
	dir := cfg.ConfigsDir

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var profiles []ProfileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".ovpn") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}

		pInfo := ProfileInfo{
			Name:     e.Name(),
			IsActive: e.Name() == cfg.ActiveProfile,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
		}

		// Quick parse remote & proto from file
		pPath := filepath.Join(dir, e.Name())
		if f, err := os.Open(pPath); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "remote ") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						pInfo.Remote = parts[1]
						if len(parts) >= 3 {
							pInfo.Remote += ":" + parts[2]
						}
					}
				} else if strings.HasPrefix(line, "proto ") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						pInfo.Proto = strings.ToUpper(parts[1])
					}
				}
				if pInfo.Remote != "" && pInfo.Proto != "" {
					break
				}
			}
			f.Close()
		}

		profiles = append(profiles, pInfo)
	}

	return profiles, nil
}

func (m *VPNManager) SaveProfile(filename string, content []byte) error {
	if !strings.HasSuffix(strings.ToLower(filename), ".ovpn") {
		filename += ".ovpn"
	}
	dir := m.cfg.Get().ConfigsDir
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	dest := filepath.Join(dir, filename)
	return os.WriteFile(dest, content, 0644)
}

func (m *VPNManager) DeleteProfile(filename string) error {
	dir := m.cfg.Get().ConfigsDir
	dest := filepath.Join(dir, filename)
	return os.Remove(dest)
}

func (m *VPNManager) ReadProfileContent(filename string) (string, error) {
	dir := m.cfg.Get().ConfigsDir
	dest := filepath.Join(dir, filename)
	data, err := os.ReadFile(dest)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *VPNManager) CheckPublicIP() (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		// Fallback to ifconfig.me
		resp, err = client.Get("https://ifconfig.me/ip")
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func measureHostPing(host string) int64 {
	if host == "" {
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", host).Output()
	if err != nil {
		return -1
	}
	re := regexp.MustCompile(`time=([0-9.]+)\s*ms`)
	match := re.FindStringSubmatch(string(out))
	if len(match) >= 2 {
		if val, err := strconv.ParseFloat(match[1], 64); err == nil {
			return int64(val)
		}
	}
	return -1
}

func extractProfileRemote(path string) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	var host, proto string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "remote ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				host = parts[1]
			}
		} else if strings.HasPrefix(line, "proto ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				proto = strings.ToUpper(parts[1])
			}
		}
		if host != "" && proto != "" {
			break
		}
	}
	return host, proto
}

func (m *VPNManager) TestProfile(profileName string) TestResult {
	profilePath := filepath.Join(m.cfg.Get().ConfigsDir, profileName)
	if _, err := os.Stat(profilePath); err != nil {
		return TestResult{Profile: profileName, Success: false, Error: "Profile file not found"}
	}

	remoteHost, _ := extractProfileRemote(profilePath)
	pingVal := measureHostPing(remoteHost)

	// Isolated test with OpenVPN:
	// --route-noexec --ifconfig-noexec --connect-retry-max 1 --connect-timeout 4
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	tmpPid := fmt.Sprintf("/tmp/ovpn_test_%d.pid", time.Now().UnixNano())
	defer os.Remove(tmpPid)

	args := []string{
		"--config", profilePath,
		"--verb", "3",
		"--route-noexec",
		"--ifconfig-noexec",
		"--connect-retry-max", "1",
		"--connect-timeout", "4",
		"--writepid", tmpPid,
		"--nobind",
		"--dev-type", "tun",
		"--suppress-timestamps",
	}

	startTime := time.Now()
	cmd := exec.CommandContext(ctx, "openvpn", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return TestResult{Profile: profileName, Success: false, Error: err.Error()}
	}

	if err := cmd.Start(); err != nil {
		return TestResult{Profile: profileName, Success: false, Error: "Cannot start openvpn: " + err.Error()}
	}

	success := false
	var errMsg string
	done := make(chan struct{})

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Initialization Sequence Completed") {
				success = true
				break
			}
			if strings.Contains(line, "AUTH_FAILED") {
				errMsg = "Auth Failed"
				break
			}
			if strings.Contains(line, "Connection refused") {
				errMsg = "Connection Refused"
				break
			}
			if strings.Contains(line, "TLS Error") {
				errMsg = "TLS Handshake Failed"
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		if errMsg == "" {
			errMsg = "Connection Timeout"
		}
	}

	elapsedMs := time.Since(startTime).Milliseconds()

	// Guarantee that the test process is stopped immediately!
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()

	if success {
		finalLatency := pingVal
		if finalLatency <= 0 {
			finalLatency = elapsedMs
		}
		return TestResult{
			Profile:   profileName,
			Success:   true,
			LatencyMs: finalLatency,
			PingMs:    pingVal,
		}
	}

	if errMsg == "" {
		errMsg = "Test failed"
	}
	return TestResult{
		Profile: profileName,
		Success: false,
		PingMs:  pingVal,
		Error:   errMsg,
	}
}

func (m *VPNManager) TestAllProfiles() []TestResult {
	profiles, err := m.ListProfiles()
	if err != nil {
		return nil
	}
	results := make([]TestResult, 0, len(profiles))
	for _, p := range profiles {
		res := m.TestProfile(p.Name)
		results = append(results, res)
	}
	return results
}

