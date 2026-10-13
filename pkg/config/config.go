package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Config struct {
	WebListen           string   `json:"web_listen"`
	WebPassword         string   `json:"web_password"`
	ActiveProfile       string   `json:"active_profile"`
	ConfigsDir          string   `json:"configs_dir"`
	AutoConnect         bool     `json:"auto_connect"`
	GatewayMode         bool     `json:"gateway_mode"`
	RoutingMode         string   `json:"routing_mode"` // "full" or "selective"
	SelectiveRoutes     []string `json:"selective_routes"`
	BlockedDestinations []string `json:"blocked_destinations"`
	KillSwitch          bool     `json:"kill_switch"`
	CustomDNS           string   `json:"custom_dns"`
	LogLevel            string   `json:"log_level"`

	path string
	mu   sync.RWMutex
}

func DefaultConfig() *Config {
	return &Config{
		WebListen:     ":8085",
		WebPassword:   "admin",
		ActiveProfile: "01_UDP_443_FakeQUIC.ovpn",
		ConfigsDir:    "/etc/openvpn-wrt/configs",
		AutoConnect:   true,
		GatewayMode:   true,
		RoutingMode:   "full", // "full" = all traffic, "selective" = only designated destinations
		SelectiveRoutes: []string{
			"youtube.com",
			"*.googlevideo.com",
			"twitter.com",
			"x.com",
			"t.me",
			"telegram.org",
			"instagram.com",
			"1.1.1.1",
			"8.8.8.8",
		},
		BlockedDestinations: []string{
			// Example blocked destinations
		},
		KillSwitch: false,
		CustomDNS:  "1.1.1.1,8.8.8.8",
		LogLevel:   "info",
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	cfg.path = path

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = cfg.Save()
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.WebListen == "" || cfg.WebListen == ":8080" {
		cfg.WebListen = ":8085"
	}
	if cfg.ConfigsDir == "" {
		cfg.ConfigsDir = "/etc/openvpn-wrt/configs"
	}
	if cfg.RoutingMode == "" {
		cfg.RoutingMode = "full"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	return cfg, nil
}

func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.path == "" {
		c.path = "/etc/openvpn-wrt/config.json"
	}

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.path, data, 0644)
}

func (c *Config) Update(fn func(*Config)) error {
	c.mu.Lock()
	fn(c)
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) Get() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return *c
}
