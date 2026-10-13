package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/hermanescode/openvpn-wrt/pkg/config"
	"github.com/hermanescode/openvpn-wrt/pkg/vpn"
	"github.com/hermanescode/openvpn-wrt/pkg/web"
)

func init() {
	// Embedded Router Memory Optimization:
	// Set 32MB soft heap cap and aggressive 30% GC to keep RAM footprint minimal on Google Wifi AC1304 (512MB RAM)
	debug.SetMemoryLimit(32 * 1024 * 1024)
	debug.SetGCPercent(30)
}

func main() {
	configPath := flag.String("config", "/etc/openvpn-wrt/config.json", "Path to configuration file")
	flag.Parse()

	// Active OS Memory Reclaim ticker: forces Go runtime to return unused memory pages back to OpenWrt kernel
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			debug.FreeOSMemory()
		}
	}()

	fmt.Println("=== Starting OpenVPN-WRT Gateway Daemon ===")
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}

	vpnMgr := vpn.NewVPNManager(cfg)
	webSrv := web.NewServer(cfg, vpnMgr)
	proxySrv := vpn.NewProxyServer(cfg)

	if cfg.Get().ProxyEnabled {
		if err := proxySrv.Start(); err != nil {
			fmt.Printf("Warning: Proxy server failed to start: %v\n", err)
		} else {
			fmt.Printf("Mixed Proxy (SOCKS5 + HTTP) listening on %s\n", cfg.Get().ProxyListen)
		}
	}

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived shutdown signal. Cleaning up...")
		_ = vpnMgr.Disconnect()
		proxySrv.Stop()
		if !cfg.Get().KillSwitch {
			_, _ = vpn.SetGatewayEnabled(false, "", nil, nil, false)
		}
		_ = webSrv.Shutdown()
		os.Exit(0)
	}()

	// Auto-connect if configured
	if cfg.Get().AutoConnect && cfg.Get().ActiveProfile != "" {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			vpnMgr.AddLog("Auto-connecting to active profile: " + cfg.Get().ActiveProfile)
			if err := vpnMgr.Connect(cfg.Get().ActiveProfile); err != nil {
				vpnMgr.AddLog("Auto-connect notice: " + err.Error())
			}
		}()
	}

	fmt.Printf("Web Dashboard listening on %s\n", cfg.Get().WebListen)
	if err := webSrv.Start(); err != nil {
		log.Fatalf("Web server terminated: %v", err)
	}
}
