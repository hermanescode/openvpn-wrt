package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hermanescode/openvpn-wrt/pkg/config"
	"github.com/hermanescode/openvpn-wrt/pkg/vpn"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	cfg        *config.Config
	manager    *vpn.VPNManager
	srv        *http.Server
	sessions   map[string]time.Time
	sessionsMu sync.RWMutex
}

func NewServer(cfg *config.Config, manager *vpn.VPNManager) *Server {
	return &Server{
		cfg:      cfg,
		manager:  manager,
		sessions: make(map[string]time.Time),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Authentication endpoints
	mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/auth/check", s.handleAuthCheck)
	mux.HandleFunc("/api/auth/password", s.handleAuthChangePassword)

	// Status & Telemetry endpoints (Safe polling, not blocked by 401)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/clear", s.handleLogsClear)
	mux.HandleFunc("/api/myip", s.handleMyIP)
	mux.HandleFunc("/api/ping", s.handlePing)

	// VPN Control & Configuration endpoints (Requires Auth if password is set)
	mux.HandleFunc("/api/connect", s.authMiddleware(s.handleConnect))
	mux.HandleFunc("/api/disconnect", s.authMiddleware(s.handleDisconnect))
	mux.HandleFunc("/api/profiles", s.handleProfilesList)
	mux.HandleFunc("/api/profiles/select", s.authMiddleware(s.handleProfileSelect))
	mux.HandleFunc("/api/profiles/upload", s.authMiddleware(s.handleProfileUpload))
	mux.HandleFunc("/api/profiles/delete", s.authMiddleware(s.handleProfileDelete))
	mux.HandleFunc("/api/profiles/content", s.handleProfileContent)
	mux.HandleFunc("/api/gateway/toggle", s.authMiddleware(s.handleGatewayToggle))
	mux.HandleFunc("/api/config", s.authMiddleware(s.handleConfig))

	// Static Assets with aggressive No-Cache headers
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}

	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fileServer.ServeHTTP(w, r)
	})

	s.srv = &http.Server{
		Addr:         s.cfg.Get().WebListen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown() error {
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}

// Session Helpers
func (s *Server) generateSessionToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	s.sessionsMu.Lock()
	s.sessions[token] = time.Now().Add(24 * time.Hour)
	s.sessionsMu.Unlock()

	return token
}

func (s *Server) isValidSession(token string) bool {
	if token == "" {
		return false
	}
	s.sessionsMu.RLock()
	exp, exists := s.sessions[token]
	s.sessionsMu.RUnlock()

	if !exists {
		return false
	}
	if time.Now().After(exp) {
		s.sessionsMu.Lock()
		delete(s.sessions, token)
		s.sessionsMu.Unlock()
		return false
	}
	return true
}

func (s *Server) isAuthenticated(r *http.Request) bool {
	expectedPass := s.cfg.Get().WebPassword
	if expectedPass == "" {
		return true // No password set
	}

	// 1. Check Header
	if token := r.Header.Get("X-Session-Token"); s.isValidSession(token) {
		return true
	}

	// 2. Check Cookie
	if cookie, err := r.Cookie("openvpn_session"); err == nil {
		if s.isValidSession(cookie.Value) {
			return true
		}
	}

	return false
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthenticated(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   "Authentication required",
			})
			return
		}
		next(w, r)
	}
}

// Handlers
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	expectedPass := s.cfg.Get().WebPassword
	if expectedPass != "" {
		match := subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPass)) == 1
		if !match {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   "Invalid password",
			})
			return
		}
	}

	token := s.generateSessionToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "openvpn_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"token":   token,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("openvpn_session"); err == nil {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "openvpn_session",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	passSet := s.cfg.Get().WebPassword != ""
	isAuth := s.isAuthenticated(r)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"password_required": passSet,
		"is_authenticated":  isAuth,
	})
}

func (s *Server) handleAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := s.cfg.Update(func(c *config.Config) {
		c.WebPassword = strings.TrimSpace(req.NewPassword)
	})

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dto := s.manager.GetStatus()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	payload := map[string]any{
		"status": dto,
		"system": map[string]any{
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
			"goroutines": runtime.NumGoroutine(),
			"alloc_mb":   float64(m.Alloc) / 1024 / 1024,
			"sys_mb":     float64(m.Sys) / 1024 / 1024,
		},
		"auth": map[string]any{
			"password_required": s.cfg.Get().WebPassword != "",
			"is_authenticated":  s.isAuthenticated(r),
		},
	}

	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Profile string `json:"profile"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	err := s.manager.Connect(req.Profile)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.manager.Disconnect()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleProfilesList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	profiles, err := s.manager.ListProfiles()
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "profiles": profiles})
}

func (s *Server) handleProfileSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Profile == "" {
		http.Error(w, "Invalid profile name", http.StatusBadRequest)
		return
	}

	err := s.cfg.Update(func(c *config.Config) {
		c.ActiveProfile = req.Profile
	})

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "active_profile": req.Profile})
}

func (s *Server) handleProfileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Support both multipart file upload and JSON body
	contentType := r.Header.Get("Content-Type")
	var filename string
	var content []byte

	if strings.Contains(contentType, "multipart/form-data") {
		err := r.ParseMultipartForm(10 << 20) // 10MB max
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file field required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		filename = header.Filename
		content, _ = io.ReadAll(file)
	} else {
		var req struct {
			Filename string `json:"filename"`
			Content  string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		filename = req.Filename
		content = []byte(req.Content)
	}

	if filename == "" || len(content) == 0 {
		http.Error(w, "Filename and content required", http.StatusBadRequest)
		return
	}

	err := s.manager.SaveProfile(filename, content)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "filename": filename})
}

func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	err := s.manager.DeleteProfile(req.Filename)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleProfileContent(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "filename query param required", http.StatusBadRequest)
		return
	}

	content, err := s.manager.ReadProfileContent(filename)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "content": content})
}

func (s *Server) handleGatewayToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enable     *bool `json:"enable"`
		KillSwitch *bool `json:"kill_switch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := s.cfg.Get()
	newEnable := cfg.GatewayMode
	if req.Enable != nil {
		newEnable = *req.Enable
	}
	newKillSwitch := cfg.KillSwitch
	if req.KillSwitch != nil {
		newKillSwitch = *req.KillSwitch
	}

	out, err := vpn.SetGatewayEnabled(newEnable, newKillSwitch)
	if err == nil {
		_ = s.cfg.Update(func(c *config.Config) {
			c.GatewayMode = newEnable
			c.KillSwitch = newKillSwitch
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": out})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"enabled":     newEnable,
		"kill_switch": newKillSwitch,
		"output":      out,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AutoConnect *bool   `json:"auto_connect"`
		CustomDNS   *string `json:"custom_dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := s.cfg.Update(func(c *config.Config) {
		if req.AutoConnect != nil {
			c.AutoConnect = *req.AutoConnect
		}
		if req.CustomDNS != nil {
			c.CustomDNS = strings.TrimSpace(*req.CustomDNS)
		}
	})

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := s.manager.GetLogs()
	_ = json.NewEncoder(w).Encode(map[string]any{"logs": logs})
}

func (s *Server) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.ClearLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleMyIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip, err := s.manager.CheckPublicIP()
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "ip": ip})
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "1.1.1.1"
	}

	out, err := exec.Command("ping", "-c", "2", "-W", "2", target).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   string(out),
			"target":  target,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"output":  string(out),
		"target":  target,
	})
}
