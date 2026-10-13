package vpn

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hermanescode/openvpn-wrt/pkg/config"
)

type ProxyServer struct {
	cfg      *config.Config
	listener net.Listener
	mu       sync.Mutex
	running  bool
}

func NewProxyServer(cfg *config.Config) *ProxyServer {
	return &ProxyServer{
		cfg: cfg,
	}
}

func (p *ProxyServer) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	addr := p.cfg.Get().ProxyListen
	if addr == "" {
		addr = "0.0.0.0:1081"
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.listener = l
	p.running = true

	go p.acceptLoop()
	return nil
}

func (p *ProxyServer) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
	p.running = false
}

func (p *ProxyServer) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handleConn(conn)
	}
}

func (p *ProxyServer) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// Peek first byte to distinguish between SOCKS5 (0x05) and HTTP proxy (CONNECT / GET / POST)
	br := bufio.NewReader(clientConn)
	firstByte, err := br.Peek(1)
	if err != nil {
		return
	}

	if firstByte[0] == 0x05 {
		p.handleSOCKS5(clientConn, br)
	} else {
		p.handleHTTPProxy(clientConn, br)
	}
}

func (p *ProxyServer) dialOut(network, targetAddr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 7 * time.Second,
	}

	// Try binding to tun0 if up
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if strings.HasPrefix(iface.Name, "tun") {
				addrs, _ := iface.Addrs()
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
						d.LocalAddr = &net.TCPAddr{IP: ipNet.IP}
						break
					}
				}
				break
			}
		}
	}

	return d.Dial(network, targetAddr)
}

func (p *ProxyServer) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	// Version identifier / method selection
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// Reply: No Auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	atyp := reqHeader[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(br, ipv4); err != nil {
			return
		}
		host = net.IP(ipv4).String()
	case 0x03: // Domain
		lenByte, err := br.ReadByte()
		if err != nil {
			return
		}
		domain := make([]byte, lenByte)
		if _, err := io.ReadFull(br, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(br, ipv6); err != nil {
			return
		}
		host = net.IP(ipv6).String()
	default:
		return
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	target := net.JoinHostPort(host, strconv.Itoa(port))

	if cmd != 0x01 { // Only CONNECT is supported
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	destConn, err := p.dialOut("tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer destConn.Close()

	// SOCKS5 Success
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	p.relay(conn, br, destConn)
}

func (p *ProxyServer) handleHTTPProxy(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		// HTTPS Tunnel
		destConn, err := p.dialOut("tcp", req.Host)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer destConn.Close()

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		p.relay(conn, br, destConn)
		return
	}

	// Plain HTTP Request
	destHost := req.Host
	if !strings.Contains(destHost, ":") {
		destHost += ":80"
	}

	destConn, err := p.dialOut("tcp", destHost)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	if err := req.Write(destConn); err != nil {
		return
	}

	p.relay(conn, br, destConn)
}

func (p *ProxyServer) relay(client net.Conn, br *bufio.Reader, dest net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> dest
	go func() {
		defer wg.Done()
		if br.Buffered() > 0 {
			buf := make([]byte, br.Buffered())
			_, _ = br.Read(buf)
			_, _ = dest.Write(buf)
		}
		_, _ = io.Copy(dest, client)
	}()

	// dest -> client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, dest)
	}()

	wg.Wait()
}
