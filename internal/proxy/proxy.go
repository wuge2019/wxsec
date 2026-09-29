package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// idleTimeout 是复用连接等待下一个请求的上限。
const idleTimeout = 2 * time.Minute

// Options 是代理启动参数。
type Options struct {
	// Port 监听端口，0 表示随机端口（自检用）。
	Port int
	// Host 监听地址，默认 127.0.0.1，只对本机开放。
	Host string
	CA   *Authority
	// Intercept 为 false 时退化为「只记域名不解密」的透明代理。
	Intercept bool
	// UpstreamCAs 非空时用于校验上游证书（自检与本地测试服务器用），默认走系统根证书。
	UpstreamCAs *x509.CertPool
	Store       *Store
	OnLog       func(string)
}

// Proxy 是本地 HTTPS 抓包代理。
type Proxy struct {
	opt   Options
	store *Store

	mu      sync.Mutex
	ln      net.Listener
	port    int
	running bool
	stopped bool
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

// New 创建代理实例。
func New(opt Options) (*Proxy, error) {
	if opt.CA == nil {
		return nil, errors.New("ca is required")
	}
	if opt.Store == nil {
		return nil, errors.New("store is required")
	}
	if opt.Host == "" {
		opt.Host = "127.0.0.1"
	}
	return &Proxy{opt: opt, store: opt.Store, conns: map[net.Conn]struct{}{}}, nil
}

// Start 开始监听，返回实际端口。
func (p *Proxy) Start() (int, error) {
	p.mu.Lock()
	if p.running {
		port := p.port
		p.mu.Unlock()
		return port, nil
	}
	p.mu.Unlock()

	addr := net.JoinHostPort(p.opt.Host, strconv.Itoa(p.opt.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("监听 %s 失败（端口可能被占用，请换一个）：%w", addr, err)
	}
	p.mu.Lock()
	p.ln = ln
	p.port = ln.Addr().(*net.TCPAddr).Port
	p.running = true
	p.stopped = false
	p.mu.Unlock()

	p.logf("抓包代理已启动：%s", ln.Addr().String())
	p.wg.Add(1)
	go p.acceptLoop(ln)
	return p.port, nil
}

// Stop 关闭监听并断开活动连接。
func (p *Proxy) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	ln := p.ln
	p.ln = nil
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	p.wg.Wait()
	p.logf("抓包代理已停止")
	return nil
}

// Running 返回代理是否在监听。
func (p *Proxy) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// Port 返回当前监听端口。
func (p *Proxy) Port() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.port
}

// Intercept 返回当前是否处于解密模式。
func (p *Proxy) Intercept() bool { return p.opt.Intercept }

func (p *Proxy) logf(format string, args ...any) {
	if p.opt.OnLog != nil {
		p.opt.OnLog(fmt.Sprintf(format, args...))
	}
}

func (p *Proxy) acceptLoop(ln net.Listener) {
	defer p.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			running := p.running
			p.mu.Unlock()
			if running {
				p.logf("接受连接失败: %v", err)
			}
			return
		}
		p.track(c)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(c)
			defer c.Close()
			p.serve(c)
		}()
	}
}

func (p *Proxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *Proxy) serve(client net.Conn) {
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		p.handleConnect(client, req)
		return
	}
	p.handlePlain(client, br, req)
}

// ── HTTPS：CONNECT + 中间人解密 ─────────────────────────────────────────

func (p *Proxy) handleConnect(client net.Conn, req *http.Request) {
	authority := req.Host
	host := HostFromAuthority(authority)
	target := authority
	if host != "" && !strings.Contains(authority, ":") {
		target = net.JoinHostPort(authority, "443")
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	if !p.opt.Intercept {
		up, err := p.dial(target)
		if err != nil {
			p.recordConnect(host, "代理未开启解密，且连接目标失败: "+err.Error())
			return
		}
		defer up.Close()
		p.recordConnect(host, "未开启解密模式，仅记录域名")
		pipe(client, up)
		return
	}

	leaf, err := p.opt.CA.ForHost(host)
	if err != nil {
		p.recordConnect(host, "签发叶子证书失败: "+err.Error())
		return
	}
	// 只协商 http/1.1：避免 HTTP/2 二进制帧无法被逐条解析。
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	}
	clientTLS := tls.Server(client, tlsCfg)
	clientTLS.SetDeadline(time.Now().Add(30 * time.Second))
	if err := clientTLS.Handshake(); err != nil {
		clientTLS.SetDeadline(time.Time{})
		// 客户端拒绝我们的证书：证书固定或未信任本 CA。域名信息仍然有价值。
		p.logf("TLS 握手失败 %s: %v", host, err)
		p.recordConnect(host, "TLS 握手被客户端拒绝（可能证书固定，或未信任 wxsec 根证书），仅记录域名")
		return
	}
	clientTLS.SetDeadline(time.Time{})
	defer clientTLS.Close()

	upTLS, err := p.dialTLS(target, host)
	if err != nil {
		p.recordFlow(Flow{
			Scheme: "https", Method: "CONNECT", Host: host, URL: "https://" + host,
			Intercepted: true, Note: "连接目标服务器失败: " + err.Error(),
		})
		return
	}
	defer upTLS.Close()

	p.logf("MITM %s", host)
	p.serveTunnel(bufio.NewReader(clientTLS), clientTLS, upTLS, host, "https")
}

// serveTunnel 在已解密的隧道里逐条转发请求，直到任一端结束。
func (p *Proxy) serveTunnel(br *bufio.Reader, client net.Conn, upstream net.Conn, host, scheme string) {
	up := bufio.NewReader(upstream)
	for {
		// 空闲超时：微信会长时间复用连接，不设上限会一直占着 goroutine。
		client.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		client.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		if req.Method == http.MethodConnect {
			// 隧道内再次 CONNECT（极少见），当作普通请求处理会出错，直接结束。
			return
		}
		req.Header.Del("Proxy-Authorization")
		if !p.forward(req, client, upstream, up, scheme, host) {
			return
		}
		if req.Close {
			return
		}
	}
}

// ── 明文 HTTP ───────────────────────────────────────────────────────────

func (p *Proxy) handlePlain(client net.Conn, br *bufio.Reader, req *http.Request) {
	for {
		target := req.URL.Host
		if target == "" {
			target = req.Host
		}
		if target == "" {
			return
		}
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "80")
		}
		up, err := p.dial(target)
		if err != nil {
			p.recordFlow(Flow{
				Scheme: "http", Method: req.Method, Host: HostFromAuthority(target),
				URL: req.URL.String(), Note: "连接目标失败: " + err.Error(),
			})
			return
		}
		upBuf := bufio.NewReader(up)
		req.Header.Del("Proxy-Authorization")
		ok := p.forward(req, client, up, upBuf, "http", HostFromAuthority(target))
		up.Close()
		if !ok || req.Close {
			return
		}
		client.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err = http.ReadRequest(br)
		client.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
	}
}

// ── 转发与记录 ──────────────────────────────────────────────────────────

// forward 把单个请求发给上游并把响应写回客户端，返回 false 表示连接应结束。
func (p *Proxy) forward(req *http.Request, client net.Conn, upstream net.Conn, up *bufio.Reader, scheme, defaultHost string) bool {
	start := time.Now()
	url, host, path, query := splitRequest(req, scheme, defaultHost)
	intercepted := scheme == "https" || scheme == "http"

	reqW := &countWriter{w: upstream}
	var writeReqErr error
	if err := req.Write(reqW); err != nil {
		writeReqErr = err
	}
	reqBytes := reqW.n

	resp, err := http.ReadResponse(up, req)
	if err != nil {
		note := "转发请求失败: "
		if writeReqErr != nil {
			note += writeReqErr.Error()
		} else {
			note = "读取响应失败: "
			note += err.Error()
		}
		p.recordFlow(Flow{
			Time: start, Scheme: scheme, Method: req.Method, URL: url,
			Host: host, Path: path, Query: query, Intercepted: intercepted,
			UserAgent: req.UserAgent(), Referer: req.Header.Get("Referer"),
			DurationMs: millis(time.Since(start)), ReqBytes: reqBytes,
			Note: note,
		})
		return false
	}
	defer resp.Body.Close()

	cw := &countWriter{w: client}
	note := ""
	if writeReqErr != nil {
		note = "转发请求失败: " + writeReqErr.Error()
	}
	writeErr := resp.Write(cw)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		upNote := "协议升级（WebSocket 等），后续帧未解析"
		if note == "" {
			note = upNote
		}
		if writeErr == nil {
			pipe(client, upstream)
		}
	}

	appid, ver := AttributeReferer(req.Header.Get("Referer"))
	f := Flow{
		Time:        start,
		Scheme:      scheme,
		Method:      req.Method,
		URL:         url,
		Host:        host,
		Path:        path,
		Query:       query,
		Status:      resp.StatusCode,
		Proto:       strings.TrimPrefix(resp.Proto, "HTTP/"),
		ReqType:     req.Header.Get("Content-Type"),
		ContentType: resp.Header.Get("Content-Type"),
		ReqBytes:    reqBytes,
		RespBytes:   cw.n,
		DurationMs:  millis(time.Since(start)),
		AppID:       appid,
		WxVersion:   ver,
		Referer:     req.Header.Get("Referer"),
		UserAgent:   req.UserAgent(),
		Intercepted: intercepted,
		Note:        note,
	}
	if writeErr != nil && f.Note == "" {
		f.Note = "写回客户端失败: " + writeErr.Error()
	}
	p.recordFlow(f)
	return writeErr == nil
}

// splitRequest 归一化出完整 URL 与主机/路径/查询。
// 隧道内是 origin-form（req.URL.Host 为空），代理请求是 absolute-form。
func splitRequest(req *http.Request, scheme, defaultHost string) (url, host, path, query string) {
	host = req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		host = defaultHost
	}
	path = req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	query = req.URL.RawQuery
	url = scheme + "://" + host + path
	if query != "" {
		url += "?" + query
	}
	return url, HostFromAuthority(host), path, query
}

func (p *Proxy) recordFlow(f Flow) {
	if f.Host == "" && f.URL != "" {
		f.Host = HostFromAuthority(f.URL)
	}
	p.store.Add(f)
}

func (p *Proxy) recordConnect(host, note string) {
	p.recordFlow(Flow{
		Scheme: "connect",
		Method: "CONNECT",
		Host:   host,
		URL:    "https://" + host,
		Note:   note,
	})
}

func (p *Proxy) dial(target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (p *Proxy) dialTLS(target, serverName string) (net.Conn, error) {
	raw, err := p.dial(target)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
		RootCAs:            p.opt.UpstreamCAs,
		InsecureSkipVerify: false,
	})
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})
	return tc, nil
}

// pipe 双向透传直到任一端结束，用于不解密模式与协议升级后的隧道。
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(b, a) }()
	go func() { defer wg.Done(); _, _ = io.Copy(a, b) }()
	wg.Wait()
}

type countWriter struct {
	w net.Conn
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func millis(d time.Duration) int64 {
	if d < 0 {
		return 0
	}
	return int64(d / time.Millisecond)
}
