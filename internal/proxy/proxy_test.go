package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T, dir string) *Authority {
	t.Helper()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	return ca
}

func startTestProxy(t *testing.T, ca *Authority, store *Store, intercept bool) *Proxy {
	t.Helper()
	p, err := New(Options{Port: 0, CA: ca, Store: store, Intercept: intercept, UpstreamCAs: ca.RootPool(),
		OnLog: func(s string) { t.Log("[proxy] " + s) }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p
}

func proxyClient(p *Proxy, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{
				Scheme: "http",
				Host:   fmt.Sprintf("127.0.0.1:%d", p.Port()),
			}),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
}

func waitForFlow(t *testing.T, s *Store, want func(Flow) bool) Flow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range s.All() {
			if want(f) {
				return f
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("expected flow not recorded; got %+v", s.All())
	return Flow{}
}

// TestProxyMITMDecryptsHTTPS 验证端到端：客户端信任本地 CA 时能拿到完整 URL、状态码与 AppID 归属。
func TestProxyMITMDecryptsHTTPS(t *testing.T) {
	dir := t.TempDir()
	ca := testCA(t, dir)
	store, err := NewStore(dir, 500)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	leaf, err := ca.ForHost("127.0.0.1")
	if err != nil {
		t.Fatalf("ForHost: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/order/list" {
			t.Errorf("上游收到意外路径 %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	defer srv.Close()

	p := startTestProxy(t, ca, store, true)
	client := proxyClient(p, ca.RootPool())

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/order/list?offset=0&limit=20", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Referer", "https://servicewechat.com/wx0123456789abcdef/16/page-frame.html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求经代理失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("响应体被破坏: %q", body)
	}

	f := waitForFlow(t, store, func(f Flow) bool { return f.Path == "/api/v1/order/list" })
	if f.Status != 200 {
		t.Errorf("status = %d, want 200", f.Status)
	}
	if !f.Intercepted {
		t.Error("Intercepted = false, 期望已解密")
	}
	if f.Query != "offset=0&limit=20" {
		t.Errorf("query = %q", f.Query)
	}
	if !strings.HasPrefix(f.URL, "https://127.0.0.1:") {
		t.Errorf("url = %q", f.URL)
	}
	if f.AppID != "wx0123456789abcdef" || f.WxVersion != "16" {
		t.Errorf("AppID 归属错误: %q / %q", f.AppID, f.WxVersion)
	}
	if f.RespBytes <= 0 {
		t.Errorf("respBytes = %d", f.RespBytes)
	}
}

// TestProxyRecordsDomainWhenCertRejected 验证证书未被信任（等价于证书固定）时降级为域名级记录。
func TestProxyRecordsDomainWhenCertRejected(t *testing.T) {
	dir := t.TempDir()
	ca := testCA(t, dir)
	store, err := NewStore(dir, 500)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	leaf, _ := ca.ForHost("127.0.0.1")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	defer srv.Close()

	p := startTestProxy(t, ca, store, true)
	// 客户端不信任本地 CA：握手必然被拒，代理仍应留下域名记录。
	client := proxyClient(p, nil)
	if _, err := client.Get(srv.URL + "/api/secret"); err == nil {
		t.Fatal("期望客户端拒绝代理证书")
	}
	f := waitForFlow(t, store, func(f Flow) bool { return f.Scheme == "connect" })
	if f.Intercepted {
		t.Error("握手失败不应标记为已解密")
	}
	if !strings.Contains(f.Note, "TLS 握手被客户端拒绝") {
		t.Errorf("note = %q", f.Note)
	}
	if !strings.HasPrefix(f.Host, "127.0.0.1") {
		t.Errorf("host = %q", f.Host)
	}
}

// TestProxyCapturesPlainHTTP 验证明文 HTTP 代理请求同样入库。
func TestProxyCapturesPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	ca := testCA(t, dir)
	store, err := NewStore(dir, 500)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	p := startTestProxy(t, ca, store, true)
	client := proxyClient(p, ca.RootPool())
	resp, err := client.Get(srv.URL + "/v2/config?k=1")
	if err != nil {
		t.Fatalf("明文 HTTP 经代理失败: %v", err)
	}
	resp.Body.Close()

	f := waitForFlow(t, store, func(f Flow) bool { return f.Scheme == "http" })
	if f.Path != "/v2/config" || f.Status != 200 {
		t.Errorf("flow = %+v", f)
	}
}

func TestAttributeReferer(t *testing.T) {
	cases := []struct {
		in  string
		app string
		ver string
	}{
		{"https://servicewechat.com/wx0123456789abcdef/16/page-frame.html", "wx0123456789abcdef", "16"},
		{"https://servicewechat.com/WXAAAAAAAAAAAAAAAA/2/page-frame.html", "wxaaaaaaaaaaaaaaaa", "2"},
		{"https://servicewechat.com/wx0123456789abcdef/devtools/page-frame.html", "wx0123456789abcdef", "devtools"},
		{"https://example.com/servicewechat.com/wx0123456789abcdef/9/x", "wx0123456789abcdef", "9"},
		{"https://mp.weixin.qq.com/", "", ""},
		{"", "", ""},
		{"https://servicewechat.com/notanappid/1/page-frame.html", "", ""},
	}
	for _, c := range cases {
		app, ver := AttributeReferer(c.in)
		if app != c.app || ver != c.ver {
			t.Errorf("AttributeReferer(%q) = %q,%q want %q,%q", c.in, app, ver, c.app, c.ver)
		}
	}
}

func TestStorePersistsAndClears(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 500)
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Flow{Host: "a.example.com", URL: "https://a.example.com/x"})
	s.Add(Flow{Host: "b.example.com", URL: "https://b.example.com/y"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(dir, 500)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.All(); len(got) != 2 {
		t.Fatalf("重新加载后条数 = %d, want 2", len(got))
	}
	if got := s2.All()[1].Seq; got != 2 {
		t.Errorf("seq 未续上: %d", got)
	}
	if err := s2.Clear(); err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 0 {
		t.Errorf("Clear 后仍有 %d 条", s2.Len())
	}
	_ = s2.Close()
}

func TestStoreRingDropsOldest(t *testing.T) {
	s, err := NewStore(t.TempDir(), 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 5; i++ {
		s.Add(Flow{Host: fmt.Sprintf("h%d.example.com", i)})
	}
	all := s.All()
	if len(all) != 3 {
		t.Fatalf("len = %d, want 3", len(all))
	}
	if all[0].Host != "h2.example.com" {
		t.Errorf("最早条目应被丢弃, got %q", all[0].Host)
	}
	if s.Dropped() != 2 {
		t.Errorf("dropped = %d, want 2", s.Dropped())
	}
}
