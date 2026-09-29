package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 说明：以下均为构造的假数据，仅用于验证规则命中，不代表任何真实凭据。
var corpus = map[string]string{
	"app.js": `
var app = getApp();
App({
  globalData: { appSecret: "abcdef1234567890abcdef12", api_key: 'AKID-fake-secret-token' },
  onLaunch() {
    wx.request({ url: "http://api.example-target.com/v1/user/list?token=abc" });
    wx.request({ url: "https://oapi.example-target.com/cgi-bin/get" });
    wx.request({ url: "http://10.20.30.40:8080/internal/admin" });
    eval(this.globalData.code);
    console.log("openid=" + wx.getStorageSync('openid_cache'));
  }
})
`,
	"utils/config.js": `
module.exports = {
  baseURL: "https://test.dev.example-target.com",
  isDebug: true,
  aesKey: "0123456789abcdef0123456789abcdef",
  tunnel: "https://abc123.ngrok.io/callback",
  redirect_url: options.query.redirect_url,
  version: "1.0.23.4",
  support: "ops@example-target.com",
  contact: "13800001111",
  idcard: "11010519491231002X",
  card: "4111 1111 1111 1111",
  mchId: "1508123456789012345",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz123456"
};
`,
	"pages/index/index.wxml": `<view class="box">
  <web-view src="{{pageUrl}}"></web-view>
</view>`,
	"pages/index/index.json": `{"usingComponents":{}}`,
	"app.json":                     `{"pages":["pages/index/index"],"requiredPrivateInfos":["getLocation"],"permission":{"scope.userLocation":{"desc":"用于定位"}}}`,
}

func buildCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range corpus {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func hitRules(t *testing.T, res *Result) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range res.Findings {
		m[f.RuleID] = append(m[f.RuleID], f)
	}
	return m
}

func TestScanDetectsPlantedIssues(t *testing.T) {
	root := buildCorpus(t)
	res, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	hits := hitRules(t, res)

	want := []string{
		"KEY-001", // appSecret
		"KEY-002", // api_key
		"KEY-007", // aesKey / mchId
		"PII-001", // 手机号
		"PII-002", // 身份证
		"PII-004", // 邮箱
		"NET-001", // 明文 http
		"NET-003", // 内网 IP
		"NET-004", // ngrok 隧道
		"DGR-001", // eval
		"DGR-002", // web-view
		"DGR-003", // redirect_url
		"DGR-004", // 本地存储 openid
		"DGR-005", // isDebug
	}
	for _, id := range want {
		if len(hits[id]) == 0 {
			t.Errorf("rule %s did not fire", id)
		}
	}

	// 版本号不应被当成 IP，而真正的内网端点应该命中
	for _, f := range hits["NET-002"] {
		if strings.Contains(f.Value, "1.0.23") {
			t.Errorf("version string leaked into NET-002 findings: %s", f.Value)
		}
	}
	if len(hits["NET-002"]) != 1 || hits["NET-002"][0].Value != "10.20.30.40" {
		t.Errorf("NET-002 should fire once on 10.20.30.40, got %+v", hits["NET-002"])
	}
}

func TestSecretsAreMasked(t *testing.T) {
	res, err := Scan(Options{Root: buildCorpus(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		switch f.RuleID {
		case "KEY-001", "KEY-002", "KEY-007", "PII-002":
			if strings.Contains(f.Value, "abcdef1234567890abcdef12") || strings.Contains(f.Value, "11010519491231002X") {
				t.Errorf("finding %s exposes raw secret: %s", f.RuleID, f.Value)
			}
			if !strings.Contains(f.Value, "*") {
				t.Errorf("finding %s is not masked: %s", f.RuleID, f.Value)
			}
		}
	}
}

func TestAssetExtraction(t *testing.T) {
	res, err := Scan(Options{Root: buildCorpus(t)})
	if err != nil {
		t.Fatal(err)
	}
	wantURLs := []string{
		"http://api.example-target.com/v1/user/list?token=abc",
		"https://oapi.example-target.com/cgi-bin/get",
		"https://test.dev.example-target.com",
	}
	got := map[string]bool{}
	for _, a := range res.Assets {
		got[a.URL] = true
	}
	for _, u := range wantURLs {
		if !got[u] {
			t.Errorf("asset %s missing; got %v", u, got)
		}
	}
	if len(res.Hosts) < 3 {
		t.Fatalf("expected >=3 hosts, got %v", res.Hosts)
	}
}

func TestAppInfoCollected(t *testing.T) {
	res, err := Scan(Options{Root: buildCorpus(t)})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := res.AppInfo["页面数量"]; !ok || v != 1 {
		t.Errorf("app.json pages not parsed: %+v", res.AppInfo)
	}
	if _, ok := res.AppInfo["requiredPrivateInfos"]; !ok {
		t.Errorf("requiredPrivateInfos not collected: %+v", res.AppInfo)
	}
}

func TestValidationHelpers(t *testing.T) {
	if !ValidIDCard("11010519491231002X") {
		t.Error("valid id card rejected")
	}
	if ValidIDCard("110105194912310021") {
		t.Error("invalid checksum accepted")
	}
	if !Luhn("4111111111111111") {
		t.Error("valid card rejected")
	}
	if Luhn("4111111111111112") {
		t.Error("invalid card accepted")
	}
	if !isRealIP("10.20.30.40") || isRealIP("999.1.1.1") || isRealIP("1.02.3.4") {
		t.Error("isRealIP misbehaves")
	}
	if MaskSecret("abcdefghijkl") != "abcd******kl" {
		t.Errorf("mask format: %s", MaskSecret("abcdefghijkl"))
	}
}

func TestBinaryAndHugeFilesSkipped(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "small.js"), []byte("var a=1;"), 0o644)
	os.WriteFile(filepath.Join(root, "big.js"), []byte(strings.Repeat("var a=1;\n", 5000)), 0o644)
	os.WriteFile(filepath.Join(root, "pic.png"), []byte{0x89, 'P', 'N', 'G', 0, 0, 1, 2}, 0o644)

	res, err := Scan(Options{Root: root, MaxFileBytes: 20000})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 {
		t.Fatalf("expected only small.js scanned, got %d", res.FilesScanned)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "big.js") {
		t.Fatalf("expected big.js skipped, got %v", res.Skipped)
	}
}
