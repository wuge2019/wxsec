package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wxsec/internal/scanner"
)

func sampleResult() *scanner.Result {
	return &scanner.Result{
		Root:         `C:\demo\wx0123456789abcdef_unpacked`,
		StartedAt:    time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC),
		DurationMs:   123,
		FilesTotal:   40,
		FilesScanned: 28,
		BytesScanned: 2 << 20,
		Findings: []scanner.Finding{
			{
				ID: "a1", RuleID: "KEY-001", Category: scanner.CatSecrets, Title: "硬编码 AppSecret",
				Severity: scanner.SevHigh, File: "utils/config.js", Line: 4,
				Value: "abcd******12", Context: `appSecret: "abcd******12"`,
				Recommend: "仅服务端使用",
			},
			{
				ID: "a2", RuleID: "NET-001", Category: scanner.CatNetwork, Title: "明文 HTTP 接口",
				Severity: scanner.SevMedium, File: "app.js", Line: 9,
				Value: "http://api.example.com/v1/user",
			},
		},
		Assets:   []scanner.Asset{{URL: "https://api.example.com/v1/a", Scheme: "https", Host: "api.example.com", File: "app.js", Line: 9, Count: 3}},
		Hosts:    []string{"api.example.com"},
		AppInfo:  map[string]any{"页面数量": 2, "requiredPrivateInfos": []any{"getLocation"}},
		SevCount: map[string]int{"high": 1, "medium": 1, "low": 0, "info": 0},
		Skipped:  []string{"assets/big.bin（超出大小上限）"},
	}
}

func TestRenderHTMLEscapesUntrustedContent(t *testing.T) {
	res := sampleResult()
	// 被扫小程序可控内容里注入脚本，报告必须做 HTML 转义
	res.Findings[0].Context = `<script>alert('xss')</script>`
	res.Findings[1].File = `../evil<script>.js`

	html, err := RenderHTML(res)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	s := string(html)
	if strings.Contains(s, "<script>alert") {
		t.Fatal("XSS payload was not escaped in report")
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Fatal("escaped payload missing")
	}
	for _, want := range []string{"微信小程序安全测试报告", "高危问题", "KEY-001", "api.example.com", "接口资产清单"} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if bytes.Count(html, []byte("<table")) < 2 {
		t.Error("expected finding and asset tables")
	}
}

func TestExportHTMLAndJSON(t *testing.T) {
	dir := t.TempDir()
	res := sampleResult()

	htmlPath, err := Export(res, dir, "html")
	if err != nil {
		t.Fatalf("export html: %v", err)
	}
	if !strings.HasSuffix(htmlPath, ".html") {
		t.Errorf("unexpected html path %s", htmlPath)
	}

	jsonPath, err := Export(res, dir, "json")
	if err != nil {
		t.Fatalf("export json: %v", err)
	}
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var back scanner.Result
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("exported json not parseable: %v", err)
	}
	if len(back.Findings) != 2 || back.SevCount["high"] != 1 {
		t.Errorf("json round trip lost data: %+v", back.SevCount)
	}

	if _, err := Export(res, filepath.Join(dir, "sub"), "csv"); err == nil {
		t.Error("expected error for unsupported format")
	}
}
