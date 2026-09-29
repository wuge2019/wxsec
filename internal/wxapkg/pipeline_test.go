package wxapkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wxsec/internal/scanner"
)

// TestEndToEndPipeline 模拟一次真实工作流：
// 微信缓存目录里的 V1MMWX 加密包 → 解密 → 解包 → 工程还原 → 静态安全扫描。
func TestEndToEndPipeline(t *testing.T) {
	const appid = "wx1a2b3c4d5e6f7a8b"

	// 构造一个"打平"的新版包：只有 bundle 文件
	bundle := strings.Replace(fakeAppService, "hello", "secret probe", 1) +
		"\nvar secret = { appSecret: \"supersecretvalue123456\" }; // 假数据\n"
	files := map[string][]byte{
		"/common.app.js":       []byte(bundle),
		"/app-wxss.js":         []byte("setCssToHead([],{path:\"/app.wxss\"})"),
		"/app-config.json":     []byte(`{"pages":["pages/index/index"],"global":{"window":{}},"page":{}}`),
		"/assets/pic.png":      {0x89, 'P', 'N', 'G', 0, 1},
	}
	plain := pack(t, files, []string{"/common.app.js", "/app-wxss.js", "/app-config.json", "/assets/pic.png"})
	enc := encryptV1(t, plain, appid)

	cacheDir := t.TempDir()
	src := filepath.Join(cacheDir, appid, "1169", "__APP__.wxapkg")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, enc, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), appid+"_unpacked")
	res, err := UnpackFile(src, Options{OutDir: outDir, Beautify: true, Restore: true})
	if err != nil {
		t.Fatalf("UnpackFile: %v", err)
	}
	if !res.Decrypted {
		t.Fatal("expected decrypted flag")
	}
	if res.Restored == nil || res.Restored.Type != TypeFlattened {
		t.Fatalf("restore did not run: %+v", res.Restored)
	}
	if _, err := os.Stat(filepath.Join(outDir, "pages", "index", "index.js")); err != nil {
		t.Fatalf("page js not restored: %v", err)
	}

	// 还原结果直接进入扫描引擎
	scan, err := scanner.Scan(scanner.Options{Root: outDir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	rules := map[string]bool{}
	for _, f := range scan.Findings {
		rules[f.RuleID] = true
	}
	if !rules["KEY-001"] {
		t.Errorf("planted appSecret not found by scanner; findings=%+v", scan.Findings)
	}
	if scan.FilesScanned == 0 {
		t.Error("scanner visited no files")
	}
}
