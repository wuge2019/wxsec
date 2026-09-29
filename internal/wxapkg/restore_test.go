package wxapkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeAppService = `
(function e(t,n,r){function s(o,u){if(!n[o]){var i=n[o]={exports:{}};t[o][0].call(i.exports)}return i.exports}return s(t,o,u)})(modules,installs,entries);
define("pages/index/index.js", function(require, module, exports){
    "use strict";
    Page({
        data: { msg: "hello" },
        onLoad: function() { console.log(this.data.msg); }
    });
}, { currentRoute: "pages/index/index", pageNo: 0, pageKind: "page", isPage: true });
define('components/nav/nav.js', function(require, module, exports){
    "use strict";
    Component({ properties: { title: String } });
}, { isPage: false });
__wxAppCode__['pages/index/index.json'] = {usingComponents: {}, navigationBarTitleText: '首页'};
__wxAppCode__['app.json'] = {"pages":["pages/index/index"],"window":{"navigationBarTitleText":"演示"}};
`

func writeFakeBundle(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, bundleCommonApp), []byte(fakeAppService), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundleAppWxss), []byte("page{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	appCfg := map[string]any{
		"entryPagePath": "pages/index/index",
		"pages":         []any{"pages/index/index", "pages/about/about"},
		"global":        map[string]any{"window": map[string]any{"navigationBarTitleText": "演示"}},
		"page": map[string]any{
			"pages/index/index.html": map[string]any{"window": map[string]any{"navigationBarTitleText": "首页"}},
			"pages/about/about.html": map[string]any{"navigationStyle": "custom"},
		},
	}
	b, _ := json.Marshal(appCfg)
	if err := os.WriteFile(filepath.Join(dir, bundleAppConfig), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectType(t *testing.T) {
	dir := t.TempDir()
	if got := DetectType(dir); got != TypeLegacy {
		t.Fatalf("empty dir should be legacy, got %s", got)
	}
	writeFakeBundle(t, dir)
	if got := DetectType(dir); got != TypeFlattened {
		t.Fatalf("bundle dir should be flattened, got %s", got)
	}
}

func TestRestoreSplitsModulesAndConfigs(t *testing.T) {
	dir := t.TempDir()
	writeFakeBundle(t, dir)

	res, err := Restore(dir)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Type != TypeFlattened {
		t.Fatalf("unexpected type %s", res.Type)
	}

	// define() 页面模块应还原为独立 JS 文件
	pageJS, err := os.ReadFile(filepath.Join(dir, "pages", "index", "index.js"))
	if err != nil {
		t.Fatalf("page js not restored: %v", err)
	}
	body := string(pageJS)
	if !strings.Contains(body, "Page({") || !strings.Contains(body, "hello") {
		t.Fatalf("restored js looks wrong:\n%s", body)
	}
	if strings.Contains(body, "define(") || strings.Contains(body, `"use strict";\n    Page`) {
		t.Fatalf("define wrapper not stripped:\n%s", body)
	}

	// 组件模块
	if _, err := os.Stat(filepath.Join(dir, "components", "nav", "nav.js")); err != nil {
		t.Errorf("component js missing: %v", err)
	}

	// __wxAppCode__ 页面 json 应转成合法 JSON
	raw, err := os.ReadFile(filepath.Join(dir, "pages", "index", "index.json"))
	if err != nil {
		t.Fatalf("page json not restored: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("restored page json invalid: %v (%s)", err, raw)
	}
	if m["navigationBarTitleText"] != "首页" {
		t.Fatalf("json content wrong: %s", raw)
	}

	// app-config.json 的 pages 应补齐缺失页面（about 没有 define 模块）
	if _, err := os.Stat(filepath.Join(dir, "pages", "about", "about.json")); err != nil {
		t.Errorf("missing page placeholder not generated: %v", err)
	}

	// app.json 应从 app-config 生成
	appJSON, err := os.ReadFile(filepath.Join(dir, "app.json"))
	if err != nil {
		t.Fatalf("app.json not generated: %v", err)
	}
	var app map[string]any
	if err := json.Unmarshal(appJSON, &app); err != nil {
		t.Fatalf("generated app.json invalid: %v", err)
	}
	if _, ok := app["pages"]; !ok {
		t.Fatalf("app.json missing pages: %s", appJSON)
	}
}

func TestRestoreIsIdempotentAndSafe(t *testing.T) {
	dir := t.TempDir()
	writeFakeBundle(t, dir)
	if _, err := Restore(dir); err != nil {
		t.Fatal(err)
	}
	// 第二次不应覆盖已有真实 json（内容含中文标题）
	second, err := Restore(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "pages", "index", "index.json"))
	if !strings.Contains(string(raw), "首页") {
		t.Fatalf("second run clobbered restored json: %s", raw)
	}
	if second.Type != TypeFlattened {
		t.Fatalf("type drift: %s", second.Type)
	}
}

func TestNormalizeJSObject(t *testing.T) {
	cases := map[string]string{
		`{usingComponents: {}, navigationBarTitleText: '首页'}`: `{"usingComponents":{},"navigationBarTitleText":"首页"}`,
		`{a: [1, "x"], b: {c: true}}`:                           `{"a":[1,"x"],"b":{"c":true}}`,
		`{url: "http://a.com/?q=1,x", k: 'v\'q'}`:               `{"url":"http://a.com/?q=1,x","k":"v'q"}`,
	}
	for in, want := range cases {
		got := normalizeJSObject(in)
		var a, b any
		if json.Unmarshal([]byte(got), &a) != nil {
			t.Errorf("output not valid json: %s", got)
			continue
		}
		_ = json.Unmarshal([]byte(want), &b)
		if jsonMarshal(a) != jsonMarshal(b) {
			t.Errorf("normalizeJSObject(%q) = %s, want %s", in, got, want)
		}
	}
}

func jsonMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestMatchBraceHandlesStringsAndComments(t *testing.T) {
	src := `{'a}': 1, /* } */ b: 'x\'y', c: "}\""}`
	end, ok := matchBrace(src, 0)
	if !ok {
		t.Fatal("unbalanced")
	}
	if src[end] != '}' || end != len(src)-1 {
		t.Fatalf("wrong close at %d: %q", end, src[:end+1])
	}
}
