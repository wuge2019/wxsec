package decomp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demoRegistration = "__wxAppCode__['pages/demo/index.wxml'] = $gwx_testappid('./pages/demo/index.wxml');\n"

// fakeBundle 复刻真实编译产物的契约：$gwx 工厂 + 模板注册语句，
// 渲染函数以数据作用域 env 求值并组装虚拟 DOM。
const fakeBundleBody = `
var __wxAppCode__ = __wxAppCode__ || {};
var $gwx_testappid = function(path, global) {
  if (typeof global === 'undefined') global = {};
  if (typeof global.entrys === 'undefined') global.entrys = {};
  var e_ = global.entrys;
  e_['./pages/demo/index.wxml'] = {
    f: function(env, scopes, root, g) {
      var box = {tag:'wx-view', attr:{class:'box'}, children:[], raw:{}, generics:{}};
      root.children.push(box);
      box.children.push({tag:'wx-text', attr:{class:''}, children:[ String(env.title) ], raw:{}, generics:{}});
      box.children.push({tag:'wx-image', attr:{src: 'https://cdn.demo/' + env.logo, mode:'aspectFill'}, children:[], raw:{}, generics:{}});
      box.children.push({tag:'wx-myComp', attr:{item: env.item, bindtap:'onTap', catchtouchmove:'noop', hidden: false}, children:[], raw:{}, generics:{}});
      var list = {tag:'wx-view', attr:{class:'list'}, children:[], raw:{}, generics:{}};
      box.children.push(list);
      list.children.push({tag:'virtual', wxKey:'1', children:[
        {tag:'wx-text', attr:{}, children:[ String(env.item.name) ], raw:{}, generics:{}}
      ], raw:{}, generics:{}});
    }
  };
  if (path && e_[path]) {
    return function(env, dd, global) {
      var root = {tag:'wx-page'};
      root.children = [];
      e_[path].f(env, {}, root, global || {});
      return root;
    };
  }
};
__wxAppCode__['pages/demo/index.wxss'] = '.box{color:red}';
`

const fakeBundle = fakeBundleBody + demoRegistration

// cssBundle 复刻真实 app-wxss 的写法：样式经 setCssToHead 灌进 <style> 元素，
// __wxAppCode__ 里拿不到字符串，只能从 DOM 桩回收。
const cssBundle = `
var setCssToHead = function(file, _xc, info) {
  var rewritor = function(suffix, opt, style) {
    if (!style) {
      style = document.createElement('style');
      style.type = 'text/css';
      style.setAttribute('wxss:path', info.path);
      document.head.appendChild(style);
    }
    style.styleSheet.cssText = '.made-up{color:#0f0}';
  };
  return rewritor;
};
__wxAppCode__['pages/demo/index.wxss'] = setCssToHead([".a{}"], undefined, {path:"./pages/demo/index.wxss"})();
__wxAppCode__['pages/demo/lazy.wxss'] = setCssToHead([".b{}"], undefined, {path:"./pages/demo/lazy.wxss"});
`

func TestDecompileRestoresCssFromStyleElements(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "page-frame.js"), []byte(cssBundle), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := DecompileDir(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range res.Pages {
		if p.Kind != "wxss" {
			continue
		}
		b, _ := os.ReadFile(p.Path)
		if !strings.Contains(string(b), ".made-up") {
			t.Errorf("restored wxss %s = %s", p.Entry, b)
		}
		seen[filepath.Base(p.Path)] = true
	}
	// 自执行的与注册成闭包、需要我们主动调用一次的，两种都要还原出来。
	if !seen["index.wxss"] || !seen["lazy.wxss"] {
		t.Fatalf("css recovery incomplete: %+v", res.Pages)
	}
}

// fakeBundleNoReg 去掉注册语句，用于验证退回枚举 __wxAppCode__ 的兜底路径。
const fakeBundleNoReg = fakeBundleBody

func TestDecompileFallbackWithoutRegistration(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "page-frame.js"), []byte(fakeBundleNoReg), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := DecompileDir(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pages) == 0 {
		t.Fatalf("fallback path produced nothing: %+v", res)
	}
	for _, p := range res.Pages {
		if p.Kind != "wxml" {
			continue
		}
		b, _ := os.ReadFile(p.Path)
		if !strings.Contains(string(b), "{{title}}") {
			t.Errorf("fallback wxml incomplete:\n%s", b)
		}
	}
}

func TestDecompileFakeBundle(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "page-frame.js"), []byte(fakeBundle), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := DecompileDir(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) > 0 {
		t.Fatalf("unexpected skips: %v", res.Skipped)
	}

	var wxml, wxss string
	for _, p := range res.Pages {
		b, err := os.ReadFile(p.Path)
		if err != nil {
			t.Fatalf("read %s: %v", p.Path, err)
		}
		switch p.Kind {
		case "wxml":
			wxml = string(b)
		case "wxss":
			wxss = string(b)
		}
	}
	if wxml == "" {
		t.Fatalf("no wxml produced: %+v", res.Pages)
	}

	for _, want := range []string{
		"<view", "class=\"box\"",
		"{{title}}",                         // 纯动态文本
		"src=\"https://cdn.demo/{{logo}}\"", // 拼接型动态属性
		"item=\"{{item}}\"",                 // 组件属性绑定
		"bind:tap=\"onTap\"",                // 事件名还原
		"catch:touchmove",                   //
		"<myComp",                           // 自定义组件去掉 wx- 前缀
		"{{item.name}}",                     // virtual 容器内联展开
	} {
		if !strings.Contains(wxml, want) {
			t.Errorf("wxml missing %q\n%s", want, wxml)
		}
	}
	if strings.Contains(wxml, "@@WX:") {
		t.Errorf("sentinel leaked into output:\n%s", wxml)
	}
	if strings.Contains(wxml, "<virtual") || strings.Contains(wxml, "<wx-page") {
		t.Errorf("internal wrapper leaked:\n%s", wxml)
	}
	if !strings.Contains(wxss, ".box{color:red}") {
		t.Errorf("wxss not restored: %q", wxss)
	}
}

func TestDecompileSkipsBrokenBundle(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app-service.js"), []byte("throw new Error('boom')"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := DecompileDir(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pages) != 0 {
		t.Errorf("expected no pages, got %v", res.Pages)
	}
	if len(res.Skipped) == 0 {
		t.Error("broken bundle should be recorded in Skipped")
	}
}

func TestDecompileIgnoresNonBundles(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "app.js"), []byte("var a=1"), 0o644)
	res, err := DecompileDir(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Bundles) != 0 {
		t.Errorf("app.js should not match bundle pattern, got %v", res.Bundles)
	}
}

func TestEmitWXMLDropsEmptyAndNull(t *testing.T) {
	tree := `{"tag":"wx-page","children":[
		{"tag":"wx-view","attr":{"class":"","x":null,"count":3,"obj":{"a":1}},"children":["   ","hello"]}
	]}`
	out, err := emitWXML(tree, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, `class=""`) {
		t.Errorf("empty attr should drop: %s", s)
	}
	if strings.Contains(s, `"x"`) || strings.Contains(s, " x=") {
		t.Errorf("null attr should drop: %s", s)
	}
	if !strings.Contains(s, `count="3"`) {
		t.Errorf("numeric attr should keep: %s", s)
	}
	if !strings.Contains(s, "hello") {
		t.Errorf("text should keep: %s", s)
	}
	if !strings.Contains(s, "obj=\"{{/*") {
		t.Errorf("object attr should mark dynamic: %s", s)
	}
}

func TestRestoreBindings(t *testing.T) {
	cases := map[string]string{
		"@@WX:item.title":   "{{item.title}}",
		"a@@WX:base/x.png":  "a{{base}}/x.png",
		"@@WX:list[0].name": "{{list[0].name}}",
		"static":            "static",
		"@@WX:item.":        "{{item}}",
	}
	for in, want := range cases {
		if got := restoreBindings(in); got != want {
			t.Errorf("restoreBindings(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEventAttrName(t *testing.T) {
	cases := map[string]string{
		"bindtap":        "bind:tap",
		"catchtouchmove": "catch:touchmove",
		"bind:change":    "bind:change",
		"class":          "class",
		"data-id":        "data-id",
	}
	for in, want := range cases {
		if got := eventAttrName(in); got != want {
			t.Errorf("eventAttrName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSanitizeEntry(t *testing.T) {
	cases := map[string]string{
		"./pages/index/index.wxml":                       filepath.Join("pages", "index", "index.wxml"),
		"plugin-private://wxabc/components/x/index.wxml": filepath.Join("wxabc", "components", "x", "index.wxml"),
		"../../etc/passwd":                               filepath.Join("_", "_", "etc", "passwd"),
	}
	for in, want := range cases {
		if got := sanitizeEntry(in); got != want {
			t.Errorf("sanitizeEntry(%q)=%q want %q", in, got, want)
		}
	}
	// 还原结果不得逃出输出目录
	if strings.Contains(sanitizeEntry("../../x"), "..") {
		t.Error("traversal not neutralised")
	}
}

func TestEmitWXMLNotesTemplateDeps(t *testing.T) {
	empty := `{"tag":"wx-page","children":[]}`
	out, err := emitWXML(empty, []string{"./base.wxml"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "./base.wxml") {
		t.Errorf("deps hint missing:\n%s", out)
	}
	// 有正文时不该有多余注释
	full := `{"tag":"wx-page","children":[{"tag":"wx-view","attr":{"class":"a"},"children":[]}]}`
	out2, err := emitWXML(full, []string{"./base.wxml"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "base.wxml") {
		t.Errorf("deps hint should only appear for empty tree:\n%s", out2)
	}
}

func TestVDOMParseKeepsRawChildren(t *testing.T) {
	var n vdom
	if err := json.Unmarshal([]byte(`{"tag":"wx-view","children":["a",{"tag":"wx-text"}]}`), &n); err != nil {
		t.Fatal(err)
	}
	if len(n.Children) != 2 {
		t.Fatalf("children=%d", len(n.Children))
	}
}
