package cross

import (
	"testing"

	"wxsec/internal/proxy"
	"wxsec/internal/scanner"
)

func asset(u, file string) scanner.Asset {
	return scanner.Asset{URL: u, File: file, Count: 1}
}

func flow(u, host, path, appid string) proxy.Flow {
	return proxy.Flow{URL: u, Scheme: "https", Host: host, Path: path, Method: "GET", Status: 200, AppID: appid}
}

func rowOf(t *testing.T, r *Report, host, path string) Row {
	t.Helper()
	for _, row := range r.Rows {
		if row.Host == host && row.Path == path {
			return row
		}
	}
	t.Fatalf("未找到行 %s%s；现有 %+v", host, path, r.Rows)
	return Row{}
}

func TestAnalyzeCategories(t *testing.T) {
	assets := []scanner.Asset{
		asset("https://api.example.com/v1/user/list", "pages/user/index.js"),
		asset("https://api.example.com/v1/order/", "pages/order/index.js"),
		asset("https://api.example.com/v1/order/${id}/detail", "pages/order/detail.js"),
		asset("https://api.example.com/v1/coupon/never-called", "app-service.js"),
	}
	flows := []proxy.Flow{
		{URL: "https://api.example.com/v1/user/list?offset=0&limit=20", Scheme: "https", Host: "API.example.com",
			Path: "/v1/user/list", Query: "offset=0&limit=20", Method: "GET", Status: 200, AppID: "wx0123456789abcdef"},
		{URL: "https://api.example.com/v1/user/list?offset=20", Scheme: "https", Host: "api.example.com",
			Path: "/v1/user/list", Query: "offset=20", Method: "POST", Status: 500, AppID: "wx0123456789abcdef"},
		{URL: "https://api.example.com/v1/order", Scheme: "https", Host: "api.example.com",
			Path: "/v1/order", Method: "GET", Status: 200},
		{URL: "https://api.example.com/v1/order/8871/detail", Scheme: "https", Host: "api.example.com",
			Path: "/v1/order/8871/detail", Method: "GET", Status: 200, AppID: "wxaaaaaaaaaaaaaaaa"},
		{URL: "https://api.example.com/v1/admin/export", Scheme: "https", Host: "api.example.com",
			Path: "/v1/admin/export", Method: "GET", Status: 200},
		{URL: "http://api.example.com/v1/plain/config", Scheme: "http", Host: "api.example.com",
			Path: "/v1/plain/config", Method: "GET", Status: 200},
		{Scheme: "connect", Host: "only-domain.example.com", Method: "CONNECT", Intercepted: false},
	}
	sdk := []scanner.Asset{asset("https://res.wx.qq.com/foo.js", "app-service.js")}
	sdk[0].SDK = "微信/腾讯开放平台"

	rep := Analyze(flows, assets, sdk, "/tmp/unpacked")

	both := rowOf(t, rep, "api.example.com", "/v1/user/list")
	if both.Category != CatBoth {
		t.Errorf("user/list 分类 = %q, want both", both.Category)
	}
	if both.DynamicCount != 2 || both.StaticCount != 1 {
		t.Errorf("计数错误: dyn=%d static=%d", both.DynamicCount, both.StaticCount)
	}
	if len(both.Methods) != 2 || both.Methods[0] != "GET" || both.Methods[1] != "POST" {
		t.Errorf("methods = %v", both.Methods)
	}
	if len(both.Statuses) != 2 || both.Statuses[1] != 500 {
		t.Errorf("statuses = %v", both.Statuses)
	}
	if got := both.QueryKeys; len(got) != 2 || got[0] != "limit" || got[1] != "offset" {
		t.Errorf("queryKeys = %v", got)
	}
	if len(both.AppIDs) != 1 || both.AppIDs[0] != "wx0123456789abcdef" {
		t.Errorf("appIds = %v", both.AppIDs)
	}
	if len(both.StaticFiles) != 1 || both.StaticFiles[0] != "pages/user/index.js" {
		t.Errorf("staticFiles = %v", both.StaticFiles)
	}

	// 尾斜杠归一：静态 /v1/order/ 与动态 /v1/order 应视为同一资产。
	if c := rowOf(t, rep, "api.example.com", "/v1/order").Category; c != CatBoth {
		t.Errorf("尾斜杠未归一: %q", c)
	}

	// 模板路径按段匹配。
	p := rowOf(t, rep, "api.example.com", "/v1/order/8871/detail")
	if p.Category != CatBoth || !p.Pattern {
		t.Errorf("模板匹配失败: cat=%q pattern=%v", p.Category, p.Pattern)
	}

	if c := rowOf(t, rep, "api.example.com", "/v1/admin/export").Category; c != CatDynamic {
		t.Errorf("仅动态分类 = %q", c)
	}
	plain := rowOf(t, rep, "api.example.com", "/v1/plain/config")
	if plain.Category != CatDynamic {
		t.Errorf("明文 HTTP 分类 = %q", plain.Category)
	}
	if !contains(plain.Notes, "明文 HTTP 传输") {
		t.Errorf("缺少明文提示: %v", plain.Notes)
	}

	never := rowOf(t, rep, "api.example.com", "/v1/coupon/never-called")
	if never.Category != CatStatic || !contains(never.Notes, "本次抓包未触发") {
		t.Errorf("仅静态分类/提示错误: %q %v", never.Category, never.Notes)
	}

	ho := rowOf(t, rep, "only-domain.example.com", "")
	if ho.Category != CatHostOnly {
		t.Errorf("域名级分类 = %q", ho.Category)
	}
	if !contains(ho.Notes, "仅记录到域名") {
		t.Errorf("域名级提示缺失: %v", ho.Notes)
	}

	sdkRow := rowOf(t, rep, "res.wx.qq.com", "/foo.js")
	if sdkRow.SDK != "微信/腾讯开放平台" {
		t.Errorf("SDK 归属丢失: %q", sdkRow.SDK)
	}

	if rep.Stats["both"] != 3 || rep.Stats["dynamicOnly"] != 2 || rep.Stats["staticOnly"] != 1 || rep.Stats["hostOnly"] != 1 {
		t.Errorf("stats = %v", rep.Stats)
	}
	if rep.FlowTotal != len(flows) || rep.AssetTotal != len(assets)+len(sdk) {
		t.Errorf("总数错误: %d/%d", rep.FlowTotal, rep.AssetTotal)
	}
	if rep.Rows == nil {
		t.Error("rows 为空")
	}
}

func TestAnalyzeHostStats(t *testing.T) {
	assets := []scanner.Asset{asset("https://api.example.com/v1/a", "x.js")}
	flows := []proxy.Flow{
		{Scheme: "https", Host: "api.example.com", Path: "/v1/a", Method: "GET", Status: 200, AppID: "wx0123456789abcdef"},
		{Scheme: "https", Host: "api.example.com", Path: "/v1/b", Method: "GET", Status: 200},
		{Scheme: "connect", Host: "sock.example.com", Method: "CONNECT"},
	}
	rep := Analyze(flows, assets, nil, "")
	if len(rep.Hosts) != 2 {
		t.Fatalf("hosts = %+v", rep.Hosts)
	}
	var api, sock *HostStat
	for i := range rep.Hosts {
		switch rep.Hosts[i].Host {
		case "api.example.com":
			api = &rep.Hosts[i]
		case "sock.example.com":
			sock = &rep.Hosts[i]
		}
	}
	if api == nil || api.DynamicCount != 2 || api.StaticCount != 1 {
		t.Errorf("api 统计错误: %+v", api)
	}
	if api == nil || len(api.AppIDs) != 1 {
		t.Errorf("api AppID 错误: %+v", api)
	}
	if sock == nil || sock.DynamicCount != 1 {
		t.Errorf("sock 统计错误: %+v", sock)
	}
	if len(rep.DynamicHosts) != 2 || len(rep.StaticHosts) != 1 {
		t.Errorf("域名清单错误: %v / %v", rep.DynamicHosts, rep.StaticHosts)
	}
}

func TestNormalizeHelpers(t *testing.T) {
	if got := normalizePath("/a/b//"); got != "/a/b" {
		t.Errorf("normalizePath = %q", got)
	}
	if got := normalizePath(""); got != "/" {
		t.Errorf("空路径应为 /, got %q", got)
	}
	if !isPatternPath("/v1/x/${id}") || isPatternPath("/v1/x/detail") {
		t.Error("isPatternPath 判定错误")
	}
	if got := patternSegs("/v1/${id}/detail"); len(got) != 3 || got[1] != "*" {
		t.Errorf("patternSegs = %v", got)
	}
	if got := queryKeys("a=1&b=&a=2&c"); len(got) != 3 || got[0] != "a" {
		t.Errorf("queryKeys = %v", got)
	}
	if h, p, ok := splitURL("https://API.Example.com/x/y/"); !ok || h != "api.example.com" || p != "/x/y" {
		t.Errorf("splitURL = %q %q %v", h, p, ok)
	}
	if _, _, ok := splitURL("/relative/path"); ok {
		t.Error("相对路径不应作为资产")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
