package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifySDK(t *testing.T) {
	cases := []struct{ host, want string }{
		{"res.wx.qq.com", "微信/腾讯开放平台"},
		{"WWW.QQ.COM", "微信/腾讯开放平台"},
		{"mmbiz.qpic.cn", "微信/腾讯开放平台"},
		{"wx.tenpay.com", "微信/腾讯开放平台"},
		{"tongji.baidu.com:443", "百度统计/百度地图"},
		{"cdn.jsdelivr.net", "公共前端 CDN"},
		{"cdnjs.cloudflare.com", "公共前端 CDN"},
		{"www.w3.org", "规范与元数据命名空间"},
		{"github.com", "开源仓库与许可证注释"},
		{"api.example-target.com", ""},
		// 形似厂商域名但不受厂商控制，不能误杀
		{"evil-qq.com", ""},
		{"qq.com.evil-target.com", ""},
		{"api.weixin-support.net", ""},
		// 自建存储桶属于目标资产，不在过滤表里
		{"shop-data.cos.ap-guangzhou.myqcloud.com", ""},
		{"shop-oss.oss-cn-hangzhou.aliyuncs.com", ""},
	}
	for _, c := range cases {
		if got := classifySDK(c.host); got != c.want {
			t.Errorf("classifySDK(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// 第三方 SDK 自带域名不计入目标资产面，但需要保留供人工复核。
func TestSDKAssetsSeparatedFromTarget(t *testing.T) {
	root := t.TempDir()
	content := `
wx.request({ url: "https://api.example-target.com/v1/order" });
wx.request({ url: "https://shop-data.cos.ap-guangzhou.myqcloud.com/upload" });
var SDK = "https://res.wx.qq.com/open/js/jweixin-1.6.0.js";
var LIB = "https://cdn.jsdelivr.net/npm/dayjs/dayjs.min.js";
var DOC = "https://www.w3.org/2000/svg";
`
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}

	wantTarget := []string{
		"https://api.example-target.com/v1/order",
		"https://shop-data.cos.ap-guangzhou.myqcloud.com/upload",
	}
	if got := urlSet(res.Assets); !containsAll(got, wantTarget) {
		t.Errorf("target assets = %v, want %v", keys(got), wantTarget)
	}
	wantSDK := []string{
		"https://res.wx.qq.com/open/js/jweixin-1.6.0.js",
		"https://cdn.jsdelivr.net/npm/dayjs/dayjs.min.js",
		"https://www.w3.org/2000/svg",
	}
	if got := urlSet(res.SDKAssets); !containsAll(got, wantSDK) {
		t.Errorf("sdk assets = %v, want %v", keys(got), wantSDK)
	}
	for _, h := range []string{"res.wx.qq.com", "cdn.jsdelivr.net", "www.w3.org"} {
		if contains(res.Hosts, h) {
			t.Errorf("host %s should not be in target hosts: %v", h, res.Hosts)
		}
	}
	if !contains(res.SDKHosts, "res.wx.qq.com") {
		t.Errorf("sdk hosts = %v", res.SDKHosts)
	}
	for _, a := range res.SDKAssets {
		if a.SDK == "" {
			t.Errorf("sdk asset %s has no vendor tag", a.URL)
		}
	}
}

func urlSet(as []Asset) map[string]bool {
	m := map[string]bool{}
	for _, a := range as {
		m[a.URL] = true
	}
	return m
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func containsAll(m map[string]bool, want []string) bool {
	for _, w := range want {
		if !m[w] {
			return false
		}
	}
	return true
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
