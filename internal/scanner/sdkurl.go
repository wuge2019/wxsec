package scanner

import "strings"

// SDKDomain 是一类第三方 SDK／公共库／规范站点自带的固定域名。
// 这些域名归厂商所有，不属于被测小程序的资产面，默认从接口资产里分离出去。
type SDKDomain struct {
	// Name 是厂商或库的展示名。
	Name string `json:"name"`
	// Domains 匹配规则：host 等于该域名，或是它的子域名。
	Domains []string `json:"domains"`
}

// SDKDomains 是已知第三方域名表。
//
// 刻意不收录「租户自有」的域名后缀（如 myqcloud.com、aliyuncs.com、obs、cos 桶域名）：
// 同一后缀既可能是厂商服务，也可能是目标自己开的存储桶/接口，过滤会误杀真实资产。
// 新增条目前请确认该域名只能由厂商控制。
var SDKDomains = []SDKDomain{
	{"微信/腾讯开放平台", []string{
		"qq.com", "weixin.com", "wechat.com", "tencent.com", "tenpay.com",
		"qlogo.cn", "qpic.cn", "gtimg.cn", "gtimg.com",
		"url.cn", "wxaurl.cn", "mmbizurl.cn",
	}},
	{"支付宝/阿里系", []string{
		"alipay.com", "alipayobjects.com", "alicdn.com", "mmstat.com", "tb.cn",
	}},
	{"百度统计/百度地图", []string{"baidu.com", "baidustatic.com"}},
	{"高德地图", []string{"amap.com"}},
	{"友盟统计", []string{"umeng.com", "umengcloud.com", "umsns.com", "uweb.cn"}},
	{"极光推送", []string{"jpush.cn", "jiguang.cn"}},
	{"个推", []string{"getui.com", "getui.net"}},
	{"神策分析", []string{"sensorsdata.cn", "sensorsdata.com"}},
	{"TalkingData", []string{"talkingdata.com", "talkingdata.net"}},
	{"GrowingIO", []string{"growingio.com"}},
	{"字节/巨量统计", []string{"snssdk.com", "bytedance.com", "oceanengine.com"}},
	{"Google 统计/字体", []string{"google-analytics.com", "googletagmanager.com", "googleapis.com", "gstatic.com"}},
	{"uni-app/DCloud", []string{"dcloud.net.cn", "dcloudimg.com"}},
	{"公共前端 CDN", []string{
		"jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "bootstrapcdn.com",
		"jquery.com", "polyfill.io", "momentjs.com", "lodash.com",
	}},
	{"开源仓库与许可证注释", []string{"github.com", "gitlab.com", "bitbucket.org", "gitee.com", "sourceforge.net"}},
	{"规范与元数据命名空间", []string{
		"w3.org", "json-schema.org", "purl.org", "adobe.com", "iptc.org", "prismstandard.org",
	}},
}

// classifySDK 返回 host 所属的第三方厂商名；目标自有域名或未知厂商返回空串。
// host 可能带端口（reAnyURL 会保留 :port），匹配前先剥离。
func classifySDK(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	for _, g := range SDKDomains {
		for _, d := range g.Domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return g.Name
			}
		}
	}
	return ""
}
