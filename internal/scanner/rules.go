// Package scanner 对解包后的小程序源码目录做静态安全扫描。
package scanner

import (
	"regexp"
)

// Severity 风险等级。
type Severity string

const (
	SevHigh   Severity = "high"
	SevMedium Severity = "medium"
	SevLow    Severity = "low"
	SevInfo   Severity = "info"
)

// 分类常量
const (
	CatSecrets   = "硬编码密钥"
	CatPII       = "敏感个人信息"
	CatNetwork   = "接口与资产"
	CatDangerous = "危险用法与配置"
)

// Rule 是一条静态检测规则。
type Rule struct {
	ID       string
	Category string
	Title    string
	Severity Severity
	Pattern  *regexp.Regexp

	// Exts 限定参与匹配的文件后缀；为空表示所有文本文件。
	Exts []string
	// ValueGroup 指定报告中展示的捕获组序号（0 表示整段命中）。
	ValueGroup int
	// RejectVersionAt 过滤 "1.2.3.4.5" 这类版本号写法造成的误报。
	RejectVersionAt bool
	// NeedsHostContext 要求命中出现在 URL/端点上下文中（前面有 :// 或后面跟 :port 或 /path），
	// 用于区分 "1.0.23.4" 这类四段版本号与真正的 IP 端点。
	NeedsHostContext bool
	// LineFilter 对命中做二次判定，返回 false 则丢弃。
	LineFilter func(line, value string) bool
	// Mask 为 true 时命中值以脱敏形式呈现（避免报告本身成为泄露源）。
	Mask        bool
	Recommend   string
	MaxPerFile  int
}

// codeExts 小程序中常见的代码/配置载体。
var codeExts = []string{".js", ".json", ".wxml", ".wxss", ".html", ".css", ".txt", ".md"}

func extIn(exts []string, ext string) bool {
	if len(exts) == 0 {
		return true
	}
	for _, e := range exts {
		if e == ext {
			return true
		}
	}
	return false
}

// Rules 返回内置规则集。正则均为 RE2 兼容写法（无回溯型构造，天然免疫 ReDoS）。
func Rules() []Rule {
	return []Rule{
		// ── 硬编码密钥 ──────────────────────────────────────────
		{
			ID: "KEY-001", Category: CatSecrets, Title: "硬编码 AppSecret / SecretKey",
			Severity: SevHigh, ValueGroup: 2, Mask: true, MaxPerFile: 20, Exts: codeExts,
			Pattern:   regexp.MustCompile(`(?i)(appsecret|app_secret|secretkey|secret_key|appkey|app_key)\s*[:=]\s*['"]([0-9a-zA-Z_\-.]{8,})['"]`),
			Recommend: "小程序 AppSecret 只能存在于服务端；出现在前端包内等同于泄露，应立即轮换并改为服务端换取会话凭证。",
		},
		{
			ID: "KEY-002", Category: CatSecrets, Title: "硬编码 apikey / token / password",
			Severity: SevHigh, ValueGroup: 2, Mask: true, MaxPerFile: 30, Exts: codeExts,
			Pattern:   regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|access[_-]?key|accesskeyid|auth[_-]?token|access[_-]?token|password|passwd)\b["']?\s*[:=]\s*['"]([^'"\s]{6,})['"]`),
			Recommend: "任何长期凭据都不应随包分发；改为服务端下发短期令牌并吊销已泄露凭据。",
		},
		{
			ID: "KEY-003", Category: CatSecrets, Title: "阿里云 AccessKey ID",
			Severity: SevHigh, Mask: true, MaxPerFile: 10,
			Pattern:   regexp.MustCompile(`LTAI[A-Za-z0-9]{12,22}`),
			Recommend: "云 AK 泄露可直接导致 OSS/短信/计算资源被滥用；轮换并改用 STS 临时凭证。",
		},
		{
			ID: "KEY-004", Category: CatSecrets, Title: "AWS AccessKey ID",
			Severity: SevHigh, Mask: true, MaxPerFile: 10,
			Pattern:   regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Recommend: "轮换密钥，使用 IAM Role / Cognito 临时凭证。",
		},
		{
			ID: "KEY-005", Category: CatSecrets, Title: "JWT 令牌",
			Severity: SevMedium, Mask: true, MaxPerFile: 10,
			Pattern:   regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}`),
			Recommend: "包内 JWT 可用于离线重放与用户信息解码；确认有效期并考虑吊销。",
		},
		{
			ID: "KEY-006", Category: CatSecrets, Title: "私钥内容",
			Severity: SevHigh, MaxPerFile: 3,
			Pattern:   regexp.MustCompile(`-----BEGIN [A-Z ]{0,12}PRIVATE KEY-----`),
			Recommend: "私钥必须移出小程序包并撤销对应证书。",
		},
		{
			ID: "KEY-007", Category: CatSecrets, Title: "商户号 / 对称加密密钥",
			Severity: SevMedium, ValueGroup: 2, Mask: true, MaxPerFile: 15, Exts: codeExts,
			Pattern:   regexp.MustCompile(`(?i)\b(mch_?id|sub_?mch_?id|aeskey|aes_key|des_?key|encrypt_?key|sign_?key)\b\s*[:=]\s*['"]?([0-9a-zA-Z]{12,44})['"]?`),
			Recommend: "微信支付 APIv3 密钥/商户签名密钥泄露会导致回调解密与伪造风险，必须仅存服务端。",
		},

		// ── 敏感个人信息 ────────────────────────────────────────
		{
			ID: "PII-001", Category: CatPII, Title: "疑似手机号",
			Severity: SevLow, ValueGroup: 1, Mask: true, MaxPerFile: 40,
			Pattern:    regexp.MustCompile(`(^|[^0-9a-zA-Z])(1[3-9][0-9]{9})([^0-9]|$)`),
			LineFilter: func(line, value string) bool { return !allDigits13(value) },
			Recommend:  "确认是否为真实手机号（订单号/时间戳常见误报）；测试数据请清除。",
		},
		{
			ID: "PII-002", Category: CatPII, Title: "身份证号（校验位通过）",
			Severity: SevHigh, ValueGroup: 1, Mask: true, MaxPerFile: 20,
			Pattern:    regexp.MustCompile(`[^0-9Xx]([1-8][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx])[^0-9Xx]`),
			LineFilter: func(line, value string) bool { return ValidIDCard(value) },
			Recommend:  "属于个人敏感信息，出现在前端包内即为数据泄露，需定位来源并清除。",
		},
		{
			ID: "PII-003", Category: CatPII, Title: "银行卡号（Luhn 校验通过）",
			Severity: SevHigh, ValueGroup: 1, Mask: true, MaxPerFile: 20,
			Pattern:    regexp.MustCompile(`[^0-9]([0-9]{16,19})[^0-9]`),
			LineFilter: func(line, value string) bool { return Luhn(value) },
			Recommend:  "确认卡号来源，测试卡必须清除。",
		},
		{
			ID: "PII-004", Category: CatPII, Title: "邮箱地址",
			Severity: SevInfo, MaxPerFile: 40,
			Pattern:   regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
			Recommend: "内部邮箱可作为社工与账号枚举线索，确认是否有必要保留在包内。",
		},

		// ── 接口与网络资产 ──────────────────────────────────────
		{
			ID: "NET-001", Category: CatNetwork, Title: "明文 HTTP 接口",
			Severity: SevMedium, MaxPerFile: 60,
			Pattern:    regexp.MustCompile(`http://[a-zA-Z0-9\-.]+(:[0-9]{2,5})?(/[^\s'"\\<>\x60,;]*)?`),
			LineFilter: func(line, value string) bool { return !isLocalHost(value) },
			Recommend:  "微信要求业务域名必须 HTTPS；明文 HTTP 请求可被中间人窃听与篡改。",
		},
		{
			ID: "NET-002", Category: CatNetwork, Title: "硬编码 IP 端点",
			Severity: SevMedium, ValueGroup: 1, RejectVersionAt: true, NeedsHostContext: true, MaxPerFile: 40,
			Pattern:    regexp.MustCompile(`[^0-9]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]{2,5})?`),
			LineFilter: func(line, value string) bool { return !isLoopback(value) && isRealIP(value) },
			Recommend:  "硬编码 IP 便于资产关联且绕过了域名白名单管控，应改为配置下发。",
		},
		{
			ID: "NET-003", Category: CatNetwork, Title: "内网 / 保留地址",
			Severity: SevHigh, ValueGroup: 1, NeedsHostContext: true, MaxPerFile: 20,
			Pattern:   regexp.MustCompile(`[^0-9]((10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(192\.168\.[0-9]{1,3}\.[0-9]{1,3})|(172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}))(:[0-9]{2,5})?`),
			Recommend: "内网地址暴露内部拓扑，若为可达管理端则属于严重问题，需重点验证。",
		},
		{
			ID: "NET-004", Category: CatNetwork, Title: "隧道 / 临时回调域名",
			Severity: SevHigh, MaxPerFile: 20,
			Pattern: regexp.MustCompile(`(?i)\b(ngrok\.(io|app)|serveo\.net|localtest\.me|requestbin\.[a-z.]+|pipedream\.xyz|webhook\.(site|tools)|burpcollaborator\.net|interact\.sh|dnslog\.cn|ceye\.io|oast\.[a-z]+)\b`),
			Recommend: "调试隧道属于遗留后门，可能把线上数据转发到第三方，需确认并移除。",
		},

		// ── 危险用法与不安全配置 ────────────────────────────────
		{
			ID: "DGR-001", Category: CatDangerous, Title: "动态代码执行",
			Severity: SevMedium, MaxPerFile: 20, Exts: []string{".js"},
			Pattern:   regexp.MustCompile(`\bnew\s+Function\s*\(|\beval\s*\(`),
			Recommend: "若执行内容受接口影响即为代码注入面；确认输入来源。",
		},
		{
			ID: "DGR-002", Category: CatDangerous, Title: "web-view 加载页面",
			Severity: SevInfo, MaxPerFile: 20, Exts: []string{".wxml", ".html", ".js"},
			Pattern:   regexp.MustCompile(`<web-view[^>]*\bsrc\s*=|\bwebview-?(url|src)\b`),
			Recommend: "webview 地址若可被参数控制，需校验业务域名白名单，否则存在跳转钓鱼与登录态泄露。",
		},
		{
			ID: "DGR-003", Category: CatDangerous, Title: "重定向类参数",
			Severity: SevLow, MaxPerFile: 40, Exts: codeExts,
			Pattern:   regexp.MustCompile(`(?i)\b(redirect_?url|back_?url|target_?url|return_?url|jump_?url|continue_?url|goto)\s*[:=]`),
			Recommend: "手工验证该参数是否来自 scene/query 且未经白名单校验（开放重定向）。",
		},
		{
			ID: "DGR-004", Category: CatDangerous, Title: "本地存储/日志中的身份数据",
			Severity: SevInfo, MaxPerFile: 30, Exts: []string{".js"},
			Pattern:   regexp.MustCompile(`(?i)(setStorageSync|getStorageSync|console\.[a-z]+)\s*\(\s*['"][^'"]{0,40}(token|openid|unionid|sessionkey|session_key|phone|mobile|idcard|password)`),
			Recommend: "本地明文存储身份凭据可被同设备其他途径读取，建议收敛存储内容。",
		},
		{
			ID: "DGR-005", Category: CatDangerous, Title: "调试开关 / 测试环境残留",
			Severity: SevMedium, ValueGroup: 2, MaxPerFile: 20, Exts: codeExts,
			Pattern:    regexp.MustCompile(`(?i)\b(is_?debug|debug_?mode|isdev|test_?env|dev_?url|uat_?url|mock_?url)\b\s*[:=]\s*(true|['"]([^'"]{2,})['"])`),
			LineFilter: func(line, value string) bool { return value != "" },
			Recommend:  "线上包残留调试开关可能绕过校验或指向测试后端，需确认发布配置。",
		},
	}
}

var re13Digits = regexp.MustCompile(`^[0-9]{13}$`)

func allDigits13(s string) bool { return re13Digits.MatchString(s) }

var reLoopback = regexp.MustCompile(`^(127\.|0\.0\.0\.0$|localhost$|\[::1\]$|::1$)`)

func isLoopback(s string) bool { return reLoopback.MatchString(s) }

var reLocalURL = regexp.MustCompile(`^http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`)

func isLocalHost(s string) bool { return reLocalURL.MatchString(s) }

var reOctet = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$`)

// isRealIP 排除每段 >255 的伪 IP（如长版本号）。
func isRealIP(s string) bool {
	m := reOctet.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	for _, seg := range m[1:] {
		if len(seg) > 1 && seg[0] == '0' {
			return false
		}
		if segToInt(seg) > 255 {
			return false
		}
	}
	return true
}

func segToInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
