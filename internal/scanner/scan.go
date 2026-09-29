package scanner

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Finding 是一条命中记录。
type Finding struct {
	ID         string   `json:"id"`
	RuleID     string   `json:"ruleId"`
	Category   string   `json:"category"`
	Title      string   `json:"title"`
	Severity   Severity `json:"severity"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Value      string   `json:"value"`
	Context    string   `json:"context"`
	Recommend  string   `json:"recommend"`
	Occurrence int      `json:"occurrence"`
}

// Asset 是提取出的接口资产。
type Asset struct {
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Count  int    `json:"count"`
	// SDK 非空表示该域名属于已知第三方 SDK/公共库，空表示目标自有资产。
	SDK string `json:"sdk"`
}

// Options 扫描参数。
type Options struct {
	Root string
	// MaxFileBytes 超过该大小的文件跳过（小程序包内极少有超大文本）。
	MaxFileBytes int64
	// Progress 每处理若干文件回调一次，用于 GUI 进度显示。
	Progress func(filesDone, filesTotal, findings int, current string)
}

// Result 一次扫描的完整结果。
type Result struct {
	Root         string         `json:"root"`
	StartedAt    time.Time      `json:"startedAt"`
	DurationMs   int64          `json:"durationMs"`
	FilesTotal   int            `json:"filesTotal"`
	FilesScanned int            `json:"filesScanned"`
	BytesScanned int64          `json:"bytesScanned"`
	Skipped      []string       `json:"skipped"`
	Findings     []Finding      `json:"findings"`
	Assets       []Asset        `json:"assets"`
	Hosts        []string       `json:"hosts"`
	SDKAssets    []Asset        `json:"sdkAssets"`
	SDKHosts     []string       `json:"sdkHosts"`
	AppInfo      map[string]any `json:"appInfo"`
	SevCount     map[string]int `json:"sevCount"`
}

// TextExts 参与扫描的文本文件后缀。
var TextExts = map[string]bool{
	".js": true, ".json": true, ".wxml": true, ".wxss": true,
	".html": true, ".htm": true, ".css": true, ".txt": true, ".md": true,
}

const maxLineBytes = 20000

var reAnyURL = regexp.MustCompile(`https?://[a-zA-Z0-9\-.]+(:[0-9]{2,5})?(/[^\s'"\\<>\x60,;\]]*)?`)

// Scan 遍历目录并执行内置规则集。
func Scan(opt Options) (*Result, error) {
	if opt.MaxFileBytes <= 0 {
		opt.MaxFileBytes = 8 << 20
	}
	rules := Rules()
	res := &Result{Root: opt.Root, StartedAt: time.Now(), Skipped: []string{}}
	seen := map[string]*Finding{}
	assets := map[string]*Asset{}

	var files []string
	err := filepath.WalkDir(opt.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", opt.Root, err)
	}
	res.FilesTotal = len(files)

	done := 0
	for _, p := range files {
		done++
		rel, err := filepath.Rel(opt.Root, p)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)

		if !TextExts[strings.ToLower(filepath.Ext(p))] {
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			res.Skipped = append(res.Skipped, rel+"（无法读取）")
			continue
		}
		if st.Size() > opt.MaxFileBytes {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s（%d 字节，超过上限）", rel, st.Size()))
			continue
		}
		if scanFile(p, rel, rules, res, seen, assets) {
			res.FilesScanned++
		}
		if opt.Progress != nil && done%25 == 0 {
			opt.Progress(done, len(files), len(seen), rel)
		}
	}
	if opt.Progress != nil {
		opt.Progress(len(files), len(files), len(seen), "")
	}

	res.AppInfo = collectAppInfo(opt.Root)
	res.Findings = flattenFindings(seen)
	res.Assets, res.SDKAssets = splitSDKAssets(flattenAssets(assets))
	res.Hosts = uniqueHosts(res.Assets)
	res.SDKHosts = uniqueHosts(res.SDKAssets)
	res.SevCount = countSeverity(res.Findings)
	res.DurationMs = time.Since(res.StartedAt).Milliseconds()
	sortFindings(res.Findings)
	return res, nil
}

// scanFile 返回该文件是否作为文本被扫描。
func scanFile(path, rel string, rules []Rule, res *Result, seen map[string]*Finding, assets map[string]*Asset) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	br := bufio.NewReader(f)
	if head, _ := br.Peek(512); strings.IndexByte(string(head), 0) >= 0 || !utf8.Valid(head) {
		return false // 二进制资源（图片/字体/音效）不参与文本扫描
	}

	lineNo := 0
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes*2)
	for sc.Scan() {
		line := sc.Text()
		lineNo++
		if len(line) > maxLineBytes {
			line = line[:maxLineBytes]
		}

		for _, r := range rules {
			if !extIn(r.Exts, strings.ToLower(filepath.Ext(rel))) {
				continue
			}
			locs := r.Pattern.FindAllStringIndex(line, -1)
			if len(locs) == 0 {
				continue
			}
			if r.MaxPerFile > 0 && len(locs) > r.MaxPerFile {
				locs = locs[:r.MaxPerFile]
			}
			for _, loc := range locs {
				if r.RejectVersionAt && isVersionAt(line, loc[0], loc[1]) {
					continue
				}
				if r.NeedsHostContext && !hasHostContext(line, loc[0], loc[1]) {
					continue
				}
				value := valueOf(line, loc, r)
				if r.LineFilter != nil && !r.LineFilter(line, value) {
					continue
				}
				shown := value
				if r.Mask {
					shown = MaskSecret(value)
				}
				key := r.ID + "|" + rel + "|" + shown
				if old, ok := seen[key]; ok {
					old.Occurrence++
					continue
				}
				seen[key] = &Finding{
					ID:        shortID(r.ID, rel, fmt.Sprintf(":%d", lineNo), value),
					RuleID:    r.ID,
					Category:  r.Category,
					Title:     r.Title,
					Severity:  r.Severity,
					File:      rel,
					Line:      lineNo,
					Value:     truncate(shown, 200),
					Context:   truncate(strings.TrimSpace(line), 300),
					Recommend: r.Recommend,
				}
			}
		}

		for _, u := range reAnyURL.FindAllString(line, -1) {
			addAsset(assets, rel, lineNo, u)
		}
	}
	return true
}

// valueOf 取出用于展示的捕获组内容，避免把整行噪声写进报告。
func valueOf(line string, loc []int, r Rule) string {
	full := line[loc[0]:loc[1]]
	if r.ValueGroup <= 0 {
		return full
	}
	subs := r.Pattern.FindStringSubmatch(line)
	if subs == nil || r.ValueGroup >= len(subs) || subs[r.ValueGroup] == "" {
		return full
	}
	return subs[r.ValueGroup]
}

func addAsset(assets map[string]*Asset, rel string, line int, url string) {
	url = strings.TrimRight(url, "'\",;)}]")
	scheme := "http"
	if strings.HasPrefix(url, "https") {
		scheme = "https"
	}
	rest := url
	if i := strings.Index(url, "://"); i >= 0 {
		rest = url[i+3:]
	}
	host, path := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	key := scheme + "://" + host + path
	if a, ok := assets[key]; ok {
		a.Count++
		return
	}
	assets[key] = &Asset{URL: key, Scheme: scheme, Host: host, Path: path, File: rel, Line: line, Count: 1, SDK: classifySDK(host)}
}

// collectAppInfo 抽取 app.json / project.config.json 中与权限面相关的配置。
func collectAppInfo(root string) map[string]any {
	info := map[string]any{}
	read := func(name string) map[string]any {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil
		}
		m := map[string]any{}
		if json.Unmarshal(stripJSON(b), &m) != nil {
			return nil
		}
		return m
	}

	if app := read("app.json"); app != nil {
		if v, ok := app["pages"].([]any); ok {
			info["页面数量"] = len(v)
		}
		if v, ok := app["subPackages"].([]any); ok {
			info["分包数量"] = len(v)
		}
		for _, k := range []string{"plugins", "permission", "requiredPrivateInfos", "embeddedAppIdList",
			"navigateToMiniProgramAppIdList", "debug", "miniProgram", "useExtendedLib"} {
			if v, ok := app[k]; ok {
				info[k] = v
			}
		}
	}
	if proj := read("project.config.json"); proj != nil {
		if v, ok := proj["appid"]; ok {
			info["appid"] = v
		}
		if v, ok := proj["projectname"]; ok {
			info["projectname"] = v
		}
		if v, ok := proj["setting"].(map[string]any); ok {
			info["urlCheck"] = v["urlCheck"]
		}
	}
	if cfg := read("config.json"); cfg != nil {
		if v, ok := cfg["permission"]; ok {
			info["permission"] = v
		}
		if v, ok := cfg["plugins"]; ok {
			info["plugins"] = v
		}
	}
	return info
}

// stripJSON 去掉小程序配置里可能存在的 BOM。
func stripJSON(b []byte) []byte {
	return []byte(strings.TrimPrefix(string(b), "\ufeff"))
}

func flattenFindings(m map[string]*Finding) []Finding {
	out := make([]Finding, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	return out
}

// splitSDKAssets 把第三方 SDK/公共库自带域名与目标自有接口分开，
// 前者不再进入资产面与域名清单，但仍保留下来供报告与人工复核。
func splitSDKAssets(all []Asset) (target, sdk []Asset) {
	target = []Asset{}
	sdk = []Asset{}
	for _, a := range all {
		if a.SDK == "" {
			target = append(target, a)
		} else {
			sdk = append(sdk, a)
		}
	}
	return target, sdk
}

func flattenAssets(m map[string]*Asset) []Asset {	out := make([]Asset, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].URL < out[j].URL
	})
	return out
}

func uniqueHosts(assets []Asset) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range assets {
		if !seen[a.Host] {
			seen[a.Host] = true
			out = append(out, a.Host)
		}
	}
	sort.Strings(out)
	return out
}

func countSeverity(fs []Finding) map[string]int {
	m := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range fs {
		m[string(f.Severity)]++
	}
	return m
}

var sevOrder = map[Severity]int{SevHigh: 0, SevMedium: 1, SevLow: 2, SevInfo: 3}

func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if sevOrder[fs[i].Severity] != sevOrder[fs[j].Severity] {
			return sevOrder[fs[i].Severity] < sevOrder[fs[j].Severity]
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// MaskSecret 保留首尾少量字符，中间以星号替代，避免报告本身成为泄露渠道。
func MaskSecret(s string) string {
	r := []rune(s)
	switch {
	case len(r) <= 3:
		return strings.Repeat("*", len(r))
	case len(r) <= 8:
		return string(r[:2]) + "****"
	default:
		return string(r[:4]) + "******" + string(r[len(r)-2:])
	}
}

// isVersionAt 判断命中前后是否连着 ".数字"，用于排除版本号写法。
func isVersionAt(line string, start, end int) bool {
	if end+1 < len(line) && line[end] == '.' && line[end+1] >= '0' && line[end+1] <= '9' {
		return true
	}
	if start >= 2 && line[start-1] == '.' && line[start-2] >= '0' && line[start-2] <= '9' {
		return true
	}
	return false
}

// hasHostContext 判断 IP 命中是否处于 URL/端点上下文，避免把版本号报成 IP。
func hasHostContext(line string, start, end int) bool {
	lo := start - 12
	if lo < 0 {
		lo = 0
	}
	before := line[lo:start]
	if strings.Contains(before, "://") || strings.HasSuffix(before, "//") || strings.HasSuffix(before, "@") {
		return true
	}
	if end < len(line) {
		switch line[end] {
		case ':', '/':
			return true
		}
	}
	return false
}

// ValidIDCard 校验 18 位身份证号（GB 11643 校验位算法）。
func ValidIDCard(s string) bool {
	if len(s) != 18 {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := 0; i < 17; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		sum += int(s[i]-'0') * weights[i]
	}
	return "10X98765432"[sum%11] == byte(strings.ToUpper(s)[17])
}

// Luhn 校验卡号。
func Luhn(digits string) bool {
	var sum, alt int
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if alt == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt ^= 1
	}
	return sum%10 == 0
}

// shortID 为命中生成稳定 ID，供 GUI 定位与去重使用。
func shortID(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:12]
}
