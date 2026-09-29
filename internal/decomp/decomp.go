package decomp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// Options 控制一次 WXML/WXSS 还原。
type Options struct {
	// OutSubdir 是产物子目录名，默认 "_decompiled"；不覆盖任何解包原始文件。
	OutSubdir string
	// Timeout 限制单个编译产物的执行时间，默认 90s。
	Timeout time.Duration
	// Progress 回调 (已完成数, 总数, 当前条目)。
	Progress func(done, total int, name string)
}

// Page 是一条还原出来的模板或样式。
type Page struct {
	Bundle string `json:"bundle"`
	Entry  string `json:"entry"`
	Path   string `json:"path"`
	Kind   string `json:"kind"` // "wxml" | "wxss"
	Bytes  int    `json:"bytes"`
}

// Result 是一次还原的汇总。
type Result struct {
	Bundles []string `json:"bundles"`
	Pages   []Page   `json:"pages"`
	Skipped []string `json:"skipped"`
	Notes   []string `json:"notes"`
}

// bundlePat 匹配承载编译产物的打平文件。
var bundlePat = regexp.MustCompile(`(?i)(page[-_]?frame|app[-_]?wxss|app[-_]?service|vue[-_]?generator).*\.(js|html)$`)

// scriptPat 提取 page-frame.html 中的内联脚本；旧版基础库把模板编译产物放在 HTML 里。
var scriptPat = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

// regPat 匹配编译产物里的模板注册语句：
//
//	__wxAppCode__['pages/x/index.wxml'] = $gwx_wxAPPID('./pages/x/index.wxml');
//
// 它同时给出输出文件名、应调用的 $gwx 工厂以及工厂入参。三者都无法从
// __WXML_GLOBAL__ 反推：注册调用传入的是临时 global，编译表不落在全局对象上。
var regPat = regexp.MustCompile(`__wxAppCode__\s*\[\s*['"]([^'"]+\.wxml)['"]\s*\]\s*=\s*(\$gwx\w*)\s*\(\s*['"]([^'"]+)['"]\s*\)`)

// templateRef 是一条模板注册记录。
type templateRef struct {
	FullKey string
	GName   string
	Rel     string
	Bundle  string
}

// DecompileDir 在已解包目录内查找编译产物并还原 WXML/WXSS。
//
// 所有编译产物按文件名顺序加载进同一个 JS 运行时：微信本来就把它们灌进同一个
// webview 上下文。$gwx 工厂与它的注册语句经常分处不同打平文件，分文件建沙箱
// 会得到 "Object has no member $gwx_xxx"。
func DecompileDir(root string, opt Options) (*Result, error) {
	if opt.OutSubdir == "" {
		opt.OutSubdir = "_decompiled"
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 90 * time.Second
	}

	bundles, err := findBundles(root, opt.OutSubdir)
	if err != nil {
		return nil, err
	}

	res := &Result{Notes: []string{
		"WXML 由执行小程序编译产物还原；wx:if/wx:for 分支按哨兵数据展开，与原始源码结构存在差异。",
		"class/style 等拼接型属性中的求值中间量无法逐字还原。",
	}}
	if len(bundles) == 0 {
		return res, nil
	}

	rt := goja.New()
	if _, err := rt.RunString(envJS); err != nil {
		return nil, fmt.Errorf("init env: %w", err)
	}

	sources := make(map[string][]byte, len(bundles))
	for i, b := range bundles {
		base := filepath.Base(b)
		src, err := bundleSource(b)
		if err != nil {
			res.Skipped = append(res.Skipped, base+": "+err.Error())
			continue
		}
		sources[b] = src
		if len(bytes.TrimSpace(src)) > 0 {
			// 编译产物可能依赖更完整的宿主 API 而中途抛错；抛错之前完成的注册仍然可用。
			stop := interruptAfter(rt, opt.Timeout)
			_, lerr := rt.RunString(string(src))
			stop()
			if lerr != nil {
				res.Skipped = append(res.Skipped, base+": 部分加载失败，仅还原抛错前的注册: "+trunc(lerr.Error(), 120))
			}
		}
		res.Bundles = append(res.Bundles, base)
		if opt.Progress != nil {
			opt.Progress(i+1, len(bundles), "加载 "+base)
		}
	}

	outRoot := filepath.Join(root, opt.OutSubdir)
	deps := templateDeps(rt)
	refs := collectRefs(sources, rt)
	for i, ref := range refs {
		path, size, err := renderAndWrite(rt, ref, outRoot, deps[ref.Rel])
		if err != nil {
			res.Skipped = append(res.Skipped, ref.FullKey+": "+trunc(err.Error(), 120))
		} else {
			res.Pages = append(res.Pages, Page{
				Bundle: filepath.Base(ref.Bundle), Entry: ref.Rel,
				Path: path, Kind: "wxml", Bytes: size,
			})
		}
		if opt.Progress != nil {
			opt.Progress(i+1, len(refs), ref.FullKey)
		}
	}

	res.Pages = append(res.Pages, writeStyles(rt, outRoot)...)
	return res, nil
}

// findBundles 列出目录内的编译产物，按路径排序以保证加载顺序稳定。
func findBundles(root, outSubdir string) ([]string, error) {
	var bundles []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == outSubdir {
				return filepath.SkipDir
			}
			return nil
		}
		if bundlePat.MatchString(info.Name()) && info.Size() < 64<<20 {
			bundles = append(bundles, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan bundles: %w", err)
	}
	sort.Strings(bundles)
	return bundles, nil
}

// bundleSource 读出可执行 JS；HTML 载体只取含 $gwx 的内联脚本，外链脚本无法离线求值。
func bundleSource(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(strings.ToLower(path), ".html") {
		return raw, nil
	}
	var buf bytes.Buffer
	for _, m := range scriptPat.FindAllSubmatch(raw, -1) {
		if bytes.Contains(m[1], []byte("$gwx")) {
			buf.Write(m[1])
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), nil
}

// syntheticNames 是插件包里的清单伪模板，没有对应的 WXML 源码。
var syntheticNames = map[string]bool{
	"plugin.wxml": true, "package.wxml": true, "package-lock.wxml": true,
}

// collectRefs 汇总所有编译产物的注册记录；同一模板被重复登记时只保留首次。
func collectRefs(sources map[string][]byte, rt *goja.Runtime) []templateRef {
	var refs []templateRef
	seen := map[string]bool{}

	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, b := range keys {
		for _, m := range regPat.FindAllStringSubmatch(string(sources[b]), -1) {
			if seen[m[1]] || syntheticNames[filepath.Base(m[1])] {
				continue
			}
			seen[m[1]] = true
			refs = append(refs, templateRef{FullKey: m[1], GName: m[2], Rel: m[3], Bundle: b})
		}
	}
	if len(refs) > 0 {
		return refs
	}

	// 注册语句被改写（个别基础库版本插入空白或换用变量名）时退回枚举 __wxAppCode__。
	names, err := gwxNames(rt)
	if err != nil || len(names) == 0 {
		return nil
	}
	fb, err := fallbackRefs(rt, names)
	if err != nil {
		return nil
	}
	return fb
}

// renderAndWrite 渲染单个模板并落盘，返回输出路径与字节数。
func renderAndWrite(rt *goja.Runtime, ref templateRef, outRoot string, deps []string) (string, int, error) {
	tree, err := render(rt, ref.GName, ref.Rel)
	if err != nil {
		return "", 0, err
	}
	wxml, err := emitWXML(tree, deps)
	if err != nil {
		return "", 0, err
	}
	dst := filepath.Join(templateOutDir(outRoot, ref.FullKey), ensureExt(sanitizeEntry(ref.FullKey), ".wxml"))
	if err := writeOut(dst, wxml); err != nil {
		return "", 0, err
	}
	return dst, len(wxml), nil
}

// writeStyles 导出编译产物中以字符串形式保存的 WXSS。
func writeStyles(rt *goja.Runtime, outRoot string) []Page {
	styles, err := listStyles(rt)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(styles))
	for k := range styles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []Page
	for _, k := range keys {
		body := styles[k]
		if strings.TrimSpace(body) == "" {
			continue
		}
		dst := filepath.Join(outRoot, ensureExt(sanitizeEntry(k), ".wxss"))
		if err := writeOut(dst, []byte(body)); err != nil {
			continue
		}
		out = append(out, Page{Entry: k, Path: dst, Kind: "wxss", Bytes: len(body)})
	}
	return out
}

// templateDeps 读出 __WXML_DEP__，并补齐带/不带 "./" 前缀两种键写法。
func templateDeps(rt *goja.Runtime) map[string][]string {
	out := map[string][]string{}
	v, err := rt.RunString(`__deps()`)
	if err != nil {
		return out
	}
	var raw map[string][]string
	if err := json.Unmarshal([]byte(v.String()), &raw); err != nil {
		return out
	}
	for k, deps := range raw {
		out[k] = deps
		if alt := strings.TrimPrefix(k, "./"); alt != k {
			out[alt] = deps
		} else {
			out["./"+k] = deps
		}
	}
	return out
}

// interruptAfter 在超时后中断 goja，防止畸形编译产物把解包任务挂死。
func interruptAfter(rt *goja.Runtime, d time.Duration) func() {
	timer := time.AfterFunc(d, func() {
		rt.Interrupt("wxsec: decompile timeout")
	})
	return func() { timer.Stop() }
}

func gwxNames(rt *goja.Runtime) ([]string, error) {
	v, err := rt.RunString(`Object.keys(globalThis).filter(function(k){return k.indexOf('$gwx')===0}).join('\n')`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(v.String(), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// fallbackRefs 在注册语句解析不出来时，用 __wxAppCode__ 的键名推断工厂入参。
func fallbackRefs(rt *goja.Runtime, names []string) ([]templateRef, error) {
	v, err := rt.RunString(`Object.keys(__wxAppCode__).filter(function(k){return /\.wxml$/.test(k)}).join('\n')`)
	if err != nil {
		return nil, err
	}
	g := names[0]
	var out []templateRef
	for _, line := range strings.Split(v.String(), "\n") {
		k := strings.TrimSpace(line)
		if k == "" {
			continue
		}
		rel := k
		if i := strings.Index(k, "//"); i > 0 && strings.Contains(k[:i], ":") {
			rel = k[i+2:] // 去掉 plugin-private://<appid>/ 前缀
		}
		if !strings.HasPrefix(rel, "./") {
			rel = "./" + rel
		}
		out = append(out, templateRef{FullKey: k, GName: g, Rel: rel})
	}
	return out, nil
}

func listStyles(rt *goja.Runtime) (map[string]string, error) {
	v, err := rt.RunString(`__styles()`)
	if err != nil {
		return nil, err
	}
	var styles map[string]string
	if err := json.Unmarshal([]byte(v.String()), &styles); err != nil {
		return nil, err
	}
	return styles, nil
}

// render 用注册语句给出的工厂与入参渲染模板；个别基础库版本对相对路径前缀
// 处理不同，因此带与不带 "./" 两种写法都试。
func render(rt *goja.Runtime, gname, rel string) (string, error) {
	candidates := []string{rel}
	if strings.HasPrefix(rel, "./") {
		candidates = append(candidates, strings.TrimPrefix(rel, "./"))
	} else {
		candidates = append(candidates, "./"+rel)
	}
	var lastErr error
	for _, c := range candidates {
		arg, err := json.Marshal(c)
		if err != nil {
			return "", err
		}
		v, err := rt.RunString(fmt.Sprintf(`__render(%q, %s, true)`, gname, string(arg)))
		if err != nil {
			lastErr = err
			continue
		}
		s := v.String()
		if s == "" || s == "null" || s == "undefined" {
			lastErr = fmt.Errorf("empty tree")
			continue
		}
		return s, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidate path rendered")
	}
	return "", lastErr
}

// templateOutDir 为插件模板保留 appid 目录，主包模板直接落在还原根目录。
func templateOutDir(outRoot, fullKey string) string {
	if i := strings.Index(fullKey, "//"); i > 0 && strings.Contains(fullKey[:i], ":") {
		return filepath.Join(outRoot, sanitizeEntry(fullKey[:i]))
	}
	return outRoot
}

// sanitizeEntry 把编译期模板路径转成安全的相对文件名。
func sanitizeEntry(rel string) string {
	s := strings.TrimSpace(filepath.ToSlash(rel))
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimPrefix(s, "/")
	if i := strings.Index(s, "//"); i >= 0 && strings.Contains(s[:i], ":") {
		// 形如 plugin-private://wxAPPID/pages/x/index.wxml
		s = s[i+2:]
	}
	s = strings.ReplaceAll(s, ":", "_")
	replacer := strings.NewReplacer(`\`, "_", "*", "_", "?", "_", `"`, "_", "<", "_", ">", "_", "|", "_")
	parts := strings.Split(s, "/")
	for i, p := range parts {
		if p == "" || p == ".." {
			parts[i] = "_"
			continue
		}
		parts[i] = replacer.Replace(p)
	}
	return filepath.Join(parts...)
}

// ensureExt 补全扩展名；编译产物里的模板键名本身已带 .wxml/.wxss。
func ensureExt(name, ext string) string {
	if strings.HasSuffix(name, ext) {
		return name
	}
	return name + ext
}

func writeOut(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
