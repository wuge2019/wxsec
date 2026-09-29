package wxapkg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// 新版小程序包会把所有页面代码打平成少数 bundle 文件（app-service.js 等）。
// 本文件做「无 JS 虚拟机」的静态还原：
//   - define("pages/x/x.js", function(){...}, {isPage:true}) 模块拆分
//   - __wxAppCode__['pages/x/x.json'] = {...} 页面配置提取
//   - app-config.json 的 pages/page 映射 → 补齐页面 .json
//   - 分包/插件等 bundle 保留原文件并在结果中注明
// WXML/WXSS 的完整反编译需要执行编译产物（VM 路线），此处保留 bundle 原文。

// PackageType 描述解包产物的形态。
type PackageType string

const (
	TypeLegacy      PackageType = "legacy"     // 老格式：包内即独立文件，无需还原
	TypeFlattened   PackageType = "flattened"  // 打平 bundle：app-service.js + app-wxss.js + page-frame.*
	TypeSubpackage  PackageType = "subpackage" // 分包/插件等仅有部分 bundle 的形态
)

const (
	bundleAppService = "app-service.js"
	bundleAppWxss    = "app-wxss.js"
	bundlePageFrame  = "page-frame.html"
	bundleCommonApp  = "common.app.js"
	bundleAppConfig  = "app-config.json"
	bundleAppConfigS = "app-config-service.js"
)

// RestoreResult 是一次还原的汇总。
type RestoreResult struct {
	Type    PackageType `json:"type"`
	Written []string    `json:"written"`
	Notes   []string    `json:"notes"`
}

// DetectType 按 bundle 文件集合判定包形态。
func DetectType(dir string) PackageType {
	has := func(names ...string) bool {
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
				return false
			}
		}
		return true
	}
	switch {
	case has(bundlePageFrame, bundleCommonApp), has(bundleCommonApp, bundleAppWxss), has(bundlePageFrame, bundleAppWxss):
		return TypeFlattened
	case has(bundleAppService), has(bundlePageFrame), has(bundleCommonApp), has(bundleAppConfigS):
		return TypeSubpackage
	default:
		return TypeLegacy
	}
}

var (
	// define("pages/index/index.js", function(a,b){ ... }, {..., isPage: true, ...});
	reDefineBlock = regexp.MustCompile(`(?s)define\s*\(\s*["']([^"']+)["']\s*,\s*function\s*\(([^)]*)\)\s*\{`)
	// __wxAppCode__['pages/index/index.json'] = {…}; 值可能嵌套，用括号配对截取
	reAppCodeJSON = regexp.MustCompile(`__wxAppCode__\[['"]([^'"]+\.json)['"]\]\s*=\s*\{`)
	reWxPageMap   = regexp.MustCompile(`(?s)"page"\s*:\s*(\{.*?\})\s*,?\s*"`)
)

// Restore 对解包目录执行静态工程还原。
func Restore(dir string) (*RestoreResult, error) {
	res := &RestoreResult{Type: DetectType(dir), Written: []string{}, Notes: []string{}}
	if res.Type == TypeLegacy {
		res.Notes = append(res.Notes, "包内已是独立文件结构，无需还原")
		return res, nil
	}

	for _, bundle := range []string{bundleAppService, bundleCommonApp} {
		p := filepath.Join(dir, bundle)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		n, err := extractDefines(string(data), dir)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s 模块拆分失败：%v", bundle, err))
		}
		res.Written = append(res.Written, n...)

		m, err := extractAppCodeJSON(string(data), dir)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s 页面配置提取失败：%v", bundle, err))
		}
		res.Written = append(res.Written, m...)
	}

	// app-config.json（新版）里带完整 pages 列表与每页 window 配置
	if data, err := os.ReadFile(filepath.Join(dir, bundleAppConfig)); err == nil {
		n, err := restoreFromAppConfig(data, dir)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("app-config.json 解析失败：%v", err))
		}
		res.Written = append(res.Written, n...)
	}

	res.Notes = append(res.Notes,
		"WXML/WXSS 需执行包内编译产物才能完整还原（本版本保留在 app-wxss.js / page-frame.* 中）",
		"还原后的目录可直接用微信开发者工具打开做动态验证")
	return res, nil
}

// extractDefines 按括号配对切出每个 define() 的函数体，还原为独立 JS 文件。
func extractDefines(src, dir string) ([]string, error) {
	var written []string
	for _, loc := range reDefineBlock.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		bodyStart := loc[1] // "function(...){" 之后
		end, ok := matchBrace(src, bodyStart-1)
		if !ok {
			continue
		}
		body := strings.TrimSpace(src[bodyStart:end])
		body = strings.TrimPrefix(body, `"use strict";`)
		body = strings.TrimPrefix(body, "'use strict';")
		// define 回调体内多带一层基础库注入缩进，去掉统一的 4 空格
		body = dedent(body)

		rel := strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(rel, ".js") {
			rel += ".js"
		}
		rel = sanitizeRelPath(rel)
		if rel == "" {
			continue
		}
		out := filepath.Join(dir, filepath.FromSlash(rel))
		if !within(out, dir) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return written, err
		}
		content := "// 由 wxsec 从 " + bundleAppService + " 静态还原，模块名: " + name + "\n" + body + "\n"
		if err := os.WriteFile(out, []byte(content), 0o644); err != nil {
			return written, err
		}
		written = append(written, rel)
	}
	return written, nil
}

func extractAppCodeJSON(src, dir string) ([]string, error) {
	var written []string
	for _, loc := range reAppCodeJSON.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		rel := sanitizeRelPath(strings.TrimPrefix(name, "/"))
		if rel == "" {
			continue
		}
		open := loc[1] - 1
		end, ok := matchBrace(src, open)
		if !ok {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(normalizeJSObject(src[open:end+1])), &v); err != nil {
			continue
		}
		pretty, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			continue
		}
		out := filepath.Join(dir, filepath.FromSlash(rel))
		if !within(out, dir) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return written, err
		}
		if err := os.WriteFile(out, pretty, 0o644); err != nil {
			return written, err
		}
		written = append(written, rel)
	}
	return written, nil
}

// restoreFromAppConfig 用 app-config.json 的 pages/page 映射补齐缺失的页面 .json。
func restoreFromAppConfig(data []byte, dir string) ([]string, error) {
	var root any
	trimmed := strings.TrimPrefix(string(data), "\ufeff")
	if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
		return nil, err
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected app-config.json shape")
	}

	var pages []string
	if ps, ok := m["pages"].([]any); ok {
		for _, p := range ps {
			if s, ok := p.(string); ok {
				pages = append(pages, s)
			}
		}
	}
	if subs, ok := m["subPackages"].([]any); ok {
		for _, s := range subs {
			sm, ok := s.(map[string]any)
			if !ok {
				continue
			}
			rootPrefix, _ := sm["root"].(string)
			if sps, ok := sm["pages"].([]any); ok {
				for _, p := range sps {
					if str, ok := p.(string); ok {
						pages = append(pages, rootPrefix+"/"+str)
					}
				}
			}
		}
	}

	var written []string
	pageCfg, _ := m["page"].(map[string]any)
	for _, page := range pages {
		jsonPath := filepath.Join(dir, filepath.FromSlash(page)+".json")
		if _, err := os.Stat(jsonPath); err == nil {
			continue // 已有真实配置则不覆盖
		}
		rel := sanitizeRelPath(page)
		if rel == "" {
			continue
		}
		out := filepath.Join(dir, filepath.FromSlash(rel)+".json")
		if !within(out, dir) {
			continue
		}
		cfg := map[string]any{}
		// app-config 的 page 映射 key 形如 "pages/index/index.wxss" 或 ".html"，取同前缀项
		for k, v := range pageCfg {
			base := strings.TrimSuffix(strings.TrimPrefix(k, "/"), ".wxss")
			base = strings.TrimSuffix(base, ".html")
			if base == page {
				if vm, ok := v.(map[string]any); ok {
					cfg = vm
				}
			}
		}
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return written, err
		}
		if err := os.WriteFile(out, b, 0o644); err != nil {
			return written, err
		}
		written = append(written, rel+".json")
	}

	// 同时把 app-config.json 本体转成 app.json，便于开发者工具识别
	if app, err := os.OpenFile(filepath.Join(dir, "app.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err == nil {
		slim := map[string]any{}
		for k, v := range m {
			switch k {
			case "global", "tabBar", "pages", "subPackages", "window", "permission", "requiredPrivateInfos", "plugins", "entryPagePath", "usingComponents", "debug":
				slim[k] = v
			}
		}
		if k, ok := m["global"].(map[string]any); ok {
			if w, ok := k["window"]; ok {
				slim["window"] = w
			}
			for _, kk := range []string{"permission", "plugins", "usingComponents"} {
				if v, ok := k[kk]; ok {
					slim[kk] = v
				}
			}
		}
		if b, err := json.MarshalIndent(slim, "", "  "); err == nil {
			_, _ = app.Write(b)
		}
		_ = app.Close()
		written = append(written, "app.json")
	}
	return written, nil
}

// matchBrace 从 open 位置的 '{' 起找到配对的 '}'，跳过字符串与注释。
func matchBrace(src string, open int) (int, bool) {
	if open >= len(src) || src[open] != '{' {
		return 0, false
	}
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '"', '\'', '`':
			i = skipString(src, i)
			if i < 0 {
				return 0, false
			}
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				for i < len(src) && src[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				j := strings.Index(src[i+2:], "*/")
				if j < 0 {
					return 0, false
				}
				i += j + 3
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// skipString 返回字符串结束引号的位置；处理转义。
func skipString(src string, start int) int {
	q := src[start]
	for i := start + 1; i < len(src); i++ {
		switch src[i] {
		case '\\':
			i++
		case q:
			return i
		}
	}
	return -1
}

func dedent(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimPrefix(ln, "    ")
	}
	return strings.Join(lines, "\n")
}

// normalizeJSObject 把 JS 对象字面量转成合法 JSON（无引号 key、单引号字符串）。
func normalizeJSObject(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			// 单引号串内的 \' 在 JSON 里非法，直接还原成裸引号
			if inStr == '\'' && c == '\\' && i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			if c == '\\' {
				b.WriteByte(c)
				if i+1 < len(s) {
					i++
					b.WriteByte(s[i])
				}
				continue
			}
			if c == inStr {
				inStr = 0
				b.WriteByte('"')
				continue
			}
			if inStr == '\'' && c == '"' {
				b.WriteString("\\\"")
				continue
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
			b.WriteByte('"')
		case '{', ',':
			b.WriteByte(c)
			// 尝试吸收无引号 key: 形如 {a: 或 ,a:（含引号 key 已在上面的分支处理）
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			k := j
			for k < len(s) && (isJSIdentChar(s[k])) {
				k++
			}
			m := k
			for m < len(s) && (s[m] == ' ' || s[m] == '\t') {
				m++
			}
			if k > j && m < len(s) && s[m] == ':' {
				b.WriteString(`"` + s[j:k] + `":`)
				i = m
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isJSIdentChar(c byte) bool {
	return c == '_' || c == '$' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
