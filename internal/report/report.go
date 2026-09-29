// Package report 将扫描结果导出为可交付的 HTML / JSON 报告。
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"wxsec/internal/scanner"
)

// Export 将结果写入 dir，返回生成的文件路径。format 取 "html" 或 "json"。
func Export(res *scanner.Result, dir, format string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create report dir: %w", err)
	}
	stamp := res.StartedAt.Format("20060102-150405")
	target := strings.ToLower(filepath.Clean(strings.TrimPrefix(format, ".")))

	switch target {
	case "json":
		path := filepath.Join(dir, fmt.Sprintf("wxsec-report-%s.json", stamp))
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal json: %w", err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return "", err
		}
		return path, nil

	case "html", "":
		path := filepath.Join(dir, fmt.Sprintf("wxsec-report-%s.html", stamp))
		b, err := RenderHTML(res)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return "", err
		}
		return path, nil

	default:
		return "", fmt.Errorf("unsupported report format %q", format)
	}
}

type view struct {
	*scanner.Result
	SevOrder   []string
	BySeverity map[string][]scanner.Finding
	HostCount  int
	URLCount   int
	SDKCount   int
	BytesMB    float64
	InfoRows   []kv
}

type kv struct {
	Key   string
	Value string
}

func severityGroups(fs []scanner.Finding) map[string][]scanner.Finding {
	m := map[string][]scanner.Finding{}
	for _, f := range fs {
		m[string(f.Severity)] = append(m[string(f.Severity)], f)
	}
	return m
}

func infoRows(m map[string]any) []kv {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows []kv
	for _, k := range keys {
		var s string
		switch v := m[k].(type) {
		case string:
			s = v
		default:
			b, err := json.Marshal(v)
			if err != nil {
				s = fmt.Sprint(v)
			} else {
				s = truncate(string(b), 400)
			}
		}
		if s == "" || s == "null" {
			continue
		}
		rows = append(rows, kv{Key: k, Value: s})
	}
	return rows
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RenderHTML 生成单文件、可离线查看的 HTML 报告。
func RenderHTML(res *scanner.Result) ([]byte, error) {
	v := &view{
		Result:     res,
		SevOrder:   []string{"high", "medium", "low", "info"},
		BySeverity: severityGroups(res.Findings),
		HostCount:  len(res.Hosts),
		URLCount:   len(res.Assets),
		SDKCount:   len(res.SDKAssets),
		BytesMB:    float64(res.BytesScanned) / (1 << 20),
		InfoRows:   infoRows(res.AppInfo),
	}
	tpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"sevName": sevName,
		"join":    strings.Join,
	}).Parse(htmlTpl))

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("render html report: %w", err)
	}
	return buf.Bytes(), nil
}

func sevName(s string) string {
	switch s {
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "提示"
	}
}

// 说明：所有插值均通过 html/template 自动转义，被扫小程序中的脚本不会执行。
const htmlTpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>微信小程序安全测试报告 - {{.Root}}</title>
<style>
:root{--high:#d93025;--medium:#e8710a;--low:#1a73e8;--info:#5f6368;}
*{box-sizing:border-box}
body{font-family:"Microsoft YaHei","PingFang SC",system-ui,sans-serif;margin:0;background:#f5f6f8;color:#202124;}
header{background:#1f2937;color:#fff;padding:24px 32px;}
header h1{margin:0 0 6px;font-size:20px}
header .meta{font-size:12px;opacity:.8;line-height:1.8;word-break:break-all}
main{max-width:1200px;margin:0 auto;padding:24px 32px 64px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{flex:1 1 140px;background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.12)}
.card .num{font-size:28px;font-weight:700}
.card.high .num{color:var(--high)}.card.medium .num{color:var(--medium)}
.card.low .num{color:var(--low)}.card.info .num{color:var(--info)}
h2{font-size:16px;margin:32px 0 12px;border-left:4px solid #1f2937;padding-left:10px}
table{width:100%;border-collapse:collapse;background:#fff;font-size:13px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th,td{padding:9px 10px;border-bottom:1px solid #eef0f2;text-align:left;vertical-align:top}
th{background:#fafbfc;font-weight:600;white-space:nowrap}
td.mono,th.mono{font-family:Consolas,Menlo,monospace}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;color:#fff}
.tag.high{background:var(--high)}.tag.medium{background:var(--medium)}
.tag.low{background:var(--low)}.tag.info{background:var(--info)}
code{background:#f1f3f4;padding:1px 5px;border-radius:3px;word-break:break-all;font-family:Consolas,Menlo,monospace}
.rec{color:#5f6368;font-size:12px;margin-top:4px}
footer{padding:20px 32px;font-size:12px;color:#5f6368;border-top:1px solid #dadce0}
.empty{padding:16px;background:#fff;border-radius:8px;color:#5f6368}
.muted{color:#5f6368;font-size:12px;margin:6px 0 10px}
</style>
</head>
<body>
<header>
  <h1>微信小程序安全测试报告</h1>
  <div class="meta">
    扫描目标：{{.Root}}<br>
    扫描时间：{{.StartedAt.Format "2006-01-02 15:04:05"}} ·
    耗时 {{.DurationMs}} ms ·
    文件总数 {{.FilesTotal}} ·
    实际扫描 {{.FilesScanned}} ·
    扫描数据量 {{printf "%.2f" .BytesMB}}MB
  </div>
</header>
<main>
  <div class="cards">
    {{range .SevOrder}}
    <div class="card {{.}}"><div class="num">{{len (index $.BySeverity .)}}</div><div>{{sevName .}}</div></div>
    {{end}}
    <div class="card"><div class="num">{{.HostCount}}</div><div>关联域名</div></div>
    <div class="card"><div class="num">{{.URLCount}}</div><div>接口 URL</div></div>
    <div class="card"><div class="num">{{.SDKCount}}</div><div>第三方 SDK URL</div></div>
  </div>

  {{if .InfoRows}}
  <h2>小程序配置概览</h2>
  <table><thead><tr><th>配置项</th><th>值</th></tr></thead><tbody>
    {{range .InfoRows}}<tr><td>{{.Key}}</td><td class="mono">{{.Value}}</td></tr>{{end}}
  </tbody></table>
  {{end}}

  {{range .SevOrder}}
    {{$sev := .}}
    {{with index $.BySeverity .}}
    <h2>{{sevName $sev}}问题（{{len .}}）</h2>
    <table>
      <thead><tr><th>规则</th><th>标题</th><th>位置</th><th>命中内容</th></tr></thead>
      <tbody>
      {{range .}}
        <tr>
          <td><span class="tag {{$sev}}">{{.RuleID}}</span><div class="rec">{{.Category}}</div></td>
          <td>{{.Title}}{{if gt .Occurrence 0}} <span class="rec">（同类重复 {{.Occurrence}} 次）</span>{{end}}</td>
          <td class="mono">{{.File}}:{{.Line}}</td>
          <td><code>{{.Value}}</code><div class="rec">上下文：{{.Context}}</div><div class="rec">建议：{{.Recommend}}</div></td>
        </tr>
      {{end}}
      </tbody>
    </table>
    {{end}}
  {{end}}

  {{if not .Findings}}<div class="empty">本次扫描未命中任何内置规则，仍需进行人工代码审计与动态接口测试。</div>{{end}}

  <h2>接口资产清单（{{len .Assets}}）</h2>
  {{if .Assets}}
  <table>
    <thead><tr><th>URL</th><th>协议</th><th>首次出现位置</th><th>出现次数</th></tr></thead>
    <tbody>
    {{range .Assets}}
      <tr><td class="mono">{{.URL}}</td><td>{{.Scheme}}</td><td class="mono">{{.File}}{{if .Line}}:{{.Line}}{{end}}</td><td>{{.Count}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<div class="empty">未发现目标自有接口 URL。</div>{{end}}

  {{if .SDKAssets}}
  <h2>第三方 SDK／公共库自带 URL（{{len .SDKAssets}}，不计入目标资产面）</h2>
  <div class="muted">以下域名由厂商控制（微信开放平台、统计与推送 SDK、公共 CDN、规范命名空间等），仅作组件识别参考；自建存储桶与业务域名不会被归入此类。</div>
  <table>
    <thead><tr><th>URL</th><th>来源</th><th>首次出现位置</th><th>出现次数</th></tr></thead>
    <tbody>
    {{range .SDKAssets}}
      <tr><td class="mono">{{.URL}}</td><td>{{.SDK}}</td><td class="mono">{{.File}}{{if .Line}}:{{.Line}}{{end}}</td><td>{{.Count}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .Skipped}}
  <h2>跳过项</h2>
  <table><tbody>{{range .Skipped}}<tr><td class="mono">{{.}}</td></tr>{{end}}</tbody></table>
  {{end}}
</main>
<footer>
  本报告由 wxsec 静态扫描引擎自动生成，仅覆盖内置规则，<b>不能替代人工代码审计与动态接口测试</b>；
  报告中的密钥类命中已做脱敏处理，完整值请回到源码定位查看。
  <b>报告内容是需要人工验证的线索，不构成安全结论</b>，误报与漏报均属正常现象。
  请仅在对你拥有所有权或已获得书面测试授权的小程序范围内使用本报告；
  本工具不绕过、也不协助绕过服务端鉴权与平台安全机制。
  <br>
  wxsec · Copyright © 2026 Lyu · 以 <a href="https://opensource.org/licenses/MIT">MIT License</a> 开源发布 ·
  联系：QQ 3531323422 / 微信 Lyu5918 / GitHub wuge2019
</footer>
</body>
</html>`
