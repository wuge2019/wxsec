package xlsx

import (
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"

	"wxsec/internal/cross"
	"wxsec/internal/proxy"
	"wxsec/internal/scanner"
)

func sampleInput() Input {
	flows := []proxy.Flow{
		{Seq: 1, Time: time.Now(), Method: "GET", URL: "https://api.example.com/v1/user/list?limit=20",
			Scheme: "https", Host: "api.example.com", Path: "/v1/user/list", Query: "limit=20&offset=0",
			Status: 200, ContentType: "application/json", RespBytes: 512, DurationMs: 33,
			AppID: "wx0123456789abcdef", WxVersion: "16", Intercepted: true},
		{Seq: 2, Time: time.Now(), Method: "CONNECT", Scheme: "connect", Host: "pinned.example.com",
			Intercepted: false, Note: "TLS 握手被客户端拒绝，仅记录域名"},
	}
	assets := []scanner.Asset{
		{URL: "https://api.example.com/v1/user/list", Scheme: "https", Host: "api.example.com",
			Path: "/v1/user/list", File: "pages/user/index.js", Line: 12, Count: 2},
		{URL: "https://api.example.com/v1/coupon/never", Scheme: "https", Host: "api.example.com",
			Path: "/v1/coupon/never", File: "app-service.js", Line: 3, Count: 1},
	}
	sdk := []scanner.Asset{
		{URL: "https://res.wx.qq.com/foo.js", Scheme: "https", Host: "res.wx.qq.com",
			Path: "/foo.js", File: "app-service.js", Line: 1, Count: 1, SDK: "微信/腾讯开放平台"},
	}
	return Input{
		Flows:     flows,
		Assets:    assets,
		SDKAssets: sdk,
		Report:    cross.Analyze(flows, assets, sdk, `C:\unpacked`),
	}
}

func TestExportWorkbook(t *testing.T) {
	path, err := Export(sampleInput(), t.TempDir())
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if !strings.HasSuffix(path, ".xlsx") {
		t.Errorf("文件名异常: %s", path)
	}

	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, name := range []string{sheetFlows, sheetStatic, sheetCompare, sheetSummary} {
		idx, err := f.GetSheetIndex(name)
		if err != nil || idx < 0 {
			t.Fatalf("缺少工作表 %s: %v", name, err)
		}
	}

	flowRows, err := f.GetRows(sheetFlows)
	if err != nil {
		t.Fatal(err)
	}
	if len(flowRows) != 3 {
		t.Fatalf("抓包表行数 = %d, want 3", len(flowRows))
	}
	if flowRows[0][3] != "URL" {
		t.Errorf("抓包表表头错误: %v", flowRows[0])
	}
	if flowRows[1][3] != "https://api.example.com/v1/user/list?limit=20" {
		t.Errorf("URL 单元格错误: %q", flowRows[1][3])
	}
	if flowRows[1][7] != "limit, offset" {
		t.Errorf("查询参数名错误: %q", flowRows[1][7])
	}
	if flowRows[2][3] != "https://pinned.example.com/（未解密，仅域名）" {
		t.Errorf("CONNECT-only URL 错误: %q", flowRows[2][3])
	}
	if flowRows[2][15] != "否" {
		t.Errorf("未解密标记错误: %q", flowRows[2][15])
	}

	compareRows, err := f.GetRows(sheetCompare)
	if err != nil {
		t.Fatal(err)
	}
	if len(compareRows)-1 != 4 {
		t.Fatalf("对照表行数 = %d", len(compareRows)-1)
	}
	if compareRows[1][0] != "两者都有" {
		t.Errorf("分类应中文化: %v", compareRows[1])
	}

	staticRows, err := f.GetRows(sheetStatic)
	if err != nil {
		t.Fatal(err)
	}
	if len(staticRows) != 4 {
		t.Fatalf("静态资产表行数 = %d, want 4", len(staticRows))
	}
	if staticRows[3][7] != "微信/腾讯开放平台" {
		t.Errorf("SDK 归属丢失: %v", staticRows[3])
	}

	summary, err := f.GetRows(sheetSummary)
	if err != nil {
		t.Fatal(err)
	}
	cell := map[string]string{}
	for _, r := range summary {
		if len(r) >= 2 {
			cell[r[0]] = r[1]
		}
	}
	if cell["抓包记录条数"] != "2" || cell["静态接口资产条数"] != "3" {
		t.Errorf("汇总计数错误: %v", cell)
	}
	if cell["包内声明且实际请求"] != "1" || cell["仅出现在包内（本次未触发）"] != "2" {
		t.Errorf("分类统计错误: %v", cell)
	}
	if !strings.Contains(cell["数据范围说明"], "Cookie") {
		t.Errorf("缺少数据范围说明: %v", cell)
	}
	if !strings.Contains(cell["结论使用说明"], "不构成安全结论") {
		t.Errorf("缺少结论免责说明: %v", cell)
	}
	if !strings.Contains(cell["授权要求"], "书面测试授权") {
		t.Errorf("缺少授权要求说明: %v", cell)
	}
}

func TestExportKeepsFormulasAsText(t *testing.T) {
	in := sampleInput()
	in.Flows[0].URL = "=cmd|' /C calc'!A0"
	in.Flows[0].Note = "@SUM(1+1)*3"
	path, err := Export(in, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	v, err := f.GetCellValue(sheetFlows, "D2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v, "=") {
		t.Errorf("以 = 开头的 URL 应原样保留为文本: %q", v)
	}
	note, _ := f.GetCellValue(sheetFlows, "Q2")
	if !strings.HasPrefix(note, "@") {
		t.Errorf("备注应原样保留: %q", note)
	}
}

func TestExportEmptyInput(t *testing.T) {
	path, err := Export(Input{}, t.TempDir())
	if err != nil {
		t.Fatalf("空数据也应导出: %v", err)
	}
	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rows, err := f.GetRows(sheetCompare)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("对照表应只剩表头: %d", len(rows))
	}
}
