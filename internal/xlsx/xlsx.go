// Package xlsx 把抓包与交叉分析结果导出为 Excel 工作簿，供测试记录与复现使用。
package xlsx

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"wxsec/internal/cross"
	"wxsec/internal/proxy"
	"wxsec/internal/scanner"
)

// Input 是一次导出的全部数据源。
type Input struct {
	Flows     []proxy.Flow
	Assets    []scanner.Asset
	SDKAssets []scanner.Asset
	Report    *cross.Report
}

// 工作表名称固定，前端与测试都按名字引用。
const (
	sheetFlows   = "抓包URL"
	sheetStatic  = "静态接口资产"
	sheetCompare = "动态静态对照"
	sheetSummary = "汇总"
)

var (
	flowCols = []string{"序号", "时间", "方法", "URL", "协议", "域名", "路径", "查询参数名", "状态码",
		"响应类型", "请求字节", "响应字节", "耗时(ms)", "小程序AppID", "包版本", "已解密", "备注"}
	staticCols  = []string{"URL", "协议", "域名", "路径", "出现文件", "行号", "出现次数", "第三方SDK"}
	compareCols = []string{"分类", "域名", "路径", "完整URL示例", "协议", "方法", "状态码", "查询参数名",
		"小程序AppID", "请求次数", "包内声明次数", "包内出现位置", "第三方SDK", "备注"}
	summaryCols = []string{"项目", "值"}

	widths = map[string][]float64{
		sheetFlows:   {7, 19, 8, 62, 7, 26, 34, 26, 8, 22, 11, 11, 10, 20, 9, 8, 34},
		sheetStatic:  {62, 7, 26, 34, 30, 7, 10, 22},
		sheetCompare: {14, 26, 34, 62, 7, 14, 14, 26, 20, 10, 13, 34, 22, 40},
		sheetSummary: {26, 64},
	}
)

// Export 生成四表工作簿（抓包 / 静态资产 / 对照 / 汇总），返回文件路径。
func Export(in Input, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create export dir: %w", err)
	}
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	if err := f.SetSheetName(f.GetSheetName(0), sheetFlows); err != nil {
		return "", err
	}
	for _, name := range []string{sheetStatic, sheetCompare, sheetSummary} {
		if _, err := f.NewSheet(name); err != nil {
			return "", err
		}
	}

	if err := writeFlows(f, in.Flows); err != nil {
		return "", err
	}
	if err := writeStatic(f, in.Assets, in.SDKAssets); err != nil {
		return "", err
	}
	if err := writeCompare(f, in.Report); err != nil {
		return "", err
	}
	if err := writeSummary(f, in); err != nil {
		return "", err
	}
	if err := decorate(f); err != nil {
		return "", err
	}

	path := filepath.Join(dir, fmt.Sprintf("wxsec-urls-%s.xlsx", time.Now().Format("20060102-150405")))
	if err := f.SaveAs(path); err != nil {
		return "", fmt.Errorf("save xlsx: %w", err)
	}
	return path, nil
}

func writeFlows(f *excelize.File, flows []proxy.Flow) error {
	if err := setRow(f, sheetFlows, 1, flowCols); err != nil {
		return err
	}
	for i, fl := range flows {
		err := setRow(f, sheetFlows, i+2, []string{
			strconv.FormatInt(fl.Seq, 10),
			fl.Time.Local().Format("2006-01-02 15:04:05"),
			fl.Method,
			fl.DisplayURL(),
			strings.ToUpper(fl.Scheme),
			fl.Host,
			fl.Path,
			strings.Join(queryNames(fl.Query), ", "),
			strconv.Itoa(fl.Status),
			fl.ContentType,
			strconv.FormatInt(fl.ReqBytes, 10),
			strconv.FormatInt(fl.RespBytes, 10),
			strconv.FormatInt(fl.DurationMs, 10),
			fl.AppID,
			fl.WxVersion,
			yesNo(fl.Intercepted),
			fl.Note,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func writeStatic(f *excelize.File, assets, sdkAssets []scanner.Asset) error {
	if err := setRow(f, sheetStatic, 1, staticCols); err != nil {
		return err
	}
	row := 2
	lists := [][]scanner.Asset{assets, sdkAssets}
	for _, list := range lists {
		for _, a := range list {
			err := setRow(f, sheetStatic, row, []string{
				a.URL, strings.ToUpper(a.Scheme), a.Host, a.Path, a.File,
				strconv.Itoa(a.Line), strconv.Itoa(maxInt(a.Count, 1)), a.SDK,
			})
			if err != nil {
				return err
			}
			row++
		}
	}
	return nil
}

func writeCompare(f *excelize.File, rep *cross.Report) error {
	if err := setRow(f, sheetCompare, 1, compareCols); err != nil {
		return err
	}
	if rep == nil {
		return nil
	}
	for i, r := range rep.Rows {
		err := setRow(f, sheetCompare, i+2, []string{
			categoryCN(r.Category),
			r.Host,
			r.Path,
			r.Sample,
			strings.ToUpper(r.Scheme),
			strings.Join(r.Methods, ", "),
			statusText(r.Statuses),
			strings.Join(r.QueryKeys, ", "),
			strings.Join(r.AppIDs, ", "),
			strconv.Itoa(r.DynamicCount),
			strconv.Itoa(r.StaticCount),
			strings.Join(r.StaticFiles, "; "),
			r.SDK,
			strings.Join(r.Notes, "；"),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func writeSummary(f *excelize.File, in Input) error {
	if err := setRow(f, sheetSummary, 1, summaryCols); err != nil {
		return err
	}
	rows := [][2]string{
		{"生成时间", time.Now().Local().Format("2006-01-02 15:04:05")},
		{"抓包记录条数", strconv.Itoa(len(in.Flows))},
		{"静态接口资产条数", strconv.Itoa(len(in.Assets) + len(in.SDKAssets))},
	}
	decrypted, connectOnly := 0, 0
	appIDs := map[string]bool{}
	for _, fl := range in.Flows {
		if fl.Intercepted {
			decrypted++
		} else {
			connectOnly++
		}
		if fl.AppID != "" {
			appIDs[fl.AppID] = true
		}
	}
	rows = append(rows,
		[2]string{"已解密请求", strconv.Itoa(decrypted)},
		[2]string{"仅域名的 CONNECT 记录", strconv.Itoa(connectOnly)},
		[2]string{"涉及小程序 AppID", strings.Join(keys(appIDs), ", ")},
	)
	if in.Report != nil {
		rows = append(rows, [2]string{"扫描目录", in.Report.ScanRoot})
		for _, item := range []struct{ key, label string }{
			{cross.StatBoth, "包内声明且实际请求"},
			{cross.StatDynamicOnly, "仅出现在流量中"},
			{cross.StatStaticOnly, "仅出现在包内（本次未触发）"},
			{cross.StatHostOnly, "仅记录到域名"},
		} {
			rows = append(rows, [2]string{item.label, strconv.Itoa(in.Report.Tally(item.key))})
		}
		rows = append(rows,
			[2]string{"对照表行数", strconv.Itoa(in.Report.Tally(cross.StatRows))},
			[2]string{"动态域名", strings.Join(in.Report.DynamicHosts, ", ")},
			[2]string{"静态域名", strings.Join(in.Report.StaticHosts, ", ")},
		)
	}
	rows = append(rows,
		[2]string{"数据范围说明", "仅包含 URL、状态码与体量等定位信息；未记录 Cookie、Authorization 等凭据"},
		[2]string{"工具与许可", "wxsec · Copyright © 2026 wuge2019 · MIT License · GitHub: wuge2019"},
	)
	for i, r := range rows {
		if err := setRow(f, sheetSummary, i+2, []string{r[0], r[1]}); err != nil {
			return err
		}
	}
	return nil
}

// decorate 设置列宽、表头样式、冻结首行与筛选。
func decorate(f *excelize.File) error {
	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"2F5B8F"}, Pattern: 1},
		Alignment: &excelize.Alignment{Vertical: "center"},
	})
	if err != nil {
		return err
	}
	for name, cols := range widths {
		for i := range cols {
			col := colName(i)
			if err := f.SetColWidth(name, col, col, cols[i]); err != nil {
				return err
			}
		}
		last := colName(len(cols) - 1)
		if err := f.SetCellStyle(name, "A1", last+"1", headerStyle); err != nil {
			return err
		}
		if err := f.SetPanes(name, &excelize.Panes{
			Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft",
		}); err != nil {
			return err
		}
		if err := f.AutoFilter(name, "A1:"+last+"1", nil); err != nil {
			return err
		}
	}
	return nil
}

// setRow 全部按文本写入：URL 常以 = 开头会被 Excel 当公式执行，文本化可避免注入。
func setRow(f *excelize.File, sheet string, row int, cells []string) error {
	for i, v := range cells {
		cell, err := excelize.CoordinatesToCellName(i+1, row)
		if err != nil {
			return err
		}
		if err := f.SetCellStr(sheet, cell, v); err != nil {
			return err
		}
	}
	return nil
}

func colName(idx int) string {
	name, err := excelize.ColumnNumberToName(idx + 1)
	if err != nil {
		return "A"
	}
	return name
}

func queryNames(raw string) []string {
	if raw == "" {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return strings.Split(raw, "&")
	}
	out := make([]string, 0, len(q))
	for k := range q {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func statusText(statuses []int) string {
	out := make([]string, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, strconv.Itoa(s))
	}
	return strings.Join(out, ", ")
}

func categoryCN(cat string) string {
	switch cat {
	case cross.CatBoth:
		return "两者都有"
	case cross.CatDynamic:
		return "仅动态抓包"
	case cross.CatStatic:
		return "仅包内声明"
	case cross.CatHostOnly:
		return "仅域名"
	default:
		return cat
	}
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
