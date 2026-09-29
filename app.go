package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"wxsec/internal/decomp"
	"wxsec/internal/report"
	"wxsec/internal/scanner"
	"wxsec/internal/wechat"
	"wxsec/internal/wxapkg"
)

// App 暴露给前端的绑定服务。
type App struct {
	ctx context.Context

	tasks sync.Map // id -> *Task

	mu         sync.Mutex
	lastScan   *scanner.Result
	scanRoot   string
	lastDecomp *decomp.Result
}

// Task 是异步任务（解包/扫描）的状态快照。
type Task struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"`
	Title    string  `json:"title"`
	Status   string  `json:"status"` // running / done / error
	Message  string  `json:"message"`
	Current  int     `json:"current"`
	Total    int     `json:"total"`
	Progress float64 `json:"progress"`
	Output   string  `json:"output"`
	Restored string  `json:"restored"` // WXML/WXSS 还原产物目录，空表示未还原
	Error    string  `json:"error"`
}

// UnpackRequest 是前端提交的解包参数。
type UnpackRequest struct {
	Source    string `json:"source"` // .wxapkg 文件或包含 wxapkg 的目录
	AppID     string `json:"appId"`  // 加密包解密用
	OutDir    string `json:"outDir"` // 输出目录，空则自动
	Beautify  bool   `json:"beautify"`
	Restore   bool   `json:"restore"`
	Decompile bool   `json:"decompile"` // 执行编译产物还原 WXML/WXSS
	Scan      bool   `json:"scan"`      // 解包完成后自动安全扫描
}

// DirEntry 是文件浏览器的一个条目。
type DirEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
	Ext   string `json:"ext"`
}

// SourceView 是代码查看器的返回体。
type SourceView struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Size      int64  `json:"size"`
}

// Version 是构建信息。
const Version = "0.1.0"

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

func (a *App) VersionInfo() string { return Version }

// ── 包发现 ──────────────────────────────────────────────────────────────

// DetectWeChatRoots 返回本机微信小程序缓存目录的探测结果。
func (a *App) DetectWeChatRoots() []wechat.RootInfo {
	return wechat.CandidateRoots()
}

// ScanPackages 在指定根目录下枚举小程序包（按 AppID 聚合）。
func (a *App) ScanPackages(root string) ([]wechat.PackageRef, error) {
	if root == "" {
		return nil, errors.New("root path is empty")
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("directory not found: %s", root)
	}
	return wechat.DiscoverPackages(root)
}

// InspectPackage 预览单个 .wxapkg 的内部结构。
func (a *App) InspectPackage(path, appid string) ([]wxapkg.Entry, error) {
	pkg, _, _, err := wxapkg.Inspect(path, appid)
	if err != nil {
		return nil, err
	}
	return pkg.Files, nil
}

// PackageCacheInfo 返回某个 AppID 在本机微信缓存中的目录与规模，供删除前确认。
func (a *App) PackageCacheInfo(root, appid string) (*wechat.CacheDir, error) {
	return wechat.LocateCacheDir(root, appid)
}

// DeletePackageCache 清除该 AppID 的本机小程序缓存（不可撤销，微信会在下次打开时重新下载）。
// 路径边界校验全部在 wechat 包内完成，只允许删除缓存根目录下确实装有小程序包的 AppID 目录。
func (a *App) DeletePackageCache(root, appid string) (*wechat.CacheDir, error) {
	res, err := wechat.DeleteCacheDir(root, appid)
	a.invalidateAnalysisCache()
	return res, err
}

// DeletePackageCaches 批量清除多个 AppID 的本机小程序缓存。
// 越界的 AppID 会被逐条拒绝并记入 Failed，不会中断整批操作。
func (a *App) DeletePackageCaches(root string, appids []string) (*wechat.CacheCleanup, error) {
	res, err := wechat.DeleteCacheDirs(root, appids)
	if res != nil && res.Deleted > 0 {
		a.invalidateAnalysisCache()
	}
	return res, err
}

// invalidateAnalysisCache 在缓存被清除后丢弃陈旧的扫描与还原结果，避免 GUI 展示过期数据。
func (a *App) invalidateAnalysisCache() {
	a.mu.Lock()
	a.lastScan = nil
	a.scanRoot = ""
	a.lastDecomp = nil
	a.mu.Unlock()
}

// ── 解包 ────────────────────────────────────────────────────────────────

// Unpack 异步解包，返回任务 ID，进度通过 "task" 事件推送。
func (a *App) Unpack(req UnpackRequest) (string, error) {
	if req.Source == "" {
		return "", errors.New("source path is empty")
	}
	st, err := os.Stat(req.Source)
	if err != nil {
		return "", fmt.Errorf("source not found: %w", err)
	}

	sources := []string{req.Source}
	if st.IsDir() {
		found, err := wxapkg.WalkSources(req.Source)
		if err != nil {
			return "", err
		}
		if len(found) == 0 {
			return "", errors.New("no .wxapkg file found in directory")
		}
		sources = found
	}

	outDir := req.OutDir
	if outDir == "" {
		base, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		outDir = filepath.Join(base, "wxsec-output")
	}
	if !filepath.IsAbs(outDir) {
		return "", errors.New("output dir must be an absolute path")
	}

	task := &Task{ID: newID(), Kind: "unpack", Title: filepath.Base(req.Source), Status: "running", Total: len(sources) * 100}
	a.tasks.Store(task.ID, task)

	go func() {
		agg := newProgressAgg(task, len(sources), req.Decompile, req.Scan)
		decompNote := ""
		for i, src := range sources {
			dst := resolveOutDir(outDir, src, len(sources))
			task.Message = "解包 " + filepath.Base(src)
			a.push(task)

			unpackProg := agg.begin(i, phaseUnpack)
			res, err := wxapkg.UnpackFile(src, wxapkg.Options{
				AppID:    req.AppID,
				OutDir:   dst,
				Beautify: req.Beautify,
				Restore:  req.Restore,
				Progress: func(cur, total int, name string) {
					unpackProg(cur, total)
					a.push(task)
				},
			})
			if err != nil {
				task.Status = "error"
				task.Error = err.Error()
				a.push(task)
				return
			}
			task.Output = dst

			if req.Decompile {
				decompNote = a.decompileInto(task, dst, agg.begin(i, phaseDecompile))
			}

			if req.Scan && res != nil {
				if err := a.scanInto(task, dst, agg.begin(i, phaseScan)); err != nil {
					task.Status = "error"
					task.Error = err.Error()
					a.push(task)
					return
				}
			}
			agg.set(i+1, 0)
			a.push(task)
		}
		task.Status = "done"
		task.Current = task.Total
		task.Progress = 100
		task.Message = "完成"
		if decompNote != "" {
			task.Message = "完成 · " + decompNote
		}
		a.push(task)
	}()

	return task.ID, nil
}

// GetTask 拉取任务最新状态（供前端轮询兜底）。
func (a *App) GetTask(id string) (*Task, error) {
	v, ok := a.tasks.Load(id)
	if !ok {
		return nil, errors.New("task not found")
	}
	t := v.(*Task)
	cp := *t
	return &cp, nil
}

func (a *App) ListTasks() []Task {
	var out []Task
	a.tasks.Range(func(_, v any) bool {
		t := v.(*Task)
		out = append(out, *t)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func (a *App) push(t *Task) {
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "task", *t)
	}
}

// ── 任务进度聚合 ────────────────────────────────────────────────────────

// 解包流水线内部的三个阶段。
const (
	phaseUnpack    = "unpack"
	phaseDecompile = "decompile"
	phaseScan      = "scan"
)

// progressAgg 把「多个包 × 多个阶段」的进度折算成整任务的 Current/Total：
// Total 固定为 包数×100，Current 单调递增且不会超过 Total。
// 各阶段的 done/total 是阶段自身的文件数，不能直接跨包相加，必须按权重归一。
type progressAgg struct {
	task    *Task
	pkgs    int
	phases  []string
	weights map[string]float64
	sum     float64
	current int // 已展示过的进度，用于阻止回退
}

// newProgressAgg 按启用的阶段分配权重：解包是主体，还原与扫描分享剩余。
func newProgressAgg(task *Task, pkgs int, decompile, scan bool) *progressAgg {
	agg := &progressAgg{task: task, pkgs: max(pkgs, 1), weights: map[string]float64{}}
	agg.add(phaseUnpack, 5)
	if decompile {
		agg.add(phaseDecompile, 2)
	}
	if scan {
		agg.add(phaseScan, 3)
	}
	return agg
}

func (agg *progressAgg) add(phase string, weight float64) {
	agg.phases = append(agg.phases, phase)
	agg.weights[phase] = weight
	agg.sum += weight
}

// begin 返回某个包某个阶段的进度回调，pkg 从 0 开始。
func (agg *progressAgg) begin(pkg int, phase string) func(done, total int) {
	var base float64
	for _, p := range agg.phases {
		if p == phase {
			break
		}
		base += agg.weights[p]
	}
	return func(done, total int) {
		agg.set(pkg, base+agg.weights[phase]*ratio(done, total))
	}
}

// set 按「已完成包数 + 当前包的加权完成比例」写入任务进度。
// 阶段内部的 done/total 会重新计数（例如还原先按编译产物计数、再按页面计数），
// 所以进度只允许前进，不允许回退。
func (agg *progressAgg) set(pkg int, weighted float64) {
	next := int((float64(pkg) + clamp01(weighted/agg.sum)) * 100)
	if next < agg.current {
		next = agg.current
	}
	agg.current = next
	agg.task.Current = next
	agg.task.Total = agg.pkgs * 100
	agg.task.Progress = ratio(next, agg.task.Total) * 100
}

// directProgress 用于独立任务：阶段进度就是任务进度。
// 统一折算成 0~100，并在计数重新开始时保持不回退。
func directProgress(task *Task) func(done, total int) {
	last := 0.0
	return func(done, total int) {
		p := ratio(done, total) * 100
		if p < last {
			p = last
		}
		last = p
		task.Current = int(p)
		task.Total = 100
		task.Progress = p
	}
}

func ratio(done, total int) float64 {
	if total <= 0 {
		return 1
	}
	return clamp01(float64(done) / float64(total))
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// ── 页面结构还原 ────────────────────────────────────────────────────────

// decompSubdir 是还原产物子目录名，与 decomp.Options.OutSubdir 保持一致。
const decompSubdir = "_decompiled"

// decompileInto 在解包目录内执行编译产物，还原 WXML/WXSS，返回一句可展示的汇总。
// 还原是增强分析，失败只记录在任务消息里，不让整个解包任务判失败。
// phase 接收本阶段的 done/total，由调用方决定如何折算成任务进度。
func (a *App) decompileInto(task *Task, dir string, phase func(done, total int)) string {
	task.Message = "还原页面结构 " + filepath.Base(dir)
	a.push(task)

	res, err := decomp.DecompileDir(dir, decomp.Options{
		OutSubdir: decompSubdir,
		Progress: func(done, total int, name string) {
			phase(done, total)
			task.Message = fmt.Sprintf("还原页面结构 %d/%d · %s", done, total, name)
			a.push(task)
		},
	})
	if err != nil {
		task.Message = "页面结构还原失败：" + err.Error()
		a.push(task)
		return ""
	}
	a.mu.Lock()
	a.lastDecomp = res
	a.mu.Unlock()

	wxml, wxss := 0, 0
	for _, p := range res.Pages {
		if p.Kind == "wxml" {
			wxml++
		} else {
			wxss++
		}
	}
	if len(res.Pages) > 0 {
		task.Restored = filepath.Join(dir, decompSubdir)
	}
	task.Message = fmt.Sprintf("还原 WXML %d 个 · WXSS %d 个 · 跳过 %d 个", wxml, wxss, len(res.Skipped))
	a.push(task)
	return task.Message
}

// DecompileDir 对已有的解包目录单独执行还原，返回任务 ID。
func (a *App) DecompileDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("directory is empty")
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("directory not found: %s", dir)
	}
	task := &Task{ID: newID(), Kind: "decompile", Title: filepath.Base(dir), Status: "running", Output: dir}
	a.tasks.Store(task.ID, task)
	go func() {
		a.decompileInto(task, dir, directProgress(task))
		task.Current = task.Total
		task.Progress = 100
		task.Status = "done"
		a.push(task)
	}()
	return task.ID, nil
}

// LastDecompile 返回最近一次还原的汇总，供前端展示还原清单。
func (a *App) LastDecompile() (*decomp.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastDecomp == nil {
		return nil, errors.New("no decompile result yet")
	}
	return a.lastDecomp, nil
}

// ── 安全扫描 ────────────────────────────────────────────────────────────
// ScanDir 异步对解包目录执行静态安全扫描。
func (a *App) ScanDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("directory is empty")
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("directory not found: %s", dir)
	}
	task := &Task{ID: newID(), Kind: "scan", Title: filepath.Base(dir), Status: "running"}
	a.tasks.Store(task.ID, task)
	go func() {
		if err := a.scanInto(task, dir, directProgress(task)); err != nil {
			task.Status = "error"
			task.Error = err.Error()
			a.push(task)
			return
		}
		task.Current = task.Total
		task.Progress = 100
		task.Status = "done"
		task.Message = "扫描完成"
		a.push(task)
	}()
	return task.ID, nil
}

// scanInto 执行扫描并缓存结果，phase 接收本阶段的 done/total。
func (a *App) scanInto(task *Task, dir string, phase func(done, total int)) error {
	res, err := scanner.Scan(scanner.Options{
		Root: dir,
		Progress: func(done, total, findings int, current string) {
			phase(done, total)
			task.Message = fmt.Sprintf("扫描 %s（已发现 %d）", current, findings)
			a.push(task)
		},
	})
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.lastScan = res
	a.scanRoot = dir
	a.mu.Unlock()
	return nil
}

// LastScanResult 返回最近一次扫描结果（GUI 主数据源）。
func (a *App) LastScanResult() (*scanner.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastScan == nil {
		return nil, errors.New("no scan result yet")
	}
	return a.lastScan, nil
}

// ExportReport 将最近扫描结果导出为 html/json，返回文件路径。
func (a *App) ExportReport(format, dir string) (string, error) {
	a.mu.Lock()
	res := a.lastScan
	a.mu.Unlock()
	if res == nil {
		return "", errors.New("请先执行安全扫描")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, "wxsec-reports")
	}
	return report.Export(res, dir, format)
}

// ── 文件浏览 ────────────────────────────────────────────────────────────

// ListDir 列出一层目录（前端树按需懒加载）。
func (a *App) ListDir(dir string) ([]DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]DirEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		var size int64
		if err == nil {
			size = info.Size()
		}
		out = append(out, DirEntry{
			Name:  e.Name(),
			Path:  filepath.Join(dir, e.Name()),
			IsDir: e.IsDir(),
			Size:  size,
			Ext:   strings.ToLower(filepath.Ext(e.Name())),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > 2000 {
		out = out[:2000]
	}
	return out, nil
}

const maxViewBytes = 512 << 10

// ReadSource 以只读方式查看解包产物；rootDir 用于限制越界访问。
func (a *App) ReadSource(rootDir, path string) (*SourceView, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(abs, absRoot+string(os.PathSeparator)) {
		return nil, errors.New("path outside scan root rejected")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Size() > maxViewBytes {
		return nil, fmt.Errorf("cannot preview: %s", filepath.Base(abs))
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	if !isLikelyText(data) {
		return nil, errors.New("binary file")
	}
	text := string(data)
	return &SourceView{
		Path:      abs,
		Content:   text,
		Lines:     strings.Count(text, "\n") + 1,
		Truncated: false,
		Size:      info.Size(),
	}, nil
}

func isLikelyText(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
	}
	return true
}

// ── 对话框与系统集成 ────────────────────────────────────────────────────

// PickDirectory 打开系统目录选择框。
func (a *App) PickDirectory(title string) (string, error) {
	return wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{Title: title})
}

// PickWxapkgFiles 支持多选 .wxapkg 文件。
func (a *App) PickWxapkgFiles() ([]string, error) {
	return wailsruntime.OpenMultipleFilesDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择小程序包文件",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "微信小程序包 (*.wxapkg)", Pattern: "*.wxapkg"},
			{DisplayName: "所有文件", Pattern: "*.*"},
		},
	})
}

// OpenInExplorer 在资源管理器中打开目录或文件。
func (a *App) OpenInExplorer(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch goruntime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", filepath.Clean(path))
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}

// ClipboardWrite 复制文本（如复制报告路径、接口 URL）。
func (a *App) ClipboardWrite(text string) error {
	return wailsruntime.ClipboardSetText(a.ctx, text)
}

// LegalNotice 返回免责声明（法律文本按惯例保持英文）。
func (a *App) LegalNotice() string {
	return "wxsec is intended for authorized security testing and education only. " +
		"Do not use it against applications you do not own or have written permission to test. " +
		"The authors accept no liability for misuse."
}

func resolveOutDir(base, source string, total int) string {
	name := strings.TrimSuffix(filepath.Base(source), filepath.Ext(source))
	if wxapkg.IsAppID(name) {
		name = name + "_unpacked"
	} else {
		name = filepath.Base(source) + "_unpacked"
	}
	if total == 1 {
		name = filepath.Base(source)
		name = strings.TrimSuffix(name, filepath.Ext(name))
		name += "_unpacked"
	}
	return filepath.Join(base, sanitizeForFilesystem(name))
}

func sanitizeForFilesystem(s string) string {
	r := strings.NewReplacer(":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", "\\", "_", "/", "_")
	return strings.TrimSpace(r.Replace(s))
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
