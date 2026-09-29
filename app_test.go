package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wxsec/internal/cross"
	"wxsec/internal/proxy"
	"wxsec/internal/scanner"
)

// appBundle 复刻真实编译产物的最小契约：$gwx 工厂 + __wxAppCode__ 注册语句。
const appBundle = `
var $gwx_wxapp0000000000 = function(path, global) {
  if (typeof global === 'undefined') global = {};
  if (typeof global.entrys === 'undefined') global.entrys = {};
  var e_ = global.entrys;
  e_['./pages/a/index.wxml'] = {
    f: function(env, scopes, root, g) {
      root.children.push({tag:'wx-view', attr:{class:'box'}, children:[String(env.title)], raw:{}, generics:{}});
    }
  };
  if (path && e_[path]) {
    return function(env, dd, global) {
      var root = {tag:'wx-page', children: []};
      e_[path].f(env, {}, root, global || {});
      return root;
    };
  }
};
__wxAppCode__['pages/a/index.wxml'] = $gwx_wxapp0000000000('./pages/a/index.wxml');
__wxAppCode__['pages/a/index.wxss'] = '.box{color:red}';
`

func TestDecompileIntoWritesArtifacts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "page-frame.js"), []byte(appBundle), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewApp()
	task := &Task{ID: "t1", Kind: "unpack", Status: "running", Output: root}
	a.decompileInto(task, root, directProgress(task))

	if !strings.Contains(task.Message, "WXML 1 个") || !strings.Contains(task.Message, "WXSS 1 个") {
		t.Errorf("task message = %q", task.Message)
	}
	if task.Restored == "" {
		t.Fatal("restored dir not reported")
	}
	b, err := os.ReadFile(filepath.Join(task.Restored, "pages", "a", "index.wxml"))
	if err != nil {
		t.Fatalf("wxml not written: %v", err)
	}
	if !strings.Contains(string(b), "{{title}}") {
		t.Errorf("restored wxml = %s", b)
	}
	res, err := a.LastDecompile()
	if err != nil || len(res.Pages) != 2 {
		t.Errorf("LastDecompile = %+v, %v", res, err)
	}
}

// 进度聚合：多包多阶段的 current/total 必须单调递增且始终落在 0~100%。
func TestProgressAggKeepsPercentInRange(t *testing.T) {
	task := &Task{ID: "p1", Kind: "unpack", Status: "running", Total: 2 * 100}
	agg := newProgressAgg(task, 2, true, true)

	lastPct := -1.0
	check := func(at string) {
		if task.Current < 0 || task.Current > task.Total {
			t.Fatalf("%s: current=%d out of 0..%d", at, task.Current, task.Total)
		}
		pct := float64(task.Current) / float64(task.Total) * 100
		if pct < lastPct {
			t.Fatalf("%s: progress went backwards %.1f%% -> %.1f%%", at, lastPct, pct)
		}
		lastPct = pct
	}

	// 真实包里单包文件数可达数百，旧代码把它直接当百分比累加会算出 252%。
	for i := 0; i < 2; i++ {
		unpack := agg.begin(i, phaseUnpack)
		for _, cur := range []int{1, 37, 252, 300} {
			unpack(cur, 300)
			check("unpack")
		}
		decompPhase := agg.begin(i, phaseDecompile)
		decompPhase(69, 75)
		check("decompile")
		decompPhase(75, 75)
		check("decompile end")
		scan := agg.begin(i, phaseScan)
		scan(10, 8) // done 超过 total 也不能越过阶段边界
		check("scan overflow")
		scan(500, 500)
		check("scan end")
		agg.set(i+1, 0)
		check("package done")
	}

	if task.Current != task.Total || task.Progress != 100 {
		t.Errorf("final = current %d/%d, progress %.1f", task.Current, task.Total, task.Progress)
	}
}

// 只启用解包时，单包进度仍应完整覆盖 0~100%。
func TestProgressAggUnpackOnly(t *testing.T) {
	task := &Task{ID: "p2", Kind: "unpack", Status: "running"}
	agg := newProgressAgg(task, 1, false, false)
	unpack := agg.begin(0, phaseUnpack)
	unpack(5, 10)
	if task.Current != 50 || task.Total != 100 {
		t.Errorf("mid = %d/%d", task.Current, task.Total)
	}
	unpack(10, 10)
	if task.Current != 100 {
		t.Errorf("end = %d/%d", task.Current, task.Total)
	}
}

// 阶段内部的计数会重新从零开始（还原先按编译产物计数，再按页面计数），
// 进度条不能因此回退。
func TestProgressAggNeverGoesBackwards(t *testing.T) {
	task := &Task{ID: "p3", Kind: "unpack", Status: "running"}
	agg := newProgressAgg(task, 1, true, true)

	phase := agg.begin(0, phaseDecompile)
	phase(9, 9) // 加载完 9 个编译产物
	peak := task.Current
	phase(1, 6) // 换成按页面重新计数
	if task.Current != peak {
		t.Errorf("progress fell back: %d -> %d", peak, task.Current)
	}
	phase(6, 6)
	if task.Current != 70 { // (5+2)/10
		t.Errorf("decompile end = %d/%d", task.Current, task.Total)
	}
}

// 独立任务（单独还原/单独扫描）同样折算成 0~100，且不回退。
func TestDirectProgressNeverGoesBackwards(t *testing.T) {
	task := &Task{ID: "p4", Kind: "decompile", Status: "running"}
	phase := directProgress(task)
	phase(6, 9)
	if task.Current != 66 || task.Total != 100 {
		t.Fatalf("mid = %d/%d", task.Current, task.Total)
	}
	phase(9, 9)
	phase(1, 6) // 重新按页面计数，进度必须停在已到达的高度
	if task.Current != 100 {
		t.Errorf("fell back to %d/%d", task.Current, task.Total)
	}
}

// 解包目录没有编译产物时不应报错，也不能谎报还原产物。
func TestDecompileIntoWithoutBundles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app-service.js"), []byte("var a=1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewApp()
	task := &Task{ID: "t2", Kind: "unpack", Status: "running"}
	a.decompileInto(task, root, directProgress(task))

	if task.Restored != "" {
		t.Errorf("unexpected restored dir: %q", task.Restored)
	}
	if strings.Contains(task.Message, "失败") {
		t.Errorf("task message = %q", task.Message)
	}
}

// 抓包生命周期：随机端口启动、重复启动幂等、导出 Excel、退出收尾。
// 系统代理与根证书写入涉及真实机器状态，这里刻意不触发。
func TestCaptureLifecycleWithoutSystemProxy(t *testing.T) {
	a := NewApp() // 测试里没有 Wails 上下文，事件推送会自动跳过
	defer a.CloseCapture()

	// Windows 允许普通进程绑定低端口，公端口必须被拒绝。
	for _, port := range []int{80, 443, 1023, 65536, 70000} {
		if _, err := a.StartCapture(CaptureOptions{Port: port}); err == nil {
			t.Errorf("端口 %d 应被拒绝但启动成功", port)
		}
	}

	st, err := a.StartCapture(CaptureOptions{Intercept: true})
	if err != nil {
		t.Fatalf("启动抓包失败: %v", err)
	}
	if !st.Running || st.Port <= 0 {
		t.Fatalf("代理状态错误: %+v", st)
	}
	if st.SysProxy != nil && st.SysProxy.Managed {
		t.Fatal("测试不应接管系统代理")
	}

	again, err := a.StartCapture(CaptureOptions{Intercept: true})
	if err != nil {
		t.Fatalf("重复启动失败: %v", err)
	}
	if again.Port != st.Port {
		t.Errorf("重复启动换了端口: %d -> %d", st.Port, again.Port)
	}

	ca, err := a.CAInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ca.Subject, "wxsec") {
		t.Errorf("根证书主题异常: %q", ca.Subject)
	}
	exported, err := a.ExportCA(t.TempDir())
	if err != nil {
		t.Fatalf("导出根证书失败: %v", err)
	}
	if !strings.HasSuffix(exported, ".crt") {
		t.Errorf("根证书导出路径异常: %s", exported)
	}

	a.capMu.Lock()
	store := a.capStore
	a.capMu.Unlock()
	store.Add(proxy.Flow{Method: "GET", Scheme: "https", Host: "api.example.com",
		Path: "/v1/user/list", Query: "limit=20", Status: 200, Intercepted: true,
		AppID: "wx0123456789abcdef"})
	store.Add(proxy.Flow{Method: "CONNECT", Scheme: "connect", Host: "pinned.example.com"})

	flows, err := a.ListFlows(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("记录条数 = %d", len(flows))
	}
	if limited, err := a.ListFlows(1); err != nil || len(limited) != 1 || limited[0].Host != "pinned.example.com" {
		t.Errorf("limit 取尾部记录失败: %v %+v", err, limited)
	}

	if _, err := a.AnalyzeCapture(); err == nil || !strings.Contains(err.Error(), "安全扫描") {
		t.Errorf("未扫描时应提示先扫描: %v", err)
	}
	if p, err := a.ExportCaptureExcel(t.TempDir()); err != nil || !strings.HasSuffix(p, ".xlsx") {
		t.Errorf("仅有抓包记录也应能导出: %v %s", err, p)
	}

	// 模拟一次已完成的扫描，交叉分析与导出都应可用。
	a.mu.Lock()
	a.lastScan = &scanner.Result{Root: "fake-root", Assets: []scanner.Asset{
		{URL: "https://api.example.com/v1/user/list", Scheme: "https", Host: "api.example.com",
			Path: "/v1/user/list", File: "pages/user/index.js", Count: 2},
	}}
	a.scanRoot = "fake-root"
	a.mu.Unlock()

	rep, err := a.AnalyzeCapture()
	if err != nil {
		t.Fatalf("交叉分析失败: %v", err)
	}
	if rep.Tally(cross.StatBoth) != 1 || rep.Tally(cross.StatHostOnly) != 1 {
		t.Errorf("交叉统计错误: %v", rep.Stats)
	}

	outDir := t.TempDir()
	path, err := a.ExportCaptureExcel(outDir)
	if err != nil {
		t.Fatalf("导出 Excel 失败: %v", err)
	}
	if filepath.Dir(path) != outDir || !strings.HasSuffix(path, ".xlsx") {
		t.Errorf("导出位置错误: %s", path)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() < 4096 {
		t.Errorf("导出的工作簿异常: %v", err)
	}

	st, err = a.StopCapture()
	if err != nil {
		t.Fatal(err)
	}
	if st.Running {
		t.Error("停止后仍在运行")
	}
	if err := a.ClearFlows(); err != nil {
		t.Fatal(err)
	}
	if n, err := a.ListFlows(0); err != nil || len(n) != 0 {
		t.Errorf("清空后仍有记录: %d", len(n))
	}
	if len(a.capLogsSnapshot()) == 0 {
		t.Error("抓包日志为空")
	}
}
