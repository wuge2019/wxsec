package cross

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"wxsec/internal/proxy"
	"wxsec/internal/scanner"
)

// 分类常量：动态与静态两种来源的交叉结果。
const (
	CatBoth     = "both"      // 包内声明过，且实际发出过请求
	CatDynamic  = "dynamic"   // 只在流量里出现（下发配置、其他来源、运行时拼接）
	CatStatic   = "static"    // 只在包内出现（本次未触发）
	CatHostOnly = "host-only" // 动态侧只解出域名，未拿到路径
)

// Row 是一条 URL 对照记录（按 域名+路径 归并，不含查询参数）。
type Row struct {
	Key          string   `json:"key"`
	Host         string   `json:"host"`
	Path         string   `json:"path"`
	Scheme       string   `json:"scheme"`
	Category     string   `json:"category"`
	Methods      []string `json:"methods"`
	Statuses     []int    `json:"statuses"`
	QueryKeys    []string `json:"queryKeys"`
	AppIDs       []string `json:"appIds"`
	StaticFiles  []string `json:"staticFiles"`
	StaticCount  int      `json:"staticCount"`
	DynamicCount int      `json:"dynamicCount"`
	SDK          string   `json:"sdk"`
	Sample       string   `json:"sample"`
	Pattern      bool     `json:"pattern"` // 静态侧是含模板变量的路径
	Notes        []string `json:"notes"`
}

// HostStat 是按域名聚合的概览。
type HostStat struct {
	Host          string   `json:"host"`
	DynamicCount  int      `json:"dynamicCount"`
	StaticCount   int      `json:"staticCount"`
	Paths         int      `json:"paths"`
	AppIDs        []string `json:"appIds"`
	SDK           string   `json:"sdk"`
	EncryptedOnly bool     `json:"encryptedOnly"` // 该域名只有未解密的 CONNECT 记录
}

// Report 是抓包与静态资产的完整对照结果。
type Report struct {
	GeneratedAt  time.Time      `json:"generatedAt"`
	ScanRoot     string         `json:"scanRoot"`
	FlowTotal    int            `json:"flowTotal"`
	AssetTotal   int            `json:"assetTotal"`
	Rows         []Row          `json:"rows"`
	Hosts        []HostStat     `json:"hosts"`
	Stats        map[string]int `json:"stats"`
	DynamicHosts []string       `json:"dynamicHosts"`
	StaticHosts  []string       `json:"staticHosts"`
}

type staticInfo struct {
	host    string
	path    string
	files   map[string]int
	count   int
	sdk     string
	scheme  string
	pattern bool
	segs    []string
}

func (s *staticInfo) key() string { return key(s.host, s.path) }

type dynInfo struct {
	count     int
	methods   map[string]bool
	statuses  map[int]bool
	queryKeys map[string]bool
	appIDs    map[string]bool
	sample    string
	scheme    string
	plain     bool
}

// Analyze 把抓包记录与静态扫描出的接口资产按 域名+路径 归并比对。
func Analyze(flows []proxy.Flow, assets []scanner.Asset, sdkAssets []scanner.Asset, scanRoot string) *Report {
	res := &Report{
		GeneratedAt: time.Now(),
		ScanRoot:    scanRoot,
		FlowTotal:   len(flows),
		AssetTotal:  len(assets) + len(sdkAssets),
		Stats:       map[string]int{},
	}

	staticIdx := map[string]*staticInfo{}
	var patterns []*staticInfo
	addStatic := func(a scanner.Asset, sdk string) {
		host, path, ok := splitURL(a.URL)
		if !ok {
			return
		}
		si := staticIdx[key(host, path)]
		if si == nil {
			si = &staticInfo{
				host:    host,
				path:    path,
				files:   map[string]int{},
				scheme:  schemeOf(a.URL),
				sdk:     sdk,
				pattern: isPatternPath(path),
			}
			if si.pattern {
				si.segs = patternSegs(path)
				patterns = append(patterns, si)
			}
			staticIdx[key(host, path)] = si
		}
		si.count += max(a.Count, 1)
		if a.File != "" {
			si.files[a.File] += max(a.Count, 1)
		}
	}
	for _, a := range assets {
		addStatic(a, "")
	}
	for _, a := range sdkAssets {
		addStatic(a, a.SDK)
	}

	dynIdx := map[string]*dynInfo{}
	hostOnly := map[string]*dynInfo{}
	for _, f := range flows {
		host := strings.ToLower(f.Host)
		if host == "" {
			continue
		}
		if f.Path == "" {
			// CONNECT-only：只有域名级信息，单独归档，不参与路径比对。
			d := hostOnly[host]
			if d == nil {
				d = &dynInfo{methods: map[string]bool{}, statuses: map[int]bool{}, queryKeys: map[string]bool{}, appIDs: map[string]bool{}, scheme: "https"}
				hostOnly[host] = d
			}
			d.count++
			if f.AppID != "" {
				d.appIDs[f.AppID] = true
			}
			continue
		}
		path := normalizePath(f.Path)
		k := key(host, path)
		d := dynIdx[k]
		if d == nil {
			d = &dynInfo{
				methods:   map[string]bool{},
				statuses:  map[int]bool{},
				queryKeys: map[string]bool{},
				appIDs:    map[string]bool{},
				sample:    f.URL,
				scheme:    f.Scheme,
			}
			dynIdx[k] = d
		}
		d.count++
		d.methods[f.Method] = true
		if f.Status != 0 {
			d.statuses[f.Status] = true
		}
		for _, k2 := range queryKeys(f.Query) {
			d.queryKeys[k2] = true
		}
		if f.AppID != "" {
			d.appIDs[f.AppID] = true
		}
		if f.Scheme == "http" {
			d.plain = true
		}
	}

	exactHit := map[string]bool{}
	patternHit := map[*staticInfo]bool{}
	// 先精确匹配，再用含模板变量的静态路径做段级匹配。
	for k, d := range dynIdx {
		host, path := hostOf(k), pathOf(k)
		if si, ok := staticIdx[k]; ok {
			exactHit[k] = true
			res.addRow(k, host, path, CatBoth, d, si, false)
			continue
		}
		if si := matchPattern(host, path, patterns); si != nil {
			patternHit[si] = true
			res.addRow(k, host, path, CatBoth, d, si, true)
			continue
		}
		res.addRow(k, host, path, CatDynamic, d, nil, false)
	}
	for k, si := range staticIdx {
		if exactHit[k] || patternHit[si] {
			continue
		}
		res.addRow(k, hostOf(k), pathOf(k), CatStatic, nil, si, false)
	}
	for host, d := range hostOnly {
		if _, hasPath := dynHostHasPath(dynIdx, host); hasPath {
			continue
		}
		res.addRow(key(host, ""), host, "", CatHostOnly, d, staticIdx[key(host, "")], false)
	}

	sort.Slice(res.Rows, func(i, j int) bool {
		a, b := res.Rows[i], res.Rows[j]
		if rank(a.Category) != rank(b.Category) {
			return rank(a.Category) < rank(b.Category)
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Path < b.Path
	})
	res.buildHosts(staticIdx, dynIdx, hostOnly)
	res.finalize()
	return res
}

func (r *Report) addRow(k, host, path, cat string, d *dynInfo, si *staticInfo, pattern bool) {
	row := Row{
		Key:      k,
		Host:     host,
		Path:     path,
		Category: cat,
		Pattern:  pattern,
	}
	if d != nil {
		row.DynamicCount = d.count
		row.Methods = sortedKeys(d.methods)
		row.AppIDs = sortedKeys(d.appIDs)
		row.QueryKeys = sortedKeys(d.queryKeys)
		row.Sample = d.sample
		row.Scheme = d.scheme
		for s := range d.statuses {
			row.Statuses = append(row.Statuses, s)
		}
		sort.Ints(row.Statuses)
		if d.plain {
			row.Notes = append(row.Notes, "明文 HTTP 传输")
		}
	}
	if si != nil {
		row.StaticCount = si.count
		if row.Scheme == "" {
			row.Scheme = si.scheme
		}
		row.SDK = si.sdk
		for _, f := range sortedCountKeys(si.files) {
			if len(row.StaticFiles) < 8 {
				row.StaticFiles = append(row.StaticFiles, f)
			}
		}
	}
	switch cat {
	case CatBoth:
		if pattern {
			row.Notes = append(row.Notes, "静态侧为模板路径，按段匹配")
		}
	case CatDynamic:
		row.Notes = append(row.Notes, "包内未直接声明该路径")
	case CatStatic:
		row.Notes = append(row.Notes, "本次抓包未触发")
		if si != nil && si.pattern {
			row.Notes = append(row.Notes, "静态侧为模板路径，未匹配到动态请求")
		}
	case CatHostOnly:
		row.Notes = append(row.Notes, "仅记录到域名（未解密或握手失败）")
	}
	if row.StaticFiles == nil {
		row.StaticFiles = []string{}
	}
	if row.Notes == nil {
		row.Notes = []string{}
	}
	r.Rows = append(r.Rows, row)
}

func (r *Report) buildHosts(staticIdx map[string]*staticInfo, dynIdx map[string]*dynInfo, hostOnly map[string]*dynInfo) {
	type acc struct {
		dyn, stat, paths int
		appIDs           map[string]bool
		sdk              string
		hostOnly         bool
	}
	m := map[string]*acc{}
	get := func(h string) *acc {
		a := m[h]
		if a == nil {
			a = &acc{appIDs: map[string]bool{}}
			m[h] = a
		}
		return a
	}
	for k, d := range dynIdx {
		h := hostOf(k)
		a := get(h)
		a.dyn += d.count
		a.paths++
		for id := range d.appIDs {
			a.appIDs[id] = true
		}
	}
	for k, si := range staticIdx {
		h := hostOf(k)
		a := get(h)
		a.stat += si.count
		a.paths++
		a.sdk = si.sdk
	}
	for h, d := range hostOnly {
		a := get(h)
		a.dyn += d.count
		a.hostOnly = true
		for id := range d.appIDs {
			a.appIDs[id] = true
		}
	}
	for h, a := range m {
		r.Hosts = append(r.Hosts, HostStat{
			Host:          h,
			DynamicCount:  a.dyn,
			StaticCount:   a.stat,
			Paths:         a.paths,
			AppIDs:        sortedKeys(a.appIDs),
			SDK:           a.sdk,
			EncryptedOnly: a.hostOnly && a.paths > 0 && a.dyn > 0,
		})
	}
	sort.Slice(r.Hosts, func(i, j int) bool {
		if r.Hosts[i].DynamicCount != r.Hosts[j].DynamicCount {
			return r.Hosts[i].DynamicCount > r.Hosts[j].DynamicCount
		}
		return r.Hosts[i].Host < r.Hosts[j].Host
	})
}

func (r *Report) finalize() {
	dh := map[string]bool{}
	sh := map[string]bool{}
	for _, row := range r.Rows {
		if row.DynamicCount > 0 {
			r.Stats[CatDynamic]++
			dh[row.Host] = true
		}
		if row.StaticCount > 0 {
			sh[row.Host] = true
		}
		switch row.Category {
		case CatBoth:
			r.Stats["both"]++
		case CatDynamic:
			r.Stats["dynamicOnly"]++
		case CatStatic:
			r.Stats["staticOnly"]++
		case CatHostOnly:
			r.Stats["hostOnly"]++
		}
	}
	for _, h := range r.Hosts {
		if h.DynamicCount > 0 {
			dh[h.Host] = true
		}
		if h.StaticCount > 0 {
			sh[h.Host] = true
		}
	}
	r.DynamicHosts = boolKeys(dh)
	r.StaticHosts = boolKeys(sh)
	r.Stats["dynamicHosts"] = len(r.DynamicHosts)
	r.Stats["staticHosts"] = len(r.StaticHosts)
	r.Stats["rows"] = len(r.Rows)
}

// matchPattern 用含变量的静态路径匹配动态路径（段数相同、变量段通配）。
func matchPattern(host, path string, patterns []*staticInfo) *staticInfo {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var best *staticInfo
	for _, p := range patterns {
		if p.host != host || len(p.segs) != len(segs) {
			continue
		}
		ok := true
		for i, s := range p.segs {
			if s == "*" {
				continue
			}
			if !strings.EqualFold(s, segs[i]) {
				ok = false
				break
			}
		}
		if ok && (best == nil || len(p.segs) > len(best.segs)) {
			best = p
		}
	}
	return best
}

// splitURL 解析出小写主机名与路径。
func splitURL(raw string) (host, path string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", "", false
	}
	return strings.ToLower(u.Host), normalizePath(u.Path), true
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// isPatternPath 判断静态路径是否含模板变量（编译产物里常见 ${...}、%s、{{...}}）。
func isPatternPath(p string) bool {
	return strings.Contains(p, "${") || strings.Contains(p, "{{") ||
		strings.Contains(p, "%s") || strings.Contains(p, "%d")
}

// patternSegs 把静态路径按段拆开，含变量的段替换成通配符。
func patternSegs(p string) []string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if isPatternPath(s) {
			segs[i] = "*"
		}
	}
	return segs
}

func queryKeys(q string) []string {
	if q == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, kv := range strings.Split(q, "&") {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) >= 30 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func key(host, path string) string { return host + "\x00" + path }

func hostOf(k string) string {
	if i := strings.IndexByte(k, 0); i >= 0 {
		return k[:i]
	}
	return k
}

func pathOf(k string) string {
	if i := strings.IndexByte(k, 0); i >= 0 {
		return k[i+1:]
	}
	return ""
}

func rank(cat string) int {
	switch cat {
	case CatBoth:
		return 0
	case CatDynamic:
		return 1
	case CatHostOnly:
		return 2
	default:
		return 3
	}
}

func dynHostHasPath(dynIdx map[string]*dynInfo, host string) (string, bool) {
	for k := range dynIdx {
		if hostOf(k) == host {
			return k, true
		}
	}
	return "", false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCountKeys(m map[string]int) []string {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.k)
	}
	return out
}

func boolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
