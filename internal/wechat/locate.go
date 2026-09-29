// Package wechat 负责定位并枚举 PC 微信本地缓存中的小程序包。
package wechat

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"wxsec/internal/wxapkg"
)

// RootInfo 描述一个候选缓存根目录的探测结果。
type RootInfo struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Exists bool   `json:"exists"`
	Note   string `json:"note"`
}

// PackageRef 表示按 AppID 聚合后的一组小程序包文件。
type PackageRef struct {
	AppID     string   `json:"appId"`
	Versions  []string `json:"versions"`
	Files     []string `json:"files"`
	TotalSize int64    `json:"totalSize"`
	LatestMod int64    `json:"latestMod"`
	Encrypted bool     `json:"encrypted"`
	Source    string   `json:"source"`
}

// CandidateRoots 返回当前系统上所有已知的小程序缓存位置。
func CandidateRoots() []RootInfo {
	var roots []RootInfo

	add := func(label, path string) {
		if path == "" {
			return
		}
		st, err := os.Stat(path)
		roots = append(roots, RootInfo{
			Path:   path,
			Label:  label,
			Exists: err == nil && st.IsDir(),
			Note:   statNote(err),
		})
	}

	if home, err := os.UserHomeDir(); err == nil {
		// 微信 3.x：文档目录下的 WeChat Files/Applet
		for _, doc := range []string{
			filepath.Join(home, "Documents", "WeChat Files"),
			filepath.Join(home, "OneDrive", "Documents", "WeChat Files"),
		} {
			add("微信 3.x (WeChat Files)", filepath.Join(doc, "Applet"))
		}
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			add("微信 3.x (PC 运行数据)", filepath.Join(local, "Tencent", "WeChat", "Applet"))
		}
		if roaming := os.Getenv("APPDATA"); roaming != "" {
			// 微信 4.x (xwechat) 把小程序放在 roaming 目录下
			add("微信 4.x (xwechat packages)", filepath.Join(roaming, "Tencent", "xwechat", "radium", "Applet", "packages"))
			if users, err := os.ReadDir(filepath.Join(roaming, "Tencent", "xwechat", "radium", "users")); err == nil {
				for _, u := range users {
					if u.IsDir() {
						add("微信 4.x (xwechat 多用户)", filepath.Join(roaming, "Tencent", "xwechat", "radium", "users", u.Name(), "applet", "packages"))
					}
				}
			}
		}
	}

	roots = append(roots, registryRoots()...)
	return dedupeRoots(roots)
}

func statNote(err error) string {
	if err == nil {
		return ""
	}
	if os.IsNotExist(err) {
		return "目录不存在"
	}
	return err.Error()
}

func dedupeRoots(in []RootInfo) []RootInfo {
	seen := map[string]bool{}
	out := make([]RootInfo, 0, len(in))
	for _, r := range in {
		key := strings.ToLower(filepath.Clean(r.Path))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

// DiscoverPackages 在给定根目录下递归查找 .wxapkg，并按 AppID 聚合。
// 目录层级通常为 {root}/{appid}/{version}/{name}.wxapkg。
func DiscoverPackages(root string) ([]PackageRef, error) {
	type agg struct {
		item *PackageRef
		vers map[string]bool
	}
	groups := map[string]*agg{}
	var order []string

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 权限不足的子目录直接跳过
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".wxapkg") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}

		appid := appidFromPath(p)
		if appid == "" {
			appid = "unknown"
		}
		version := versionFromPath(p, root, appid)

		g := groups[appid]
		if g == nil {
			g = &agg{item: &PackageRef{AppID: appid, Source: root}, vers: map[string]bool{}}
			groups[appid] = g
			order = append(order, appid)
		}
		g.item.Files = append(g.item.Files, p)
		g.item.TotalSize += info.Size()
		if info.ModTime().Unix() > g.item.LatestMod {
			g.item.LatestMod = info.ModTime().Unix()
		}
		if version != "" {
			g.vers[version] = true
		}
		if g.item.Encrypted {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		head := make([]byte, 6)
		if _, err := f.Read(head); err == nil && string(head) == "V1MMWX" {
			g.item.Encrypted = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]PackageRef, 0, len(order))
	for _, id := range order {
		g := groups[id]
		for v := range g.vers {
			g.item.Versions = append(g.item.Versions, v)
		}
		sort.Strings(g.item.Versions)
		sort.Strings(g.item.Files)
		out = append(out, *g.item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LatestMod > out[j].LatestMod })
	return out, nil
}

func appidFromPath(path string) string {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if wxapkg.IsAppID(seg) {
			return seg
		}
	}
	return ""
}

func versionFromPath(path, root, appid string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	segs := strings.Split(filepath.ToSlash(rel), "/")
	for i, s := range segs {
		if s == appid && i+1 < len(segs)-1 {
			return segs[i+1]
		}
	}
	return ""
}
