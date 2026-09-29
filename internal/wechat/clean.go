package wechat

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wxsec/internal/wxapkg"
)

// CacheDir 是某个 AppID 在缓存根目录下占用的空间，供删除前展示确认信息。
type CacheDir struct {
	AppID string   `json:"appId"`
	Path  string   `json:"path"`
	Dirs  []string `json:"dirs"`
	Files int      `json:"files"`
	Bytes int64    `json:"bytes"`
}

// LocateCacheDir 定位并统计 AppID 的缓存目录。
func LocateCacheDir(root, appid string) (*CacheDir, error) {
	dirs, err := cacheDirs(root, appid)
	if err != nil {
		return nil, err
	}
	return statCache(dirs, appid)
}

// DeleteCacheDir 删除该 AppID 的全部缓存目录。
// 缓存可由微信重新下载，但删除本身不可撤销，调用方必须先让用户确认。
func DeleteCacheDir(root, appid string) (*CacheDir, error) {
	dirs, err := cacheDirs(root, appid)
	if err != nil {
		return nil, err
	}
	info, err := statCache(dirs, appid)
	if err != nil {
		return nil, err
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return info, fmt.Errorf("删除缓存失败（微信运行时可能占用文件，请先退出微信重试）：%w", err)
		}
	}
	return info, nil
}

// CacheCleanup 是一次批量清除缓存的结果汇总。
type CacheCleanup struct {
	Deleted int      `json:"deleted"`
	Files   int      `json:"files"`
	Bytes   int64    `json:"bytes"`
	Failed  []string `json:"failed"`
}

// DeleteCacheDirs 依次清除多个 AppID 的缓存。
// 单个失败不影响其余条目，失败原因逐条回报，便于界面上复制排查。
func DeleteCacheDirs(root string, appids []string) (*CacheCleanup, error) {
	if len(appids) == 0 {
		return nil, errors.New("未选择任何小程序包")
	}
	res := &CacheCleanup{Failed: []string{}}
	for _, id := range appids {
		info, err := DeleteCacheDir(root, id)
		if err != nil {
			if info != nil && info.Files > 0 {
				res.Failed = append(res.Failed, fmt.Sprintf("%s：%s（已删除部分文件）", id, err.Error()))
				continue
			}
			res.Failed = append(res.Failed, fmt.Sprintf("%s：%s", id, err.Error()))
			continue
		}
		res.Deleted++
		res.Files += info.Files
		res.Bytes += info.Bytes
	}
	return res, nil
}

// cacheDirs 找出 root 下名为 appid 的目录，并逐条校验边界。
// AppID 必须是合法格式，目录必须落在 root 之内且不是符号链接，
// 这样即便调用方传入拼接过的路径也无法跳出缓存树。
func cacheDirs(root, appid string) ([]string, error) {
	if !wxapkg.IsAppID(appid) {
		return nil, fmt.Errorf("AppID 格式不合法，拒绝删除：%s", appid)
	}
	if root == "" {
		return nil, errors.New("缓存根目录为空")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("解析缓存根目录: %w", err)
	}
	st, err := os.Lstat(absRoot)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("缓存根目录不存在：%s", absRoot)
	}

	var found []string
	_ = filepath.WalkDir(absRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() || d.Name() != appid {
			return nil
		}
		rel, rerr := filepath.Rel(absRoot, p)
		if rerr != nil || rel == "." || rel == "" || strings.HasPrefix(rel, "..") {
			return nil
		}
		if lst, lerr := os.Lstat(p); lerr == nil && lst.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		found = append(found, p)
		return filepath.SkipDir
	})
	if len(found) == 0 {
		return nil, fmt.Errorf("未在该根目录下找到 AppID 缓存目录：%s / %s", root, appid)
	}
	return found, nil
}

// statCache 统计目录规模，并要求里面确实存在小程序包——
// 名字凑巧相同的无关目录不会被当成缓存删除。
func statCache(dirs []string, appid string) (*CacheDir, error) {
	info := &CacheDir{AppID: appid, Dirs: dirs, Path: dirs[0]}
	hasPkg := false
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			st, serr := d.Info()
			if serr != nil {
				return nil
			}
			info.Files++
			info.Bytes += st.Size()
			if strings.EqualFold(filepath.Ext(p), ".wxapkg") {
				hasPkg = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("统计缓存目录: %w", err)
		}
	}
	if !hasPkg {
		return nil, fmt.Errorf("目录内未发现 .wxapkg 小程序包，拒绝删除：%s", info.Path)
	}
	return info, nil
}
