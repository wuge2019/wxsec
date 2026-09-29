package wxapkg

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Options 控制解包行为。
type Options struct {
	// AppID 用于加密包派生解密密钥；明文包可留空。
	AppID string
	// OutDir 为解包输出目录。
	OutDir string
	// Beautify 为 true 时对 .js/.json 做格式化输出。
	Beautify bool
	// Restore 为 true 时对打平的新版包执行静态工程还原。
	Restore bool
	// Progress 每写出一个文件回调一次，done/total 用于进度条。
	Progress func(current, total int, name string)
}

// WrittenFile 描述一个已写出的文件。
type WrittenFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int    `json:"size"`
	Skipped bool `json:"skipped"`
	Reason string `json:"reason"`
}

// UnpackResult 是一次解包的汇总信息。
type UnpackResult struct {
	Source     string        `json:"source"`
	Layout     string        `json:"layout"`
	Decrypted  bool          `json:"decrypted"`
	AppID      string        `json:"appId"`
	Files      []WrittenFile `json:"files"`
	TotalBytes int64         `json:"totalBytes"`
	Restored   *RestoreResult `json:"restored,omitempty"`
}

// UnpackBytes 从内存中的包数据解包到 outDir。
func UnpackBytes(data []byte, source string, opt Options) (*UnpackResult, error) {
	appid := strings.TrimSpace(opt.AppID)
	if appid == "" {
		appid = appidFromPath(source)
	}
	kind := DetectEncryption(data)

	plain, err := Decrypt(data, appid)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", source, err)
	}

	pkg, err := Parse(plain)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	if err := os.MkdirAll(opt.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	res := &UnpackResult{
		Source:    source,
		Layout:    pkg.Layout,
		Decrypted: kind != EncryptionNone,
		AppID:     appid,
		Files:     make([]WrittenFile, 0, len(pkg.Files)),
	}

	total := len(pkg.Files)
	for i, e := range pkg.Files {
		raw := plain[e.Offset : e.Offset+e.Size]
		name := sanitizeRelPath(e.Name)
		if name == "" {
			res.Files = append(res.Files, WrittenFile{Name: e.Name, Skipped: true, Reason: "unsafe path"})
			emitProgress(opt.Progress, i+1, total, e.Name)
			continue
		}

		out := filepath.Join(opt.OutDir, filepath.FromSlash(name))
		if !within(out, opt.OutDir) {
			res.Files = append(res.Files, WrittenFile{Name: e.Name, Skipped: true, Reason: "path traversal blocked"})
			emitProgress(opt.Progress, i+1, total, e.Name)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return res, fmt.Errorf("mkdir for %s: %w", name, err)
		}

		payload := raw
		if opt.Beautify {
			payload = Beautify(name, raw)
		}
		// 同名条目（多包合并时常见）追加序号，避免相互覆盖。
		out = uniquePath(out)
		if err := os.WriteFile(out, payload, 0o644); err != nil {
			return res, fmt.Errorf("write %s: %w", name, err)
		}

		res.TotalBytes += int64(len(payload))
		res.Files = append(res.Files, WrittenFile{Name: name, Path: out, Size: len(payload)})
		emitProgress(opt.Progress, i+1, total, name)
	}

	if opt.Restore {
		rr, err := Restore(opt.OutDir)
		if err != nil {
			res.Files = append(res.Files, WrittenFile{Name: "(restore)", Skipped: true, Reason: err.Error()})
		} else {
			res.Restored = rr
		}
	}

	return res, nil
}

// UnpackFile 读取磁盘上的 .wxapkg 并解包。
func UnpackFile(path string, opt Options) (*UnpackResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return UnpackBytes(data, path, opt)
}

// Inspect 只解析头部结构，用于在 GUI 中预览包内容与加密状态。
func Inspect(path string, appid string) (*Package, EncryptionKind, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", 0, err
	}
	kind := DetectEncryption(data)
	if appid == "" {
		appid = appidFromPath(path)
	}
	plain, err := Decrypt(data, appid)
	if err != nil {
		return nil, kind, int64(len(data)), err
	}
	pkg, err := Parse(plain)
	if err != nil {
		return nil, kind, int64(len(data)), err
	}
	return pkg, kind, int64(len(data)), nil
}

func emitProgress(fn func(int, int, string), cur, total int, name string) {
	if fn != nil {
		fn(cur, total, name)
	}
}

// appidFromPath 从微信缓存目录结构中推断 appid（形如 .../Applet/wx0123456789abcdef/1234/x.wxapkg）。
func appidFromPath(path string) string {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if IsAppID(seg) {
			return seg
		}
	}
	return ""
}

// IsAppID 判断字符串是否为小程序 AppID（wx + 16 位十六进制）。
func IsAppID(s string) bool {
	if len(s) != 18 || !strings.HasPrefix(s, "wx") {
		return false
	}
	for _, r := range s[2:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// sanitizeRelPath 归一化包内路径：去掉前导斜杠、丢弃可疑片段、替换 Windows 非法字符。
func sanitizeRelPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return ""
	}
	parts := strings.Split(name, "/")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		var b strings.Builder
		for _, r := range p {
			switch r {
			case ':', '*', '?', '"', '<', '>', '|', 0x00:
				b.WriteRune('_')
			default:
				b.WriteRune(r)
			}
		}
		s := b.String()
		if isWindowsReserved(s) {
			s = "_" + s
		}
		clean = append(clean, s)
	}
	if len(clean) == 0 {
		return ""
	}
	return strings.Join(clean, "/")
}

func isWindowsReserved(s string) bool {
	switch strings.ToUpper(strings.SplitN(s, ".", 2)[0]) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
		"COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5":
		return true
	}
	return false
}

// within 判断目标路径是否落在 root 之内（防目录穿越）。
func within(target, root string) bool {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	prefix := absRoot + string(filepath.Separator)
	return absTarget == absRoot || strings.HasPrefix(absTarget, prefix)
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; i < 10000; i++ {
		candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return base + "_x" + ext
}

// WalkSources 收集目录下的全部 .wxapkg 文件。
func WalkSources(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".wxapkg") {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}
