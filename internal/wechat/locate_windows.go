//go:build windows

package wechat

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// registryRoots 读取微信 3.x 自定义存储路径（HKCU\Software\Tencent\WeChat\FileSavePath）。
func registryRoots() []RootInfo {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Tencent\WeChat`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	value, _, err := key.GetStringValue("FileSavePath")
	if err != nil || value == "" {
		return nil
	}
	if value == "MyDocument:" {
		if home, err := os.UserHomeDir(); err == nil {
			value = filepath.Join(home, "Documents")
		}
	}

	path := filepath.Join(value, "WeChat Files", "Applet")
	st, err := os.Stat(path)
	return []RootInfo{{
		Path:   path,
		Label:  "微信 3.x (注册表自定义路径)",
		Exists: err == nil && st.IsDir(),
		Note:   statNote(err),
	}}
}
