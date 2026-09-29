//go:build windows

package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	inetRegKey         = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	optSettingsChanged = 39 // INTERNET_OPTION_SETTINGS_CHANGED
	optRefresh         = 37 // INTERNET_OPTION_REFRESH
)

var (
	wininet             = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptW = wininet.NewProc("InternetSetOptionW")
)

// SysProxySnapshot 是接管前的原始代理设置，用于精确恢复。
type SysProxySnapshot struct {
	Enable bool   `json:"enable"`
	Server string `json:"server"`
	Bypass string `json:"bypass"`
}

// SysProxyState 是系统代理的当前状态与接管情况。
type SysProxyState struct {
	Enabled     bool              `json:"enabled"`
	Server      string            `json:"server"`
	Bypass      string            `json:"bypass"`
	Managed     bool              `json:"managed"`
	ManagedAddr string            `json:"managedAddr"`
	BackupAt    string            `json:"backupAt"`
	Backup      *SysProxySnapshot `json:"backup"`
	BackupPath  string            `json:"backupPath"`
}

// ReadSystemProxy 读取 HKCU 下的 WinINet 代理设置。
func ReadSystemProxy() (*SysProxyState, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetRegKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open internet settings key: %w", err)
	}
	defer k.Close()
	st := &SysProxyState{}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		st.Enabled = v != 0
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		st.Server = v
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		st.Bypass = v
	}
	return st, nil
}

func writeSystemProxy(enable bool, server, bypass string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetRegKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open internet settings key for write: %w", err)
	}
	defer k.Close()
	var val uint32
	if enable {
		val = 1
	}
	if err := k.SetDWordValue("ProxyEnable", val); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", bypass); err != nil {
		return err
	}
	broadcastProxyChange()
	return nil
}

func broadcastProxyChange() {
	// hInternet 传 0 表示对全局生效；这两个选项不需要句柄。
	procInternetSetOptW.Call(0, uintptr(optSettingsChanged), 0, 0)
	procInternetSetOptW.Call(0, uintptr(optRefresh), 0, 0)
}

// EnableSystemProxy 先把当前设置备份到 backupPath，再把系统代理指向 127.0.0.1:port。
// 重复调用不会覆盖首次备份，保证「恢复」一定回到用户原始状态。
func EnableSystemProxy(backupPath string, port int) (*SysProxyState, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("代理端口不合法: %d", port)
	}
	cur, err := ReadSystemProxy()
	if err != nil {
		return nil, err
	}
	bk, err := loadBackup(backupPath)
	if err != nil {
		return nil, err
	}
	if bk == nil {
		bk = &SysProxySnapshot{Enable: cur.Enabled, Server: cur.Server, Bypass: cur.Bypass}
		if err := saveBackup(backupPath, bk); err != nil {
			return nil, err
		}
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := writeSystemProxy(true, addr, "<local>"); err != nil {
		return nil, err
	}
	st, err := ReadSystemProxy()
	if err != nil {
		return nil, err
	}
	st.Managed = true
	st.ManagedAddr = addr
	st.Backup = bk
	st.BackupPath = backupPath
	st.BackupAt = backupMTime(backupPath)
	return st, nil
}

// RestoreSystemProxy 写回备份的原始设置并删除备份文件。
func RestoreSystemProxy(backupPath string) (*SysProxyState, error) {
	bk, err := loadBackup(backupPath)
	if err != nil {
		return nil, err
	}
	if bk == nil {
		st, err := ReadSystemProxy()
		if err != nil {
			return nil, err
		}
		st.BackupPath = backupPath
		return st, errors.New("没有本工具保存的原始代理设置，未做任何修改")
	}
	if err := writeSystemProxy(bk.Enable, bk.Server, bk.Bypass); err != nil {
		return nil, err
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	st, err := ReadSystemProxy()
	if err != nil {
		return nil, err
	}
	st.BackupPath = backupPath
	return st, nil
}

// SysProxyStateWithBackup 返回当前系统代理状态并合并备份文件里的接管信息。
func SysProxyStateWithBackup(backupPath string) (*SysProxyState, error) {
	st, err := ReadSystemProxy()
	if err != nil {
		return nil, err
	}
	st.BackupPath = backupPath
	bk, err := loadBackup(backupPath)
	if err != nil {
		return nil, err
	}
	st.Backup = bk
	st.BackupAt = backupMTime(backupPath)
	if bk != nil {
		st.Managed = st.Server != "" && strings.HasPrefix(st.Server, "127.0.0.1:") && st.Enabled
		st.ManagedAddr = st.Server
	}
	return st, nil
}

// HasSystemProxyBackup 判断是否存在待恢复的接管记录（异常退出后仍可按「恢复」补救）。
func HasSystemProxyBackup(backupPath string) bool {
	bk, err := loadBackup(backupPath)
	return err == nil && bk != nil
}

func loadBackup(path string) (*SysProxySnapshot, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var bk SysProxySnapshot
	if err := json.Unmarshal(b, &bk); err != nil {
		return nil, fmt.Errorf("代理备份文件已损坏，请先手动检查系统代理设置: %w", err)
	}
	return &bk, nil
}

func saveBackup(path string, bk *SysProxySnapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(bk, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func backupMTime(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return st.ModTime().Format(time.RFC3339)
}
