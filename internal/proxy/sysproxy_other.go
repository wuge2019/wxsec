//go:build !windows

package proxy

import "errors"

// SysProxySnapshot 在非 Windows 平台仅用于保持类型一致。
type SysProxySnapshot struct {
	Enable bool   `json:"enable"`
	Server string `json:"server"`
	Bypass string `json:"bypass"`
}

// SysProxyState 是非 Windows 平台的占位状态。
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

var errWindowsOnly = errors.New("系统代理接管仅支持 Windows")

func ReadSystemProxy() (*SysProxyState, error) { return nil, errWindowsOnly }

func EnableSystemProxy(_ string, _ int) (*SysProxyState, error) { return nil, errWindowsOnly }

func RestoreSystemProxy(_ string) (*SysProxyState, error) { return nil, errWindowsOnly }

func SysProxyStateWithBackup(_ string) (*SysProxyState, error) { return nil, errWindowsOnly }

func HasSystemProxyBackup(_ string) bool { return false }
