//go:build !windows

package proxy

import "errors"

var errWindowsOnlyCA = errors.New("根证书安装仅支持 Windows，其它系统请手动把证书装入系统信任存储")

// InstallRootCA 仅在 Windows 下通过 certutil 写入当前用户信任存储。
func InstallRootCA(_ string) error { return errWindowsOnlyCA }

// UninstallRootCA 从系统信任存储中移除根证书。
func UninstallRootCA(_ string, _ []byte) error { return errWindowsOnlyCA }

// RootCAInstalled 判断根证书是否已被系统信任。
func RootCAInstalled(_ []byte) bool { return false }
