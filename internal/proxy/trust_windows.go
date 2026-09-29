//go:build windows

package proxy

import (
	"crypto/sha1"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// InstallRootCA 把根证书装入当前用户的受信任根存储（不需要管理员权限）。
func InstallRootCA(certPath string) error {
	out, err := runCertutil("-addstore", "-user", "Root", certPath)
	if err != nil {
		if strings.Contains(out, "已存在") || strings.Contains(out, "already in store") || strings.Contains(out, "EXISTING_OBJECT") {
			return nil
		}
		return fmt.Errorf("certutil -addstore: %w（输出：%s）", err, firstLine(out))
	}
	return nil
}

// UninstallRootCA 按证书指纹从当前用户存储中删除根证书。
func UninstallRootCA(certPath string, der []byte) error {
	thumb := thumbprint(der)
	out, err := runCertutil("-delstore", "-user", "Root", thumb)
	if err != nil {
		if strings.Contains(out, "cannot find") || strings.Contains(out, "找不到") {
			return nil
		}
		return fmt.Errorf("certutil -delstore: %w（输出：%s）", err, firstLine(out))
	}
	return nil
}

// RootCAInstalled 判断该根证书是否已在当前用户受信任根存储中。
func RootCAInstalled(der []byte) bool {
	out, err := runCertutil("-verifystore", "-user", "Root", thumbprint(der))
	return err == nil && strings.Contains(out, "Root")
}

func thumbprint(der []byte) string {
	sum := sha1.Sum(der)
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	for _, x := range sum {
		b.WriteByte(hexDigits[x>>4])
		b.WriteByte(hexDigits[x&0xf])
	}
	return strings.ToUpper(b.String())
}

// runCertutil 执行 certutil：只使用固定参数，绝不拼接外部输入，避免命令注入。
func runCertutil(args ...string) (string, error) {
	cmd := exec.Command("certutil", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
