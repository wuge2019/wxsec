package wechat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAppID = "wx0123456789abcdef"

// cacheTree 造一棵最小缓存树：{root}/{appid}/{version}/*.wxapkg，
// 外加同级无关目录，用于验证删除只影响目标 AppID。
func cacheTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pkg := filepath.Join(root, testAppID, "16")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "__APP__.wxapkg"), []byte("V1MMWX-fake-package"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, testAppID, "config.json"), []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "wx9999999999999999", "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wx9999999999999999", "1", "__APP__.wxapkg"), []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLocateCacheDir(t *testing.T) {
	root := cacheTree(t)
	info, err := LocateCacheDir(root, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Files != 2 || info.Bytes <= 0 {
		t.Errorf("info = %+v", info)
	}
	if filepath.Base(info.Path) != testAppID {
		t.Errorf("path = %s", info.Path)
	}
	if !strings.HasPrefix(info.Path, filepath.Clean(root)) {
		t.Errorf("path %s escapes root %s", info.Path, root)
	}
}

func TestDeleteCacheDirOnlyRemovesTarget(t *testing.T) {
	root := cacheTree(t)
	info, err := DeleteCacheDir(root, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Files != 2 {
		t.Errorf("deleted files = %d", info.Files)
	}
	if _, err := os.Stat(filepath.Join(root, testAppID)); !os.IsNotExist(err) {
		t.Errorf("target dir still present: %v", err)
	}
	other := filepath.Join(root, "wx9999999999999999", "1", "__APP__.wxapkg")
	if _, err := os.Stat(other); err != nil {
		t.Errorf("sibling package removed by mistake: %v", err)
	}
	// 再删一次应当报错而不是静默成功。
	if _, err := DeleteCacheDir(root, testAppID); err == nil {
		t.Error("expected error when cache dir is already gone")
	}
}

// 非法 AppID 必须被拒绝，避免通过路径拼接删到缓存树之外的东西。
func TestCacheDirsRejectsUnsafeAppID(t *testing.T) {
	root := cacheTree(t)
	for _, bad := range []string{"", "unknown", "..", "../..", "wx0123456789abcdee/", "notanappid"} {
		if _, err := DeleteCacheDir(root, bad); err == nil {
			t.Errorf("DeleteCacheDir(%q) should be rejected", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(root, testAppID)); err != nil {
		t.Errorf("rejected call touched the tree: %v", err)
	}
}

// 批量清除：单条失败不中断整批，失败原因逐条可复制。
func TestDeleteCacheDirsReportsPerItem(t *testing.T) {
	root := cacheTree(t)
	res, err := DeleteCacheDirs(root, []string{testAppID, "wx0000000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 1 || res.Files != 2 {
		t.Errorf("res = %+v", res)
	}
	if len(res.Failed) != 1 || !strings.Contains(res.Failed[0], "未在该根目录下找到") {
		t.Errorf("failed = %v", res.Failed)
	}
	if !strings.HasPrefix(res.Failed[0], "wx0000000000000000：") {
		t.Errorf("failed entry lacks appid: %q", res.Failed[0])
	}
	sibling := filepath.Join(root, "wx9999999999999999", "1", "__APP__.wxapkg")
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("sibling package removed by mistake: %v", err)
	}
	if _, err := DeleteCacheDirs(root, nil); err == nil {
		t.Error("empty selection should be rejected")
	}
}

// 目录名凑巧像 AppID 但没有小程序包时不删。
func TestDeleteRefusesDirWithoutWxapkg(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testAppID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a package"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DeleteCacheDir(root, testAppID); err == nil {
		t.Fatal("expected refusal without .wxapkg")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("dir should survive refused deletion: %v", err)
	}
}

// 缓存根目录本身不存在时给出可展示的中文提示。
func TestLocateMissingRoot(t *testing.T) {
	_, err := LocateCacheDir(filepath.Join(t.TempDir(), "nope"), testAppID)
	if err == nil || !strings.Contains(err.Error(), "缓存根目录不存在") {
		t.Errorf("err = %v", err)
	}
}

// AppID 目录嵌套在更深层时也能定位到。
func TestLocateNestedCacheDir(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "users", "u1", "applet", "packages", testAppID, "1")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "__APP__.wxapkg"), []byte("V1MMWX"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := LocateCacheDir(root, testAppID)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(info.Path) != testAppID || info.Files != 1 {
		t.Errorf("info = %+v", info)
	}
}
