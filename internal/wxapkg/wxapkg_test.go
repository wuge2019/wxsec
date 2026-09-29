package wxapkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// pack 构造一个 v2 布局的明文 .wxapkg，供解析与解包测试使用。
// 布局：header(18) | index | body，因此文件偏移需要先算出索引区长度。
func pack(t *testing.T, files map[string][]byte, order []string) []byte {
	t.Helper()
	const headerSize = 18

	indexSize := 0
	for _, name := range order {
		indexSize += 4 + len(name) + 8
	}
	bodyStart := headerSize + indexSize

	var index bytes.Buffer
	var body bytes.Buffer
	cursor := bodyStart
	for _, name := range order {
		data := files[name]
		_ = binary.Write(&index, binary.BigEndian, uint32(len(name)))
		_, _ = index.WriteString(name)
		_ = binary.Write(&index, binary.BigEndian, uint32(cursor))
		_ = binary.Write(&index, binary.BigEndian, uint32(len(data)))
		body.Write(data)
		cursor += len(data)
	}

	out := make([]byte, 0, bodyStart+body.Len())
_scratch := make([]byte, 4)
	binary.BigEndian.PutUint32(_scratch, uint32(indexSize))
	indexLen := append([]byte(nil), _scratch...)
	binary.BigEndian.PutUint32(_scratch, uint32(body.Len()))
	bodyLen := append([]byte(nil), _scratch...)

	out = append(out, MarkFirst)
	out = append(out, 0x00, 0x00, 0x00, 0x01) // info1
	out = append(out, indexLen...)
	out = append(out, bodyLen...)
	out = append(out, MarkLast)
	binary.BigEndian.PutUint32(_scratch, uint32(len(order)))
	out = append(out, _scratch...)
	out = append(out, index.Bytes()...)
	out = append(out, body.Bytes()...)
	return out
}

func TestParseAndUnpack(t *testing.T) {
	files := map[string][]byte{
		"/app.js":              []byte(`App({onLaunch(){console.log("hi")}})`),
		"/app.json":            []byte(`{"pages":["pages/index/index"],"window":{"navigationBarTitleText":"演示"}}`),
		"/pages/index/index.js": []byte(`Page({data:{a:1}})`),
		"/assets/logo.png":     {0x89, 'P', 'N', 'G', 0, 1, 2, 3},
	}
	order := []string{"/app.js", "/app.json", "/pages/index/index.js", "/assets/logo.png"}
	data := pack(t, files, order)

	pkg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkg.Layout != "v2" || len(pkg.Files) != 4 {
		t.Fatalf("unexpected parse result: %+v", pkg)
	}

	out := t.TempDir()
	res, err := UnpackBytes(data, "sample.wxapkg", Options{OutDir: out, AppID: "wx0123456789abcdef"})
	if err != nil {
		t.Fatalf("UnpackBytes: %v", err)
	}
	if len(res.Files) != 4 {
		t.Fatalf("expected 4 written files, got %d", len(res.Files))
	}

	got, err := os.ReadFile(filepath.Join(out, "pages", "index", "index.js"))
	if err != nil {
		t.Fatalf("nested path not restored: %v", err)
	}
	if !bytes.Equal(got, files["/pages/index/index.js"]) {
		t.Fatalf("content mismatch: %q", got)
	}

	// JSON 美化应改变字节数但保持语义
	res2, err := UnpackBytes(data, "sample.wxapkg", Options{OutDir: t.TempDir(), Beautify: true, AppID: "wx0123456789abcdef"})
	if err != nil {
		t.Fatalf("beautify unpack: %v", err)
	}
	beautified, _ := os.ReadFile(filepath.Join(res2.Files[1].Path))
	if bytes.Equal(beautified, files["/app.json"]) || !bytes.Contains(beautified, []byte("\n")) {
		t.Fatalf("json not beautified: %q", beautified)
	}
}

func TestUnpackBlocksPathTraversal(t *testing.T) {
	// 包内条目名带 ../ 与 Windows 非法字符
	files := map[string][]byte{
		"/../evil.js":   []byte(`alert(1)`),
		"/a<b>bad.js":   []byte(`x`),
		"/pages/ok.js":  []byte(`ok`),
	}
	data := pack(t, files, []string{"/../evil.js", "/pages/ok.js"})
	out := t.TempDir()
	res, err := UnpackBytes(data, "x.wxapkg", Options{OutDir: out, AppID: "wx0123456789abcdef"})
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	entries, _ := filepath.Glob(filepath.Join(filepath.Dir(out), "evil.js"))
	if len(entries) > 0 {
		t.Fatalf("traversal wrote file outside out dir: %v", entries)
	}
	for _, f := range res.Files {
		if f.Skipped {
			continue
		}
		if !within(f.Path, out) {
			t.Fatalf("unsafe write target %s", f.Path)
		}
	}
}

func TestSanitizeRelPath(t *testing.T) {
	cases := map[string]string{
		"/app.js":              "app.js",
		"/pages/a/a.wxml":      "pages/a/a.wxml",
		"..":                   "",
		"/../../etc/passwd":    "etc/passwd",
		"/con.txt":             "_con.txt",
		"/a:b/c*.js":           "a_b/c_.js",
		"///weird///name.json": "weird/name.json",
	}
	for in, want := range cases {
		if got := sanitizeRelPath(in); got != want {
			t.Errorf("sanitizeRelPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// encryptV1 按 PC 微信 3.x 的方案加密明文包，用于解密往返测试。
func encryptV1(t *testing.T, plain []byte, appid string) []byte {
	t.Helper()
	dk := pbkdf2.Key([]byte(appid), []byte(v1Salt), v1Iterations, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		t.Fatal(err)
	}

	head := make([]byte, v1HeaderPlain)
	copy(head, plain[:v1HeaderPlain-1])

	enc := make([]byte, v1MagicLen+len(head)+len(plain)-(v1HeaderPlain-1))
	copy(enc, magicV1)
	cipher.NewCBCEncrypter(block, []byte(v1IV)).CryptBlocks(enc[v1MagicLen:], head)

	xorKey := appid[len(appid)-2]
	tail := plain[v1HeaderPlain-1:]
	pos := v1MagicLen + len(head)
	for i, b := range tail {
		enc[pos+i] = b ^ xorKey
	}
	return enc
}

func TestDecryptV1RoundTrip(t *testing.T) {
	const appid = "wx0123456789abcdef"
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	plain := append(pack(t, map[string][]byte{"/a.js": body}, []string{"/a.js"}), 0, 0)

	enc := encryptV1(t, plain, appid)
	if got := DetectEncryption(enc); got != EncryptionV1 {
		t.Fatalf("DetectEncryption = %q", got)
	}

	out, err := Decrypt(enc, appid)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("round trip mismatch: len %d vs %d", len(out), len(plain))
	}

	if _, err := Decrypt(enc, "wxffffffffffffff"); err == nil {
		t.Fatal("expected error for wrong appid")
	}
	if _, err := Decrypt(enc, ""); err == nil {
		t.Fatal("expected error for empty appid")
	}
}

func TestUnpackEncryptedFile(t *testing.T) {
	const appid = "wxabcdee0123456789"
	body := make([]byte, 3000)
	for i := range body {
		body[i] = byte(i)
	}
	plain := pack(t, map[string][]byte{"/app-service.js": body}, []string{"/app-service.js"})
	enc := encryptV1(t, plain, appid)

	src := filepath.Join(t.TempDir(), appid, "220", "x.wxapkg")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, enc, 0o644); err != nil {
		t.Fatal(err)
	}
	// 未显式给 AppID 时应从目录结构推断
	res, err := UnpackFile(src, Options{OutDir: t.TempDir()})
	if err != nil {
		t.Fatalf("UnpackFile: %v", err)
	}
	if !res.Decrypted || res.AppID != appid {
		t.Fatalf("expected decrypted result with inferred appid, got %+v", res)
	}
	if len(res.Files) != 1 || res.Files[0].Size != len(body) {
		t.Fatalf("unexpected files: %+v", res.Files)
	}
}

func TestRejectGarbage(t *testing.T) {
	if _, err := Parse(bytes.Repeat([]byte{0}, 100)); err == nil {
		t.Fatal("expected parse error for zero-filled data")
	}
	if _, err := Parse([]byte{MarkFirst, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}); err == nil {
		t.Fatal("expected parse error for truncated header")
	}
}

func TestIsAppID(t *testing.T) {
	if !IsAppID("wx0123456789abcdef") {
		t.Error("valid appid rejected")
	}
	for _, bad := range []string{"wx0123", "wx0123456789abcdeg", "", "xx0123456789abcdef"} {
		if IsAppID(bad) {
			t.Errorf("accepted invalid appid %q", bad)
		}
	}
}
