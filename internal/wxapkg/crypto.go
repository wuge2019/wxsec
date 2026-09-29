package wxapkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// 微信 PC 端（3.x）会把小程序包加密，文件头替换为 6 字节魔术值 "V1MMWX"，
// 前 1024 字节用 AES-256-CBC 加密，其余部分用单字节 XOR 混淆。
const (
	magicV1        = "V1MMWX"
	v1MagicLen     = 6
	v1HeaderPlain  = 1024
	v1Salt         = "saltiest"
	v1IV           = "the iv: 16 bytes"
	v1Iterations   = 1000
	v1FallbackXor  = byte(0x66)
	minEncryptedSz = v1MagicLen + v1HeaderPlain
)

// EncryptionKind 描述检测到的加密类型。
type EncryptionKind string

const (
	EncryptionNone EncryptionKind = ""
	EncryptionV1   EncryptionKind = "V1MMWX"
)

// DetectEncryption 返回数据所采用的加密方式。
func DetectEncryption(data []byte) EncryptionKind {
	if len(data) >= v1MagicLen && string(data[:v1MagicLen]) == magicV1 {
		return EncryptionV1
	}
	return EncryptionNone
}

// NeedsKey 表示该加密方式必须提供 appid 作为派生密钥。
func (k EncryptionKind) NeedsKey() bool { return k == EncryptionV1 }

// ErrNeedKey 表示缺少解密密钥。
var ErrNeedKey = errors.New("encrypted package requires the appid as decryption key")

// Decrypt 按检测到的加密方式还原出明文包数据；kind 为 None 时原样返回。
func Decrypt(data []byte, key string) ([]byte, error) {
	switch DetectEncryption(data) {
	case EncryptionNone:
		return data, nil
	case EncryptionV1:
		return decryptV1(data, key)
	}
	return nil, errors.New("unsupported encryption")
}

func decryptV1(data []byte, appid string) ([]byte, error) {
	if appid == "" {
		return nil, ErrNeedKey
	}
	if len(data) < minEncryptedSz {
		return nil, fmt.Errorf("encrypted file too small: %d bytes", len(data))
	}

	dk := pbkdf2.Key([]byte(appid), []byte(v1Salt), v1Iterations, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	// CBC 段长度必须是块大小的整数；对截断文件做向下对齐。
	span := len(data) - v1MagicLen
	if span > v1HeaderPlain {
		span = v1HeaderPlain
	}
	span -= span % aes.BlockSize

	plain := make([]byte, span)
	cipher.NewCBCDecrypter(block, []byte(v1IV)).CryptBlocks(plain, data[v1MagicLen:v1MagicLen+span])

	xorKey := v1FallbackXor
	if len(appid) >= 2 {
		xorKey = appid[len(appid)-2]
	}

	out := make([]byte, 0, len(data)-v1MagicLen)
	out = append(out, plain...)
	// 头部只保留 1023 字节有效数据，第 1024 字节属于 XOR 区的起点。
	if len(out) > v1HeaderPlain-1 {
		out = out[:v1HeaderPlain-1]
	}
	for _, b := range data[v1MagicLen+span:] {
		out = append(out, b^xorKey)
	}

	if !IsPlaintext(out) {
		return nil, fmt.Errorf("decryption produced invalid data (wrong appid?), first byte 0x%02X", out[0])
	}
	return out, nil
}
