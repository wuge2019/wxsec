// Package wxapkg 实现微信小程序离线包(.wxapkg)的格式解析、解密与解包。
package wxapkg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// MarkFirst 是明文 .wxapkg 文件的首字节魔术值。
	MarkFirst = 0xBE
	// MarkLast 是索引表结束位置的标记字节。
	MarkLast = 0xED

	maxNameLen      = 1024
	maxFileCount    = 200000
	maxSingleFileSz = 64 << 20
)

// Entry 表示包内的一个文件条目，offset/size 指向（解密后的）完整包数据。
type Entry struct {
	Name   string `json:"name"`
	Offset uint32 `json:"offset"`
	Size   uint32 `json:"size"`
}

// Package 是一次解析得到的包结构。
type Package struct {
	// Layout 记录命中的头部布局，便于诊断与日志。
	Layout string `json:"layout"`
	Count  uint32 `json:"count"`
	Files  []Entry `json:"files"`
}

// IsPlaintext 判断数据是否为未加密的 .wxapkg（依据首字节魔术值）。
func IsPlaintext(data []byte) bool {
	return len(data) > 18 && data[0] == MarkFirst
}

// ErrBadFormat 表示数据不符合任何已知的 .wxapkg 布局。
var ErrBadFormat = errors.New("not a valid wxapkg file: no known header layout matched")

type headerLayout struct {
	name    string
	countAt int // fileCount 字段偏移
	skipTo  int // 索引表起始偏移
	shape   int // 每条索引除文件名外的固定字节数（nameLen + offset + size）
}

// 两种历史布局：
// v2（当前主流）: BE | info(4) | indexInfoLen(4) | bodyLen(4) | ED | count(4) | 索引表
// v1（早期版本）  : BE | info(4) | indexInfoLen(4) | nameLen(4) | count(4) | hdrLen(1) | firstOff(4) | ED | 索引表
var layouts = []headerLayout{
	{name: "v2", countAt: 14, skipTo: 18, shape: 12},
	{name: "v1", countAt: 13, skipTo: 23, shape: 12},
}

// Parse 解析包索引表。data 必须是已解密的完整包内容。
func Parse(data []byte) (*Package, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("file too small: %d bytes", len(data))
	}
	if data[0] != MarkFirst {
		return nil, fmt.Errorf("unexpected first mark 0x%02X, want 0x%02X", data[0], MarkFirst)
	}

	var lastErr error
	for _, l := range layouts {
		pkg, err := tryLayout(data, l)
		if err == nil {
			return pkg, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w (last: %v)", ErrBadFormat, lastErr)
}

func u32(data []byte, at int) uint32 {
	if at+4 > len(data) {
		return 0
	}
	return binary.BigEndian.Uint32(data[at:])
}

func tryLayout(data []byte, l headerLayout) (*Package, error) {
	count := u32(data, l.countAt)
	if count == 0 || count > maxFileCount {
		return nil, fmt.Errorf("layout %s: implausible file count %d", l.name, count)
	}

	pos := l.skipTo
	entries := make([]Entry, 0, count)
	for i := uint32(0); i < count; i++ {
		nameLen := int(u32(data, pos))
		pos += 4
		if nameLen <= 0 || nameLen > maxNameLen || pos+nameLen+l.shape-4 > len(data) {
			return nil, fmt.Errorf("layout %s: bad name length %d at entry %d", l.name, nameLen, i)
		}
		name := string(data[pos : pos+nameLen])
		if !validName(name) {
			return nil, fmt.Errorf("layout %s: bad file name %q at entry %d", l.name, name, i)
		}
		pos += nameLen

		offset := u32(data, pos)
		size := u32(data, pos+4)
		pos += l.shape - 4

		if int64(offset)+int64(size) > int64(len(data)) || size > maxSingleFileSz {
			return nil, fmt.Errorf("layout %s: entry %q out of range (offset=%d size=%d len=%d)", l.name, name, offset, size, len(data))
		}
		entries = append(entries, Entry{Name: name, Offset: offset, Size: size})
	}

	// 索引表之后紧接文件数据区；两种布局的 skipTo 计算方式不同，
	// 因此这里不再强校验尾部标记，只要求条目按 offset 单调递增。
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Offset < entries[j].Offset })

	return &Package{Layout: l.name, Count: count, Files: entries}, nil
}

// validName 只做廉价的结构性校验（用于判定头部是否被正确解读）；
// 真正的路径安全由 sanitizeRelPath + within 在写文件时保证。
func validName(name string) bool {
	if name == "" || name == "." || !utf8.ValidString(name) {
		return false
	}
	if strings.IndexByte(name, 0) >= 0 {
		return false
	}
	return strings.HasPrefix(name, "/") || strings.Contains(name, "/")
}

// Data 返回条目对应的原始字节（切片借用，调用方不得修改）。
func (p *Package) Data(data []byte, e Entry) []byte {
	return data[e.Offset : e.Offset+e.Size]
}
