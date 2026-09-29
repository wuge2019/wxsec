package wxapkg

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/tidwall/pretty"
)

// Beautify 按扩展名对文本产物做格式化；失败时原样返回，保证不丢数据。
func Beautify(name string, data []byte) []byte {
	if len(bytes.TrimSpace(data)) == 0 {
		return data
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		if out := pretty.Pretty(data); out != nil {
			return out
		}
	case ".js":
		return beautifyJS(data)
	}
	return data
}

func beautifyJS(data []byte) []byte {
	code := string(bytes.TrimSpace(data))
	out, err := jsbeautifier.Beautify(&code, jsbeautifier.DefaultOptions())
	if err != nil || out == "" {
		return data
	}
	return []byte(out)
}
