package decomp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// vdom 是 $gwx 渲染出的虚拟 DOM 节点。
type vdom struct {
	Tag      string                     `json:"tag"`
	Attr     map[string]json.RawMessage `json:"attr"`
	Children []json.RawMessage          `json:"children"`
	Raw      map[string]json.RawMessage `json:"raw"`
	Generics map[string]json.RawMessage `json:"generics"`
}

// 哨兵形如 @@WX:item.title，代表一个被求值的绑定路径。
var sentinelPat = regexp.MustCompile(`@@WX:([A-Za-z0-9_.$#()\[\]]+)`)

const header = `<!-- 由 wxsec 执行小程序编译产物还原；动态分支按哨兵数据展开，仅作安全审计参考。 -->`

// emitWXML 把虚拟 DOM 树序列化为 WXML 文本。
// deps 是 __WXML_DEP__ 给出的模板依赖：新版编译器把多个页面的正文集中编译进
// base.wxml，页面自身模板会渲染成空树，此时指出正文在哪比留个空文件有用。
func emitWXML(tree string, deps []string) ([]byte, error) {
	var root vdom
	if err := json.Unmarshal([]byte(tree), &root); err != nil {
		return nil, fmt.Errorf("parse tree: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(header)
	buf.WriteByte('\n')
	if len(root.Children) == 0 && len(deps) > 0 {
		buf.WriteString("<!-- 本页模板正文编译在依赖模板中: " + strings.Join(deps, ", ") + " -->\n")
	}
	if err := writeNode(&buf, &root, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// transparent 标记编译期注入的容器节点，它们不对应 WXML 标签。
var transparent = map[string]bool{
	"wx-page": true, "virtual": true, "wx-virtual": true,
	"wx-scope": true, "wx-wx-scope": true, "wx-virtual-scope": true,
}

func writeNode(buf *bytes.Buffer, n *vdom, depth int) error {
	if n == nil {
		return nil
	}
	ind := strings.Repeat("  ", depth)

	if transparent[n.Tag] {
		return writeChildren(buf, n, depth)
	}

	tag := strings.TrimPrefix(n.Tag, "wx-")
	if tag == "" {
		tag = "view"
	}

	var attrs []string
	for _, k := range sortedAttrKeys(n.Attr) {
		s, ok, err := renderAttr(k, n.Attr[k])
		if err != nil {
			return err
		}
		if ok {
			attrs = append(attrs, s)
		}
	}
	attrText := ""
	if len(attrs) > 0 {
		attrText = " " + strings.Join(attrs, " ")
	}

	if len(n.Children) == 0 {
		buf.WriteString(ind + "<" + tag + attrText + "/>\n")
		return nil
	}

	buf.WriteString(ind + "<" + tag + attrText + ">\n")
	if err := writeChildren(buf, n, depth+1); err != nil {
		return err
	}
	buf.WriteString(ind + "</" + tag + ">\n")
	return nil
}

func writeChildren(buf *bytes.Buffer, n *vdom, depth int) error {
	for _, c := range n.Children {
		trimmed := bytes.TrimLeft(c, " \t\r\n")
		if len(trimmed) == 0 {
			continue
		}
		switch trimmed[0] {
		case '{':
			var child vdom
			if err := json.Unmarshal(c, &child); err != nil {
				return fmt.Errorf("child node: %w", err)
			}
			if err := writeNode(buf, &child, depth); err != nil {
				return err
			}
		case '"':
			var s string
			if err := json.Unmarshal(c, &s); err != nil {
				return fmt.Errorf("text node: %w", err)
			}
			t := strings.TrimSpace(s)
			if t == "" {
				continue
			}
			buf.WriteString(strings.Repeat("  ", depth) + restoreBindings(t) + "\n")
		}
	}
	return nil
}

func sortedAttrKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderAttr 生成一个属性片段；ok=false 表示该属性应被丢弃。
func renderAttr(key string, raw json.RawMessage) (string, bool, error) {
	switch key {
	case "wxKey", "n", "raw", "generics":
		return "", false, nil
	}

	// 编译期把 bind:tap 记成 bindtap，还原时恢复冒号写法。
	name := eventAttrName(key)

	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return "", false, nil
	}

	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return "", false, nil
		}
		return name + `="` + escapeAttr(restoreBindings(s)) + `"`, true, nil
	case 't', 'f': // 布尔字面量
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return "", false, err
		}
		return name + `="` + fmt.Sprintf("%t", b) + `"`, true, nil
	case 'n': // null 表示未赋值
		return "", false, nil
	default:
		// 数字或对象：对象一定是动态绑定，无法逐字还原表达式。
		if trimmed[0] == '{' || trimmed[0] == '[' {
			return name + `="{{/* 动态绑定，未能还原 */}}"`, true, nil
		}
		return name + `="` + string(trimmed) + `"`, true, nil
	}
}

// eventAttrName 还原事件属性名：bindtap → bind:tap，catchtouchmove → catch:touchmove。
func eventAttrName(k string) string {
	// 已是冒号形式（bind:tap / capture-bind:tap / mut-bind:tap）直接保留。
	if strings.Contains(k, ":") {
		return k
	}
	for _, p := range []struct{ prefix, out string }{
		{"mut-bind", "mut-bind:"},
		{"catch", "catch:"},
		{"bind", "bind:"},
	} {
		if strings.HasPrefix(k, p.prefix) {
			rest := strings.TrimPrefix(k, p.prefix)
			if rest == "" {
				return k
			}
			return p.out + rest
		}
	}
	return k
}

// restoreBindings 把哨兵路径还原为 {{表达式}}。
func restoreBindings(s string) string {
	return sentinelPat.ReplaceAllStringFunc(s, func(m string) string {
		path := strings.TrimSuffix(strings.TrimPrefix(m, "@@WX:"), ".")
		return "{{" + path + "}}"
	})
}

func escapeAttr(s string) string {
	return strings.ReplaceAll(s, `"`, "&quot;")
}
