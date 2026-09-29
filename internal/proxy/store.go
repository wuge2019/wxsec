package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Flow 是一条抓包记录。
// 出于最小化敏感数据落盘的原则，只保留定位接口所需的头，Cookie / Authorization 一律不记录。
type Flow struct {
	Seq         int64     `json:"seq"`
	Time        time.Time `json:"time"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Scheme      string    `json:"scheme"` // https / http / connect
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	Query       string    `json:"query"`
	Status      int       `json:"status"`
	Proto       string    `json:"proto"`
	ReqType     string    `json:"reqType"`
	ContentType string    `json:"contentType"`
	ReqBytes    int64     `json:"reqBytes"`
	RespBytes   int64     `json:"respBytes"`
	DurationMs  int64     `json:"durationMs"`
	AppID       string    `json:"appId"`
	WxVersion   string    `json:"wxVersion"`
	Referer     string    `json:"referer"`
	UserAgent   string    `json:"userAgent"`
	Intercepted bool      `json:"intercepted"` // false 表示只拿到 CONNECT，未能解密
	Note        string    `json:"note"`
}

// DisplayURL 给界面与导出用：CONNECT-only 记录没有路径，用 host 占位。
func (f Flow) DisplayURL() string {
	if f.URL != "" {
		return f.URL
	}
	if f.Scheme == "connect" {
		return "https://" + f.Host + "/（未解密，仅域名）"
	}
	return f.Host
}

// 小程序请求的 Referer 形如 https://servicewechat.com/{appid}/{version}/page-frame.html
// 版本号通常是数字，开发者工具下是 "devtools"，因此按非斜杠段取值。
var reServiceWechat = regexp.MustCompile(`(?i)servicewechat\.com/(wx[0-9a-fA-F]{16})/([^/]+)/`)

// AttributeReferer 从 Referer 中解析发起请求的小程序 AppID 与版本号。
func AttributeReferer(referer string) (appid, version string) {
	m := reServiceWechat.FindStringSubmatch(referer)
	if m == nil {
		return "", ""
	}
	return strings.ToLower(m[1]), m[2]
}

// Store 保存抓包记录：内存环形表 + JSONL 落盘，重启工具不丢历史。
type Store struct {
	mu      sync.Mutex
	flows   []Flow
	max     int
	seq     int64
	file    *os.File
	path    string
	onAdd   func(Flow)
	dropped int
}

// NewStore 打开（或创建）flows.jsonl 并把已有记录读回内存。
func NewStore(dir string, max int) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if max <= 0 {
		max = 20000
	}
	s := &Store{max: max, path: filepath.Join(dir, "flows.jsonl")}
	if b, err := os.ReadFile(s.path); err == nil {
		s.loadJSONL(b)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	s.file = f
	return s, nil
}

func (s *Store) loadJSONL(b []byte) {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f Flow
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		if f.Seq > s.seq {
			s.seq = f.Seq
		}
		s.flows = append(s.flows, f)
	}
	if len(s.flows) > s.max {
		s.flows = s.flows[len(s.flows)-s.max:]
	}
}

// Path 是抓包记录文件位置。
func (s *Store) Path() string { return s.path }

// OnAdd 注册实时回调（GUI 事件推送）。
func (s *Store) OnAdd(fn func(Flow)) {
	s.mu.Lock()
	s.onAdd = fn
	s.mu.Unlock()
}

// Add 追加一条记录，超出上限时丢弃最旧条目。
func (s *Store) Add(f Flow) Flow {
	s.mu.Lock()
	s.seq++
	f.Seq = s.seq
	if f.Time.IsZero() {
		f.Time = time.Now()
	}
	s.flows = append(s.flows, f)
	dropped := 0
	if len(s.flows) > s.max {
		dropped = len(s.flows) - s.max
		s.flows = s.flows[dropped:]
	}
	if s.file != nil {
		if b, err := json.Marshal(f); err == nil {
			_, _ = s.file.Write(append(b, '\n'))
		}
	}
	cb := s.onAdd
	s.dropped += dropped
	s.mu.Unlock()
	if cb != nil {
		cb(f)
	}
	return f
}

// All 返回全部记录的副本（时间升序）。
func (s *Store) All() []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// Len 返回当前记录条数。
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

// Dropped 返回因容量上限被丢弃的条目数，提醒用户及时导出。
func (s *Store) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Clear 清空内存与磁盘记录。
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = nil
	s.dropped = 0
	if s.file != nil {
		_ = s.file.Close()
	}
	if err := os.WriteFile(s.path, nil, 0o644); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	s.file = f
	return nil
}

// Close 关闭落盘文件。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
