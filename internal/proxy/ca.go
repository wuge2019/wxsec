package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CASubject 是本地根证书的可识别名字，安装/卸载都按这个名字定位。
const CASubject = "wxsec MITM Root CA (authorized testing only)"

const (
	caCertFile = "wxsec-ca.crt"
	caKeyFile  = "wxsec-ca.key"
)

// Authority 是本地抓包用的根证书与叶子证书签发器。
type Authority struct {
	dir      string
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	certPEM  []byte
	keyPEM   []byte
	leafPool *x509.CertPool

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// LoadOrGenerateCA 在 dir 下加载或首次生成根证书。
// 私钥只留在本机磁盘（权限 0600），绝不写入报告或导出文件。
func LoadOrGenerateCA(dir string) (*Authority, error) {
	if dir == "" {
		return nil, errors.New("ca directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir %s: %w", dir, err)
	}
	ca := &Authority{dir: dir, leafs: map[string]*tls.Certificate{}}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		if err := ca.parse(certPEM, keyPEM); err == nil {
			return ca, nil
		}
		// 已存在的证书损坏或与新私钥不匹配时重新生成，避免启动即失败。
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: CASubject, Organization: []string{"wxsec"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, newCertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := ca.parse(newCertPEM, newKeyPEM); err != nil {
		return nil, err
	}
	return ca, nil
}

func (ca *Authority) parse(certPEM, keyPEM []byte) error {
	cBlk, _ := pem.Decode(certPEM)
	if cBlk == nil {
		return errors.New("ca certificate pem is invalid")
	}
	crt, err := x509.ParseCertificate(cBlk.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca certificate: %w", err)
	}
	kBlk, _ := pem.Decode(keyPEM)
	if kBlk == nil {
		return errors.New("ca key pem is invalid")
	}
	key, err := x509.ParsePKCS1PrivateKey(kBlk.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca key: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return errors.New("ca certificate rejected by cert pool")
	}
	ca.caCert, ca.caKey, ca.certPEM, ca.keyPEM, ca.leafPool = crt, key, certPEM, keyPEM, pool
	return nil
}

// CertPath 返回根证书（仅公钥）的磁盘位置，供用户手动信任。
func (ca *Authority) CertPath() string { return filepath.Join(ca.dir, caCertFile) }

// KeyPath 返回根私钥位置，只在诊断信息里出现，内容不外泄。
func (ca *Authority) KeyPath() string { return filepath.Join(ca.dir, caKeyFile) }

// CertPEM 是根证书公钥 PEM，可安全展示或导出。
func (ca *Authority) CertPEM() []byte { return ca.certPEM }

// CertDER 是根证书 DER，用于计算指纹并在信任存储里定位自身。
func (ca *Authority) CertDER() []byte { return ca.caCert.Raw }

// RootPool 返回把本 CA 当作信任根的证书池，测试与自检用。
func (ca *Authority) RootPool() *x509.CertPool { return ca.leafPool }

// NotAfter 是根证书到期时间。
func (ca *Authority) NotAfter() time.Time { return ca.caCert.NotAfter }

// ForHost 为目标主机签发（并缓存）叶子证书。
func (ca *Authority) ForHost(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, errors.New("host is empty")
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leafs[host]; ok {
		return c, nil
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
		// 顶级域名场景下顺带签 www 子域，减少一次握手失败。
		if !strings.HasPrefix(host, "www.") && strings.Count(host, ".") >= 1 {
			tmpl.DNSNames = append(tmpl.DNSNames, "www."+host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &leafKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, fmt.Errorf("leaf keypair for %s: %w", host, err)
	}
	cert.Leaf = tmplToParsed(tmpl, der)
	ca.leafs[host] = &cert
	return &cert, nil
}

func tmplToParsed(tmpl *x509.Certificate, der []byte) *x509.Certificate {
	if c, err := x509.ParseCertificate(der); err == nil {
		return c
	}
	return &x509.Certificate{Subject: tmpl.Subject}
}

// HostFromAuthority 从 host:port / [ipv6]:port 中取出纯主机名。
func HostFromAuthority(authority string) string {
	a := strings.TrimSpace(authority)
	if a == "" {
		return ""
	}
	if h, port, err := net.SplitHostPort(a); err == nil {
		if _, err := strconv.Atoi(port); err == nil {
			return strings.ToLower(h)
		}
		return strings.ToLower(h)
	}
	if i := strings.LastIndexByte(a, ':'); i > 0 && !strings.Contains(a, "]") {
		if _, err := strconv.Atoi(a[i+1:]); err == nil {
			return strings.ToLower(a[:i])
		}
	}
	return strings.ToLower(strings.Trim(a, "[]"))
}
