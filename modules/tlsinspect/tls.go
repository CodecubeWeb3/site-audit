package tlsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Result summarises TLS handshake metadata.
type Result struct {
	Host              string
	Port              string
	Version           string
	CipherSuite       string
	OCSPStapled       bool
	H2                bool
	Certificates      []Certificate
	WeakCiphers       []string
	HSTSPreloadReady  bool
	CTLookupAttempted bool
}

// Certificate represents parsed certificate attributes.
type Certificate struct {
	Subject      string
	Issuer       string
	DNSNames     []string
	NotBefore    time.Time
	NotAfter     time.Time
	IsCA         bool
	SerialNumber string
	SignatureAlg string
	KeyUsage     []string
}

// Inspector performs TLS evaluations using a configurable dialer.
type Inspector struct {
	Dialer    *net.Dialer
	TLSConfig *tls.Config
}

// NewInspector creates an inspector with safe defaults.
func NewInspector() *Inspector {
	return &Inspector{
		Dialer: &net.Dialer{Timeout: 10 * time.Second},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: false, // #nosec G402: we rely on Go to verify certificates
		},
	}
}

// Inspect performs a TLS handshake to gather metadata.
func (i *Inspector) Inspect(ctx context.Context, host string) (*Result, error) {
	hostname, port := splitHostPort(host)
	addr := net.JoinHostPort(hostname, port)

	dialer := i.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}

	tlsCfg := i.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	tlsCfg.ServerName = hostname

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &Result{
		Host:        hostname,
		Port:        port,
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		OCSPStapled: len(state.OCSPResponse) > 0,
		H2:          state.NegotiatedProtocol == "h2",
	}

	switch state.Version {
	case tls.VersionTLS10:
		result.Version = "TLS1.0"
	case tls.VersionTLS11:
		result.Version = "TLS1.1"
	case tls.VersionTLS12:
		result.Version = "TLS1.2"
	case tls.VersionTLS13:
		result.Version = "TLS1.3"
	default:
		result.Version = fmt.Sprintf("0x%x", state.Version)
	}

	result.WeakCiphers = detectWeakCipher(result.CipherSuite)

	for _, cert := range state.PeerCertificates {
		result.Certificates = append(result.Certificates, parseCertificate(cert))
	}

	result.HSTSPreloadReady = estimateHSTSPreload(result.Certificates)
	result.CTLookupAttempted = false

	return result, nil
}

// DetectMixedContent scans HTML responses for insecure HTTP resources.
func DetectMixedContent(html string) []string {
	tokens := []string{}
	for _, segment := range strings.Split(html, "\n") {
		segment = strings.TrimSpace(segment)
		if strings.Contains(segment, "http://") && !strings.Contains(segment, "href=\"http://localhost") {
			tokens = append(tokens, segment)
		}
	}
	return tokens
}

func parseCertificate(cert *x509.Certificate) Certificate {
	usage := []string{}
	for _, u := range cert.ExtKeyUsage {
		usage = append(usage, extKeyUsageString(u))
	}
	return Certificate{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		DNSNames:     append([]string{}, cert.DNSNames...),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsCA:         cert.IsCA,
		SerialNumber: cert.SerialNumber.String(),
		SignatureAlg: cert.SignatureAlgorithm.String(),
		KeyUsage:     usage,
	}
}

func extKeyUsageString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	default:
		return fmt.Sprintf("unknown(%d)", usage)
	}
}

func detectWeakCipher(cipher string) []string {
	weak := []string{}
	lowers := strings.ToLower(cipher)
	if strings.Contains(lowers, "rc4") || strings.Contains(lowers, "3des") {
		weak = append(weak, cipher)
	}
	return weak
}

func estimateHSTSPreload(certs []Certificate) bool {
	if len(certs) == 0 {
		return false
	}
	leaf := certs[0]
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "*") {
			return false
		}
	}
	return true
}

func splitHostPort(target string) (host, port string) {
	if strings.Contains(target, ":") {
		host, port, err := net.SplitHostPort(target)
		if err == nil {
			return host, port
		}
	}
	return target, "443"
}
