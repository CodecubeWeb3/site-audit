package dnsresolver

import (
	"context"
	"errors"
	"net"
	"testing"
)

type mockLookup struct {
	ips       []net.IPAddr
	cname     string
	mx        []*net.MX
	ns        []*net.NS
	txt       []string
	dmarc     []string
	dkim      []string
	lookupErr error
}

type caaResolverStub struct {
	records []string
	err     error
}

func (c caaResolverStub) LookupCAA(ctx context.Context, domain string) ([]string, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.records, nil
}

func (m *mockLookup) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	return m.ips, nil
}

func (m *mockLookup) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return m.mx, nil
}

func (m *mockLookup) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return m.ns, nil
}

func (m *mockLookup) LookupTXT(ctx context.Context, host string) ([]string, error) {
	switch host {
	case "example.com":
		return m.txt, nil
	case "_dmarc.example.com":
		return m.dmarc, nil
	case "default._domainkey.example.com":
		return m.dkim, nil
	default:
		return nil, errors.New("no such host")
	}
}

func (m *mockLookup) LookupCNAME(ctx context.Context, host string) (string, error) {
	return m.cname, nil
}

type mockWHOIS struct{}

func (mockWHOIS) Lookup(ctx context.Context, domain string) (string, error) {
	return "Registrar: Example Registrar", nil
}

func TestResolverAggregatesRecords(t *testing.T) {
	lookup := &mockLookup{
		ips:   []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("2001:db8::1")}},
		cname: "example.net.",
		mx:    []*net.MX{{Host: "mail.example.com.", Pref: 10}},
		ns:    []*net.NS{{Host: "ns1.example.com."}},
		txt:   []string{"v=spf1 include:_spf.google.com ~all"},
		dmarc: []string{"v=DMARC1; p=reject"},
		dkim:  []string{"k=rsa; p=abc"},
	}

	resolver := &Resolver{Lookup: lookup, WHOIS: mockWHOIS{}, CAA: caaResolverStub{records: []string{"0 issue letsencrypt.org"}}}
	res, err := resolver.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(res.A) != 1 || len(res.AAAA) != 1 {
		t.Fatalf("unexpected IP results: %#v %#v", res.A, res.AAAA)
	}
	if res.CNAME != "example.net." {
		t.Fatalf("unexpected CNAME: %s", res.CNAME)
	}
	if len(res.SPF) != 1 || len(res.DMARC) != 1 || len(res.DKIM) != 1 {
		t.Fatalf("expected SPF/DMARC/DKIM records")
	}
	if res.WHOIS == "" {
		t.Fatalf("expected WHOIS data")
	}
}

func TestResolverHandlesErrors(t *testing.T) {
	lookup := &mockLookup{lookupErr: errors.New("no such host")}
	resolver := &Resolver{Lookup: lookup, CAA: caaResolverStub{err: errors.New("failed")}}
	res, err := resolver.Resolve(context.Background(), "invalid.local")
	if err != nil {
		t.Fatalf("expected no fatal error despite lookup failure: %v", err)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected errors slice to capture lookup issue")
	}
}
