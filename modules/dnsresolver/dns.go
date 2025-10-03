package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// DNSLookup defines the operations required from a DNS resolver implementation.
type DNSLookup interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupTXT(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
}

// WHOISClient defines a WHOIS lookup client for registrant information.
type WHOISClient interface {
	Lookup(ctx context.Context, domain string) (string, error)
}

// CAAResolver resolves CAA records when configured.
type CAAResolver interface {
	LookupCAA(ctx context.Context, domain string) ([]string, error)
}

// Resolver orchestrates DNS and WHOIS lookups.
type Resolver struct {
	Lookup DNSLookup
	WHOIS  WHOISClient
	CAA    CAAResolver
}

// Result captures DNS metadata for a domain.
type Result struct {
	Domain      string
	A           []string
	AAAA        []string
	CNAME       string
	MX          []string
	NS          []string
	TXT         []string
	SPF         []string
	DMARC       []string
	DKIM        []string
	CAA         []string
	WHOIS       string
	Errors      []string
	Propagation []string
}

// NewResolver builds a resolver using the standard library resolver.
func NewResolver() *Resolver {
	return &Resolver{Lookup: net.DefaultResolver}
}

// Resolve fetches DNS records and WHOIS data for a domain.
func (r *Resolver) Resolve(ctx context.Context, domain string) (*Result, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	if r.Lookup == nil {
		r.Lookup = net.DefaultResolver
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res := &Result{Domain: domain}

	if ipAddrs, err := r.Lookup.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ipAddrs {
			if ip.IP.To4() != nil {
				res.A = append(res.A, ip.IP.String())
			} else {
				res.AAAA = append(res.AAAA, ip.IP.String())
			}
		}
	} else {
		res.Errors = append(res.Errors, fmt.Sprintf("A/AAAA: %v", err))
	}

	if cname, err := r.Lookup.LookupCNAME(ctx, domain); err == nil {
		res.CNAME = cname
	} else if !isNotFound(err) {
		res.Errors = append(res.Errors, fmt.Sprintf("CNAME: %v", err))
	}

	if mxRecords, err := r.Lookup.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxRecords {
			res.MX = append(res.MX, fmt.Sprintf("%s %d", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	} else if !isNotFound(err) {
		res.Errors = append(res.Errors, fmt.Sprintf("MX: %v", err))
	}

	if nsRecords, err := r.Lookup.LookupNS(ctx, domain); err == nil {
		for _, ns := range nsRecords {
			res.NS = append(res.NS, strings.TrimSuffix(ns.Host, "."))
		}
	} else if !isNotFound(err) {
		res.Errors = append(res.Errors, fmt.Sprintf("NS: %v", err))
	}

	if txtRecords, err := r.Lookup.LookupTXT(ctx, domain); err == nil {
		res.TXT = append(res.TXT, txtRecords...)
		for _, txt := range txtRecords {
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				res.SPF = append(res.SPF, txt)
			}
		}
	} else if !isNotFound(err) {
		res.Errors = append(res.Errors, fmt.Sprintf("TXT: %v", err))
	}

	dmarcHost := "_dmarc." + domain
	if dmarcRecords, err := r.Lookup.LookupTXT(ctx, dmarcHost); err == nil {
		for _, txt := range dmarcRecords {
			if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
				res.DMARC = append(res.DMARC, txt)
			}
		}
	}

	dkimHost := "default._domainkey." + domain
	if dkimRecords, err := r.Lookup.LookupTXT(ctx, dkimHost); err == nil {
		for _, txt := range dkimRecords {
			if strings.Contains(strings.ToLower(txt), "k=rsa") {
				res.DKIM = append(res.DKIM, txt)
			}
		}
	}

	if caaRecords, err := r.lookupCAA(ctx, domain); err == nil {
		res.CAA = append(res.CAA, caaRecords...)
	} else if err != nil && !errors.Is(err, errCAAUnsupported) {
		res.Errors = append(res.Errors, fmt.Sprintf("CAA: %v", err))
	}

	if r.WHOIS != nullWHOISClient {
		if r.WHOIS != nil {
			if whois, err := r.WHOIS.Lookup(ctx, domain); err == nil {
				res.WHOIS = whois
			} else {
				res.Errors = append(res.Errors, fmt.Sprintf("WHOIS: %v", err))
			}
		}
	}

	sort.Strings(res.A)
	sort.Strings(res.AAAA)
	sort.Strings(res.MX)
	sort.Strings(res.NS)
	sort.Strings(res.SPF)
	sort.Strings(res.DMARC)
	sort.Strings(res.DKIM)
	sort.Strings(res.CAA)

	return res, nil
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

var nullWHOISClient WHOISClient

var errCAAUnsupported = errors.New("caa lookup not configured")

func (r *Resolver) lookupCAA(ctx context.Context, domain string) ([]string, error) {
	if r.CAA == nil {
		return nil, errCAAUnsupported
	}
	return r.CAA.LookupCAA(ctx, domain)
}
