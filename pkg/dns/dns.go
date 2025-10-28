package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// RecordType represents a DNS record type used in DNS queries.
type RecordType string

const (
	// RecordTypeA represents IPv4 address records.
	RecordTypeA RecordType = "A"
	// RecordTypeAAAA represents IPv6 address records.
	RecordTypeAAAA RecordType = "AAAA"
	// RecordTypeCNAME represents canonical name records.
	RecordTypeCNAME RecordType = "CNAME"
	// RecordTypeMX represents mail exchange records.
	RecordTypeMX RecordType = "MX"
	// RecordTypeNS represents name server records.
	RecordTypeNS RecordType = "NS"
	// RecordTypeTXT represents text records.
	RecordTypeTXT RecordType = "TXT"
	// RecordTypeSOA represents start of authority records.
	RecordTypeSOA RecordType = "SOA"
	// RecordTypePTR represents pointer records for reverse DNS lookups.
	RecordTypePTR RecordType = "PTR"
	// RecordTypeSRV represents service records.
	RecordTypeSRV RecordType = "SRV"
)

// LookupResult contains the results of a DNS lookup, including the queried domain,
// record type, resolved records, and metadata about the query.
type LookupResult struct {
	Domain      string                 `json:"domain"`
	RecordType  RecordType             `json:"record_type"`
	Records     []string               `json:"records"`
	MXRecords   []*net.MX              `json:"mx_records,omitempty"`
	SRVRecords  []*net.SRV             `json:"srv_records,omitempty"`
	NameServers []string               `json:"name_servers,omitempty"`
	TTL         time.Duration          `json:"ttl,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Client is a DNS lookup client that performs DNS queries with configurable
// timeout and custom resolver support.
type Client struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// Config contains configuration options for the DNS client.
type Config struct {
	// Timeout for DNS queries (default: 5 seconds).
	Timeout time.Duration
	// CustomResolver allows specifying a custom DNS server (e.g., "8.8.8.8:53").
	CustomResolver string
}

// DefaultConfig returns a default configuration with a 5-second timeout
// and the system's default DNS resolver.
func DefaultConfig() *Config {
	return &Config{
		Timeout: 5 * time.Second,
	}
}

// NewClient creates a new DNS lookup client with the given configuration.
// If config is nil, DefaultConfig is used. Returns an error if client creation fails.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	client := &Client{
		timeout: config.Timeout,
	}

	if config.CustomResolver != "" {
		client.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: config.Timeout,
				}
				return d.DialContext(ctx, network, config.CustomResolver)
			},
		}
	} else {
		client.resolver = net.DefaultResolver
	}

	return client, nil
}

// Lookup performs a DNS lookup for the specified domain and record type.
// If ctx is nil, a new context with the client's timeout is created.
// Returns a LookupResult containing the query results or an error if the lookup fails.
func (c *Client) Lookup(ctx context.Context, domain string, recordType RecordType) (*LookupResult, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
	}

	result := &LookupResult{
		Domain:     domain,
		RecordType: recordType,
		Timestamp:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	var err error

	switch recordType {
	case RecordTypeA:
		result.Records, err = c.lookupA(ctx, domain)
	case RecordTypeAAAA:
		result.Records, err = c.lookupAAAA(ctx, domain)
	case RecordTypeCNAME:
		result.Records, err = c.lookupCNAME(ctx, domain)
	case RecordTypeMX:
		result.MXRecords, err = c.lookupMX(ctx, domain)
		if err == nil {
			for _, mx := range result.MXRecords {
				result.Records = append(result.Records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
			}
		}
	case RecordTypeNS:
		result.NameServers, err = c.lookupNS(ctx, domain)
		result.Records = result.NameServers
	case RecordTypeTXT:
		result.Records, err = c.lookupTXT(ctx, domain)
	case RecordTypePTR:
		result.Records, err = c.lookupPTR(ctx, domain)
	case RecordTypeSRV:
		// SRV records require service, proto, and name format
		result.Error = "SRV lookup requires service, proto, and name. Use LookupSRV method instead"
		return result, fmt.Errorf("use LookupSRV for SRV record lookups")
	default:
		err = fmt.Errorf("unsupported record type: %s", recordType)
	}

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	return result, nil
}

// LookupAll performs lookups for all common record types (A, AAAA, CNAME, MX, NS, TXT).
// If ctx is nil, a new context with extended timeout is created.
// Returns a map of record types to their results, continuing even if individual lookups fail.
func (c *Client) LookupAll(ctx context.Context, domain string) (map[RecordType]*LookupResult, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout*6) // More time for multiple lookups
		defer cancel()
	}

	results := make(map[RecordType]*LookupResult)
	recordTypes := []RecordType{
		RecordTypeA,
		RecordTypeAAAA,
		RecordTypeCNAME,
		RecordTypeMX,
		RecordTypeNS,
		RecordTypeTXT,
	}

	for _, rt := range recordTypes {
		result, err := c.Lookup(ctx, domain, rt)
		if err != nil {
			// Continue even if one lookup fails
			result.Error = err.Error()
		}
		results[rt] = result
	}

	return results, nil
}

// LookupSRV performs a SRV record lookup for the specified service, protocol, and name.
// For example, service="_http", proto="_tcp", name="example.com".
// If ctx is nil, a new context with the client's timeout is created.
func (c *Client) LookupSRV(ctx context.Context, service, proto, name string) (*LookupResult, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
	}

	result := &LookupResult{
		Domain:     fmt.Sprintf("_%s._%s.%s", service, proto, name),
		RecordType: RecordTypeSRV,
		Timestamp:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	_, addrs, err := c.resolver.LookupSRV(ctx, service, proto, name)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.SRVRecords = addrs
	for _, srv := range addrs {
		result.Records = append(result.Records, fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target))
	}

	return result, nil
}

// lookupA performs an A record lookup and returns IPv4 addresses.
func (c *Client) lookupA(ctx context.Context, domain string) ([]string, error) {
	ips, err := c.resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ip := range ips {
		records = append(records, ip.String())
	}
	return records, nil
}

// lookupAAAA performs an AAAA record lookup and returns IPv6 addresses.
func (c *Client) lookupAAAA(ctx context.Context, domain string) ([]string, error) {
	ips, err := c.resolver.LookupIP(ctx, "ip6", domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ip := range ips {
		records = append(records, ip.String())
	}
	return records, nil
}

// lookupCNAME performs a CNAME record lookup and returns the canonical name.
func (c *Client) lookupCNAME(ctx context.Context, domain string) ([]string, error) {
	cname, err := c.resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return nil, err
	}
	return []string{cname}, nil
}

// lookupMX performs an MX record lookup and returns mail exchange records.
func (c *Client) lookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return c.resolver.LookupMX(ctx, domain)
}

// lookupNS performs an NS record lookup and returns name server records.
func (c *Client) lookupNS(ctx context.Context, domain string) ([]string, error) {
	nss, err := c.resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ns := range nss {
		records = append(records, ns.Host)
	}
	return records, nil
}

// lookupTXT performs a TXT record lookup and returns text records.
func (c *Client) lookupTXT(ctx context.Context, domain string) ([]string, error) {
	return c.resolver.LookupTXT(ctx, domain)
}

// lookupPTR performs a PTR (reverse DNS) lookup for an IP address.
func (c *Client) lookupPTR(ctx context.Context, ip string) ([]string, error) {
	return c.resolver.LookupAddr(ctx, ip)
}
