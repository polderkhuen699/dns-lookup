package whois

import (
	"context"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "custom timeout",
			config: &Config{
				Timeout: 5 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "custom server",
			config: &Config{
				CustomServers: map[string]WhoisServer{
					"test": {Host: "whois.test.com", Port: "43"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestGetWhoisServer(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name     string
		domain   string
		wantHost string
		wantErr  bool
	}{
		{
			name:     "com domain",
			domain:   "example.com",
			wantHost: "whois.verisign-grs.com",
			wantErr:  false,
		},
		{
			name:     "org domain",
			domain:   "example.org",
			wantHost: "whois.pir.org",
			wantErr:  false,
		},
		{
			name:     "co.uk domain",
			domain:   "example.co.uk",
			wantHost: "whois.nic.uk",
			wantErr:  false,
		},
		{
			name:     "io domain",
			domain:   "example.io",
			wantHost: "whois.nic.io",
			wantErr:  false,
		},
		{
			name:    "invalid domain",
			domain:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := client.getWhoisServer(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("getWhoisServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && server.Host != tt.wantHost {
				t.Errorf("getWhoisServer() host = %v, want %v", server.Host, tt.wantHost)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	// Skip in short mode as this makes real network calls
	if testing.Short() {
		t.Skip("Skipping WHOIS lookup test in short mode")
	}

	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "google.com")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if result.Domain != "google.com" {
		t.Errorf("Expected domain google.com, got %s", result.Domain)
	}

	if result.RawResponse == "" {
		t.Error("Expected non-empty raw response")
	}

	t.Logf("WHOIS server: %s", result.Server)
	t.Logf("Registrar: %s", result.Registrar)
	t.Logf("Created: %s", result.CreatedDate)
	t.Logf("Expires: %s", result.ExpiryDate)
	t.Logf("Name servers: %v", result.NameServers)
}

func TestLookupWithTimeout(t *testing.T) {
	config := &Config{
		Timeout: 1 * time.Millisecond, // Very short timeout
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.Lookup(ctx, "google.com")
	// We expect this might timeout, but we're just testing it doesn't panic
	t.Logf("Lookup with short timeout result: %v", err)
}

func TestExtractReferralServer(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "whois server format",
			response: "Whois Server: whois.example.com",
			want:     "whois.example.com",
		},
		{
			name:     "referral url format",
			response: "Referral URL: whois://whois.example.com",
			want:     "whois.example.com",
		},
		{
			name:     "refer format",
			response: "Refer: whois.example.com",
			want:     "whois.example.com",
		},
		{
			name:     "no referral",
			response: "Some other content",
			want:     "",
		},
		{
			name:     "iana server ignored",
			response: "Whois Server: whois.iana.org",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.extractReferralServer(tt.response)
			if got != tt.want {
				t.Errorf("extractReferralServer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	result := &WhoisResult{
		Domain: "example.com",
		RawResponse: `Registrar: Example Registrar Inc.
Creation Date: 2020-01-01T00:00:00Z
Expiry Date: 2025-01-01T00:00:00Z
Updated Date: 2024-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Status: clientTransferProhibited
Status: clientUpdateProhibited
Admin Email: admin@example.com
`,
		ParsedData: make(map[string]interface{}),
	}

	client.parseResponse(result)

	if result.Registrar != "Example Registrar Inc." {
		t.Errorf("Expected registrar 'Example Registrar Inc.', got '%s'", result.Registrar)
	}

	if result.CreatedDate != "2020-01-01T00:00:00Z" {
		t.Errorf("Expected created date '2020-01-01T00:00:00Z', got '%s'", result.CreatedDate)
	}

	if result.ExpiryDate != "2025-01-01T00:00:00Z" {
		t.Errorf("Expected expiry date '2025-01-01T00:00:00Z', got '%s'", result.ExpiryDate)
	}

	if len(result.NameServers) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(result.NameServers))
	}

	if len(result.Status) != 2 {
		t.Errorf("Expected 2 status values, got %d", len(result.Status))
	}

	if len(result.Emails) == 0 {
		t.Error("Expected at least one email address")
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{
			name:  "valid email",
			email: "test@example.com",
			want:  true,
		},
		{
			name:  "valid email with subdomain",
			email: "test@mail.example.com",
			want:  true,
		},
		{
			name:  "invalid - no @",
			email: "testexample.com",
			want:  false,
		},
		{
			name:  "invalid - no domain",
			email: "test@",
			want:  false,
		},
		{
			name:  "invalid - no local part",
			email: "@example.com",
			want:  false,
		},
		{
			name:  "invalid - no TLD",
			email: "test@example",
			want:  false,
		},
		{
			name:  "invalid - too short",
			email: "a@",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEmail(tt.email)
			if got != tt.want {
				t.Errorf("isValidEmail(%s) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}
