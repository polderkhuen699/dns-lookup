# DNS Lookup & Domain WHOIS

[![Go Report Card](https://goreportcard.com/badge/github.com/kataras/dns-lookup?style=for-the-badge)](https://goreportcard.com/report/github.com/kataras/dns-lookup)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kataras/dns-lookup?style=for-the-badge)](https://github.com/kataras/dns-lookup)
[![Release](https://img.shields.io/github/v/release/kataras/dns-lookup?style=for-the-badge)](https://github.com/kataras/dns-lookup/releases)
[![Build Status](https://github.com/kataras/dns-lookup/actions/workflows/ci.yml/badge.svg?style=for-the-badge)](https://github.com/kataras/dns-lookup/actions)

A fully-featured DNS Lookup and Domain WHOIS package written in Go.

## Features

### DNS Lookup
- **Multiple Record Types**: A, AAAA, CNAME, MX, NS, TXT, PTR, SRV
- **Flexible Configuration**: Custom DNS resolvers, timeouts, and more
- **Batch Lookups**: Query all record types at once
- **Context Support**: Full context.Context integration for cancellation and timeouts

### WHOIS Lookup
- **Extensive TLD Support**: 50+ TLDs with dedicated WHOIS servers
- **Automatic Referrals**: Follows WHOIS server referrals automatically
- **Parsed Data**: Extracts registrar, dates, name servers, status, and emails
- **Raw Response**: Full raw WHOIS response included
- **Custom Servers**: Override default WHOIS servers per TLD

### Unified Client
- **Single Interface**: Combines DNS and WHOIS functionality
- **Complete Domain Info**: Get all DNS and WHOIS data in one call
- **Independent Clients**: Access DNS or WHOIS clients separately

## Installation

The only requirement is the [Go Programming Language](https://go.dev/dl/).

```bash
go get github.com/kataras/dns-lookup@latest
```

## Usage

### As a Library

#### DNS Lookup

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/kataras/dns-lookup/pkg/dns"
)

func main() {
    client, err := dns.NewClient(dns.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    
    // Single record type lookup
    result, err := client.Lookup(ctx, "example.com", dns.RecordTypeA)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("A records: %v\n", result.Records)
    
    // All record types
    results, err := client.LookupAll(ctx, "example.com")
    if err != nil {
        log.Fatal(err)
    }
    
    for recordType, result := range results {
        fmt.Printf("%s records: %v\n", recordType, result.Records)
    }
}
```

#### WHOIS Lookup

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/kataras/dns-lookup/pkg/whois"
)

func main() {
    client, err := whois.NewClient(whois.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    result, err := client.Lookup(ctx, "example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Registrar: %s\n", result.Registrar)
    fmt.Printf("Created: %s\n", result.CreatedDate)
    fmt.Printf("Expires: %s\n", result.ExpiryDate)
    fmt.Printf("Name Servers: %v\n", result.NameServers)
}
```

#### Unified Client

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/kataras/dns-lookup/pkg/lookup"
)

func main() {
    client, err := lookup.NewClient(lookup.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    
    // Get complete domain information
    info, err := client.LookupAll(ctx, "example.com")
    if err != nil {
        log.Printf("Warning: %v\n", err)
    }

    fmt.Printf("Domain: %s\n", info.Domain)
    fmt.Printf("DNS Records: %d types\n", len(info.DNS))
    fmt.Printf("WHOIS Registrar: %s\n", info.WHOIS.Registrar)
}
```

### CLI Application

Install the CLI:

```bash
go install github.com/kataras/dns-lookup/cmd/dns-lookup@latest
```

#### Usage Examples

```bash
# DNS A record lookup
dns-lookup -d example.com

# DNS MX record lookup
dns-lookup -d example.com -t MX

# WHOIS lookup only
dns-lookup -d example.com -w

# All DNS records + WHOIS
dns-lookup -d example.com -a

# JSON output
dns-lookup -d example.com -j

# SRV record lookup
dns-lookup -srv xmpp,tcp,example.com

# Custom DNS resolver
dns-lookup -d example.com -resolver 8.8.8.8:53

# Show version
dns-lookup -v
```

#### CLI Options

```
-d, -domain       Domain to lookup (required)
-t, -type         DNS record type (A, AAAA, CNAME, MX, NS, TXT, PTR)
-w, -whois        Perform WHOIS lookup only
-dns              Perform DNS lookup only
-a, -all          Perform all DNS record type lookups + WHOIS
-j, -json         Output results in JSON format
-timeout          Timeout in seconds (default: 10)
-resolver         Custom DNS resolver (e.g., 8.8.8.8:53)
-follow           Follow WHOIS referrals (default: true)
-srv              SRV lookup in format: service,proto,name
-v, -version      Show version information
```

## Configuration

### DNS Configuration

```go
config := &dns.Config{
    Timeout:        5 * time.Second,    // Query timeout
    CustomResolver: "8.8.8.8:53",       // Custom DNS server
}
```

### WHOIS Configuration

```go
config := &whois.Config{
    Timeout:        10 * time.Second,   // Query timeout
    FollowReferral: true,               // Follow WHOIS referrals
    CustomServers: map[string]whois.WhoisServer{
        "example": {
            Host: "whois.example.com",
            Port: "43",
        },
    },
}
```

## Testing

Run all tests:

```bash
go test ./...
```

Run tests in short mode (skips network calls):

```bash
go test -short ./...
```

Run tests with verbose output:

```bash
go test -v ./...
```

Run tests for specific package:

```bash
go test -v ./pkg/dns
go test -v ./pkg/whois
go test -v ./pkg/lookup
```

## Supported TLDs

The WHOIS package includes dedicated servers for 50+ TLDs including:
- Generic: com, net, org, info, biz
- Country codes: uk, ca, de, jp, fr, au, ru, ch, it, nl, eu, nz, in, cn, br, mx, se, be, at, dk, fi, is, cz, pl
- New gTLDs: io, me, tv, cc, app, dev, ai, co, asia, mobi, tel

## License

This project is available under the [MIT License](LICENSE).

### Author

Gerasimos (Makis) Maropoulos ([@kataras](https://github.com/kataras))
