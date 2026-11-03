# ipdata
[![CI](https://github.com/ipdata/go/actions/workflows/ci.yml/badge.svg)](https://github.com/ipdata/go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ipdata/go.svg)](https://pkg.go.dev/github.com/ipdata/go)
[![License](https://img.shields.io/github/license/ipdata/go.svg)](https://github.com/ipdata/go/blob/master/LICENSE)
[![Latest Git Tag](https://img.shields.io/github/tag/ipdata/go.svg)](https://github.com/ipdata/go/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/ipdata/go)](https://goreportcard.com/report/github.com/ipdata/go)

Package ipdata is a Go client for the [ipdata.co](https://ipdata.co) API. It
provides IP geolocation, threat intelligence, company detection, currency,
timezone, carrier, and language data for any IP address.

## Installation

```
go get github.com/ipdata/go
```

## License
This code is released under the MIT License. Please see the
[LICENSE](https://github.com/ipdata/go/blob/master/LICENSE) for the
full content of the license.

## Usage

The service provided by ipdata requires an API key. You can get one from
https://ipdata.co/.

### Basic Lookup

```go
package main

import (
	"fmt"

	"github.com/ipdata/go"
)

func main() {
	client, err := ipdata.NewClient("YOUR_API_KEY")
	if err != nil {
		panic(err)
	}

	data, err := client.Lookup("8.8.8.8")
	if err != nil {
		panic(err)
	}

	fmt.Printf("IP: %s\n", data.IP)
	fmt.Printf("Country: %s (%s)\n", data.CountryName, data.CountryCode)
	fmt.Printf("City: %s\n", data.City)
	fmt.Printf("ASN: %s (%s)\n", data.ASN.ASN, data.ASN.Name)

	if data.Company != nil {
		fmt.Printf("Company: %s\n", data.Company.Name)
	}

	if data.Threat != nil {
		fmt.Printf("VPN: %v, Tor: %v, Proxy: %v\n",
			data.Threat.IsVPN, data.Threat.IsTOR, data.Threat.IsProxy)
	}
}
```

### Connection reuse and HTTP/2

A `Client` keeps a persistent HTTPS connection pool for as long as it lives.
Create one client per process (or one per API key or endpoint), keep it, and
reuse it for every lookup: each new client pays a fresh TLS handshake.
Requests to api.ipdata.co are multiplexed over HTTP/2 when the platform
negotiates it, and fall back to HTTP/1.1 keep-alive otherwise.

A `Client` is safe for concurrent use from multiple goroutines, so one
package-level or injected instance can serve all of them. Pooled connections
are closed after 60 seconds idle, idle HTTP/2 connections are health-checked
with a PING every 30 seconds, and TCP keepalive probes run every 30 seconds.
Call `client.CloseIdleConnections()` at shutdown (or before a long idle period)
to release the pooled connections eagerly; the client stays usable afterwards.

```go
var client ipdata.Client

func main() {
	var err error

	client, err = ipdata.NewClient("YOUR_API_KEY")
	if err != nil {
		panic(err)
	}
	defer client.CloseIdleConnections()

	// Every lookup made through client reuses the same pooled connections.
	data, err := client.Lookup("8.8.8.8")
	// ...
}
```

Bulk lookups are `POST` requests, which `net/http` does not replay on its own
once they were written to a connection. The client therefore retries a bulk
request exactly once when a pooled connection turns out to be dead before any
byte of the response arrived; it never retries after a response started to
arrive, on an HTTP error status, or after a cancellation or timeout.

If you supply your own `*http.Client` with `WithHTTPClient`, connection reuse
follows the settings of its transport. `net/http` switches its automatic HTTP/2
setup off when an `http.Transport` sets a custom `DialContext` or
`TLSClientConfig`, so set `ForceAttemptHTTP2: true` on such a transport (the
default transport already does) to keep speaking HTTP/2 to api.ipdata.co.

### EU Endpoint (GDPR Compliance)

For GDPR compliance, use `NewEUClient` to route all requests through EU data
centers only (Frankfurt, Paris, and Ireland):

```go
client, err := ipdata.NewEUClient("YOUR_API_KEY")
```

### Field Filtering

Request only specific fields to reduce response size:

```go
data, err := client.LookupFields("8.8.8.8", []string{"ip", "country_name", "threat"})
if err != nil {
	panic(err)
}

fmt.Printf("%s - %s\n", data.IP, data.CountryName)
```

### Bulk Lookup

Look up multiple IPs in a single request:

```go
results, err := client.BulkLookup([]string{"8.8.8.8", "1.1.1.1"})
if err != nil {
	// err may be of type ipdata.Error with index of first failure
	// results may still contain partial data
}

for _, ip := range results {
	if ip != nil {
		fmt.Printf("%s: %s\n", ip.IP, ip.CountryName)
	}
}
```

### Error Handling

Errors returned from lookup functions may be of type `Error`, which includes
the message from the API and the HTTP status code:

```go
import "github.com/pkg/errors"

data, err := client.Lookup("8.8.8.8")
if err != nil {
	if apiErr, ok := errors.Cause(err).(ipdata.Error); ok {
		fmt.Printf("API error %d: %s\n", apiErr.Code(), apiErr.Error())
	}
}
```

## Response Fields

The `IP` struct includes all fields from the ipdata API response:

| Field | Type | Description |
|-------|------|-------------|
| `IP` | `string` | IP address |
| `City` | `string` | City name |
| `Region` | `string` | Region/state name |
| `RegionCode` | `string` | ISO 3166-2 region code |
| `CountryName` | `string` | Country name |
| `CountryCode` | `string` | ISO 3166-1 alpha-2 code |
| `ContinentName` | `string` | Continent name |
| `ContinentCode` | `string` | 2-letter continent code |
| `Latitude` | `float64` | Geographic latitude |
| `Longitude` | `float64` | Geographic longitude |
| `Postal` | `string` | Postal/zip code |
| `CallingCode` | `string` | International calling code |
| `Flag` | `string` | URL to country flag image |
| `EmojiFlag` | `string` | Flag emoji character |
| `EmojiUnicode` | `string` | Unicode representation |
| `IsEU` | `bool` | Whether in the EU |
| `Organization` | `string` | Organization name |
| `ASN` | `ASN` | Autonomous System Number data |
| `Company` | `*Company` | Company/organization data |
| `Carrier` | `*Carrier` | Mobile carrier data |
| `Languages` | `[]Language` | Languages spoken |
| `Currency` | `*Currency` | Local currency info |
| `TimeZone` | `*TimeZone` | Timezone info |
| `Threat` | `*Threat` | Threat intelligence data |
| `Count` | `string` | API request count (24h) |
| `Status` | `int` | HTTP status code |

### Nested Types

**`Company`**: `Name`, `Domain`, `Network`, `Type`

**`ASN`**: `ASN`, `Name`, `Domain`, `Route`, `Type`

**`Carrier`**: `Name`, `MCC`, `MNC`

**`Language`**: `Name`, `Native`, `Code`

**`Currency`**: `Name`, `Code`, `Symbol`, `Native`, `Plural`

**`TimeZone`**: `Name`, `Abbreviation`, `Offset`, `IsDST`, `CurrentTime`

**`Threat`**: `IsTOR`, `IsVPN`, `IsICloudRelay`, `IsProxy`, `IsDatacenter`, `IsAnonymous`, `IsKnownAttacker`, `IsKnownAbuser`, `IsThreat`, `IsBogon`, `Blocklists`, `Scores`

## Contributors

- [Tim Heckman](https://github.com/theckman/) - Created the first version of this library
