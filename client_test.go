// Copyright (c) 2017, 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// testErrCheck looks to see if errContains is a substring of err.Error(). If
// not, this calls t.Fatal(). It also calls t.Fatal() if there was an error, but
// errContains is empty. Returns true if you should continue running the test,
// or false if you should stop the test.
func testErrCheck(t *testing.T, name string, errContains string, err error) bool {
	t.Helper()

	if len(errContains) > 0 {
		if err == nil {
			t.Fatalf("%s error = <nil>, should contain %q", name, errContains)
			return false
		}

		if errStr := err.Error(); !strings.Contains(errStr, errContains) {
			t.Fatalf("%s error = %q, should contain %q", name, errStr, errContains)
			return false
		}

		return false
	}

	if err != nil && len(errContains) == 0 {
		t.Fatalf("%s unexpected error: %v", name, err)
		return false
	}

	return true
}

func testAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "failed to parse form: %v", err)
			return
		}

		if r.FormValue("api-key") != "testAPIkey" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"message":%q}`, `You have either exceeded your quota or that API key does not exist. Get a free API Key at https://ipdata.co/registration.html or contact support@ipdata.co to upgrade or register for a paid plan at https://ipdata.co/pricing.html.`)
			return
		}

		next(w, r)
	}
}

func testBulkHTTPServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/bulk", testAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "method %s not permitted, want %s", r.Method, http.MethodPost)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "failed to read body: %v", err)
			return
		}

		var ips []string

		if err := json.Unmarshal(body, &ips); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "failed to parse JSON body: %v", err)
			return
		}

		switch n := len(ips); n {
		case 2:
			if ips[0] == "1.1.1.1" {
				if ips[1] == "8.8.8.8" {
					fmt.Fprint(w, testBulkJSONValid)
					return
				} else if ips[1] == "8.8.4.4" || ips[1] == "4.4.2.2" {
					if ips[1] == "8.8.4.4" {
						w.WriteHeader(http.StatusForbidden)
					}
					fmt.Fprint(w, "{invalid json")
					return
				}
			}

			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `ip slice wrong inputs, want ["1.1.1.1","8.8.8.8"] got: %#v`, ips)
			return
		case 3:
			if ips[0] == "98.97.34.0" && ips[1] == "8.8.8.8" && ips[2] == "187.13.250.1" {
				fmt.Fprint(w, testBulkJSONNewFields)
				return
			}

			if ips[0] == "1.1.1.1" && ips[1] == "8.8.8.8" && ips[2] == "127.0.0.1" {
				fmt.Fprint(w, testBulkJSONWithLocalhost)
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `ip slice wrong inputs, want ["1.1.1.1","8.8.8.8","127.0.0.1"] got: %#v`, ips)
			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "ip slice wrong length, want 2 or 3 got %d: %#v", n, ips)
			return
		}
	}))

	return httptest.NewServer(mux)
}

func testHTTPServer(addr string) (net.Listener, *http.Server, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}

	mux := http.NewServeMux()

	amw := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "failed to parse form: %v", err)
				return
			}

			if r.FormValue("api-key") != "testAPIkey" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "API key does not exist.")
				return
			}

			next(w, r)
		}
	}

	// 200 response code
	mux.HandleFunc("/76.14.47.42", amw(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testJSONValid)
	}))

	// 200 response code -- invalid JSON
	mux.HandleFunc("/76.14.42.42", amw(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{")
	}))

	// 400 response code
	mux.HandleFunc("/192.168.0.1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message": "192.168.0.1 is a private IP address"}`)
	})

	mux.HandleFunc("/bacon", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message": "bacon does not appear to be an IPv4 or IPv6 address"}`)
	})

	// 401 response code
	mux.HandleFunc("/8.8.4.4", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message": "API key does not exist."}`)
	})

	mux.HandleFunc("/8.4.0.3", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message": "unexpected HTTP status code"}`)
	})

	// 429 response code
	mux.HandleFunc("/8.8.8.8", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(
			w,
			`{"message":"You have either exceeded your quota or that API key does not exist. Get a free API Key at https://ipdata.co/registration.html or contact support@ipdata.co to upgrade or register for a paid plan at https://ipdata.co/pricing.html."}`,
		)
	})

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	server := &http.Server{
		Addr:              l.Addr().String(),
		Handler:           mux,
		ReadTimeout:       2 * time.Second,
		ReadHeaderTimeout: time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
	}

	go func() {
		_ = server.Serve(l)
	}()

	return l, server, nil
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name string
		i    string
		e    string
		k    string
		err  string
	}{
		{
			name: "no_api_key",
			e:    "https://api.ipdata.co/",
			err:  "apiKey cannot be an empty string",
		},
		{
			name: "with_api_key",
			i:    "testAPIkey",
			e:    "https://api.ipdata.co/",
			k:    "testAPIkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.i)

			if cont := testErrCheck(t, "NewClient()", tt.err, err); !cont {
				return
			}

			if c.e != tt.e {
				t.Fatalf("cc.e = %q,want %q", c.e, tt.e)
			}

			if c.k != tt.k {
				t.Fatalf("cc.k = %q,want %q", c.k, tt.k)
			}

			if c.c == nil {
				t.Fatal("cc.c should not be nil")
			}
		})
	}
}

func TestNewEUClient(t *testing.T) {
	tests := []struct {
		name string
		i    string
		e    string
		k    string
		err  string
	}{
		{
			name: "no_api_key",
			e:    "https://eu-api.ipdata.co/",
			err:  "apiKey cannot be an empty string",
		},
		{
			name: "with_api_key",
			i:    "testAPIkey",
			e:    "https://eu-api.ipdata.co/",
			k:    "testAPIkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewEUClient(tt.i)

			if cont := testErrCheck(t, "NewEUClient()", tt.err, err); !cont {
				return
			}

			if c.e != tt.e {
				t.Fatalf("c.e = %q, want %q", c.e, tt.e)
			}

			if c.k != tt.k {
				t.Fatalf("c.k = %q, want %q", c.k, tt.k)
			}

			if c.c == nil {
				t.Fatal("c.c should not be nil")
			}
		})
	}
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}

	c, err := NewClient("testAPIkey", WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	if c.c != custom {
		t.Fatal("expected custom http.Client to be used")
	}

	if c.e != "https://api.ipdata.co/" {
		t.Fatalf("c.e = %q, want %q", c.e, "https://api.ipdata.co/")
	}
}

func TestNewEUClient_WithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}

	c, err := NewEUClient("testAPIkey", WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("NewEUClient() unexpected error: %v", err)
	}

	if c.c != custom {
		t.Fatal("expected custom http.Client to be used")
	}

	if c.e != "https://eu-api.ipdata.co/" {
		t.Fatalf("c.e = %q, want %q", c.e, "https://eu-api.ipdata.co/")
	}
}

const tjFlagURL = "https://ipdata.co/flags/us.png"

func Test_client_Lookup(t *testing.T) {
	ln, srvr, err := testHTTPServer("")
	if err != nil {
		t.Fatalf(`testHTTPServer("") returned unexpected error: %s`, err)
	}

	defer func() {
		_ = srvr.Close()
		_ = ln.Close()
	}()

	if err != nil {
		t.Fatalf("failed to parse URL: %s", err)
	}

	c := Client{
		c: newHTTPClient(),
		e: "http://" + ln.Addr().String() + "/",
		k: "testAPIkey",
	}

	tests := []struct {
		name string
		i    string
		o    IP
		e    string
	}{
		{
			name: "invalid_json",
			i:    "76.14.42.42",
			e:    "failed to parse JSON: unexpected end of JSON input",
		},
		{
			name: "private_ipv4",
			i:    "192.168.0.1",
			e:    "192.168.0.1 is a private IP address",
		},
		{
			name: "invalid_ip",
			i:    "bacon",
			e:    "bacon does not appear to be an IPv4 or IPv6 address",
		},
		{
			name: "rate_limited",
			i:    "8.8.8.8",
			e:    "You have either exceeded your quota or that API key does not exist. Get a free API Key at https://ipdata.co/registration.html or contact support@ipdata.co to upgrade or register for a paid plan at https://ipdata.co/pricing.html.",
		},
		{
			name: "valid_address",
			i:    "76.14.47.42",
			o: IP{
				IP: "76.14.47.42",
				ASN: ASN{
					ASN:    "AS11404",
					Name:   "vanoppen.biz LLC",
					Domain: "wavebroadband.com",
					Route:  "76.14.0.0/17",
					Type:   "isp",
				},
				Organization:  "vanoppen.biz LLC",
				City:          "San Francisco",
				Region:        "California",
				RegionCode:    "CA",
				Postal:        "94132",
				CountryName:   "United States",
				CountryCode:   "US",
				Flag:          tjFlagURL,
				EmojiFlag:     "\U0001F1FA\U0001F1F8",
				EmojiUnicode:  `U+1F1FA U+1F1F8`,
				ContinentName: "North America",
				ContinentCode: "NA",
				Latitude:      37.723,
				Longitude:     -122.4842,
				CallingCode:   "1",
				IsEU:          true,
				Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
				Currency: &Currency{
					Name:   "US Dollar",
					Code:   "USD",
					Symbol: "$",
					Native: "$",
					Plural: "US dollars",
				},
				Company: &Company{
					Name:    "vanoppen.biz LLC",
					Domain:  "wavebroadband.com",
					Network: "76.14.0.0/17",
					Type:    "isp",
				},
				Carrier: &Carrier{
					Name: "T-Mobile",
					MCC:  "310",
					MNC:  "260",
				},
				TimeZone: &TimeZone{
					Name:         "America/Los_Angeles",
					Abbreviation: "PST",
					Offset:       "-0800",
					IsDST:        false,
					CurrentTime:  "2019-02-27T15:00:32.745936-08:00",
				},
				Threat: &Threat{
					IsTOR:           false,
					IsProxy:         false,
					IsAnonymous:     false,
					IsKnownAttacker: false,
					IsKnownAbuser:   false,
					IsThreat:        true,
					IsBogon:         false,
					Blocklists:      []Blocklist{},
					Scores: Scores{
						VPNScore:    0,
						ProxyScore:  0,
						ThreatScore: 1,
						TrustScore:  99,
					},
				},
				Count:  "1234",
				Status: 200,
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			var ip IP
			var err error

			ip, err = c.Lookup(tt.i)

			if len(tt.e) > 0 {
				if err == nil {
					t.Fatal("error expected but was nil")
				}

				if !strings.Contains(err.Error(), tt.e) {
					t.Fatalf("error message %q not found in error: %s", tt.e, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Lookup(%q) unexpected error: %s", tt.i, err)
			}

			if a, b := ip.IP, tt.o.IP; a != b {
				t.Errorf("ip.IP = %q, want %q", a, b)
			}

			if ip.ASN != tt.o.ASN {
				t.Errorf("ip.ASN = %q, want %q", ip.ASN, tt.o.ASN)
			}

			if ip.Organization != tt.o.Organization {
				t.Errorf("ip.Organization = %q, want %q", ip.Organization, tt.o.Organization)
			}

			if ip.City != tt.o.City {
				t.Errorf("ip.City = %q, want %q", ip.City, tt.o.City)
			}

			if ip.Region != tt.o.Region {
				t.Errorf("ip.Region = %q, want %q", ip.Region, tt.o.Region)
			}

			if ip.Postal != tt.o.Postal {
				t.Errorf("ip.Postal = %q, want %q", ip.Postal, tt.o.Postal)
			}

			if ip.CountryName != tt.o.CountryName {
				t.Errorf("ip.CountryName = %q, want %q", ip.CountryName, tt.o.CountryName)
			}

			if ip.CountryCode != tt.o.CountryCode {
				t.Errorf("ip.CountryCode = %q, want %q", ip.CountryCode, tt.o.CountryCode)
			}

			if a, b := ip.Flag, tt.o.Flag; a != b {
				t.Errorf("ip.Flag = %q, want %q", a, b)
			}

			if ip.ContinentName != tt.o.ContinentName {
				t.Errorf("ip.ContinentName = %q, want %q", ip.ContinentName, tt.o.ContinentName)
			}

			if ip.ContinentCode != tt.o.ContinentCode {
				t.Errorf("ip.ContinentCode = %q, want %q", ip.ContinentCode, tt.o.ContinentCode)
			}

			if ip.Latitude != tt.o.Latitude {
				t.Errorf("ip.Latitude = %f, want %f", ip.Latitude, tt.o.Latitude)
			}

			if ip.Longitude != tt.o.Longitude {
				t.Errorf("ip.Longitude = %f, want %f", ip.Longitude, tt.o.Longitude)
			}

			if ip.CallingCode != tt.o.CallingCode {
				t.Errorf("ip.CallingCode = %q, want %q", ip.CallingCode, tt.o.CallingCode)
			}

			if *ip.Currency != *tt.o.Currency {
				t.Errorf("ip.Currency = %#v, want %#v", ip.Currency, tt.o.Currency)
			}

			if a, b := *ip.TimeZone, *tt.o.TimeZone; a != b {
				t.Errorf("ip.TimeZone = %#v, want %#v", a, b)
			}

			if diff := cmp.Diff(tt.o.Threat, ip.Threat); diff != "" {
				t.Errorf("ip.Threat differs: (-want +got)\n%s", diff)
			}

			if diff := cmp.Diff(tt.o.Company, ip.Company); diff != "" {
				t.Errorf("ip.Company differs: (-want +got)\n%s", diff)
			}

			if diff := cmp.Diff(tt.o.Carrier, ip.Carrier); diff != "" {
				t.Errorf("ip.Carrier differs: (-want +got)\n%s", diff)
			}

			if ip.Count != tt.o.Count {
				t.Errorf("ip.Count = %q, want %q", ip.Count, tt.o.Count)
			}

			if ip.Status != tt.o.Status {
				t.Errorf("ip.Status = %d, want %d", ip.Status, tt.o.Status)
			}
		})
	}
}

func Test_client_LookupFields(t *testing.T) {
	// query holds the query string of the last request the server received
	var query atomic.Pointer[url.Values]

	mux := http.NewServeMux()

	mux.HandleFunc("/76.14.47.42", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		q := r.URL.Query()
		query.Store(&q)

		if r.FormValue("api-key") != "testAPIkey" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "API key does not exist.")
			return
		}

		fields := r.FormValue("fields")
		if fields == "" {
			_, _ = io.WriteString(w, testJSONValid)
			return
		}

		// Return a partial response when fields are specified
		_, _ = io.WriteString(w, `{"ip": "76.14.47.42", "country_name": "United States"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	c := Client{
		c: newHTTPClient(),
		e: server.URL + "/",
		k: "testAPIkey",
	}

	// lastQuery returns the query string of the last request the server saw
	lastQuery := func(t *testing.T) url.Values {
		t.Helper()

		q := query.Load()
		if q == nil {
			t.Fatal("the server received no request")
		}

		return *q
	}

	t.Run("with_fields", func(t *testing.T) {
		ip, err := c.LookupFields("76.14.47.42", []string{"ip", "country_name"})
		if err != nil {
			t.Fatalf("LookupFields() unexpected error: %v", err)
		}

		q := lastQuery(t)

		if got, want := q.Get("fields"), "ip,country_name"; got != want {
			t.Errorf("request query fields = %q, want %q", got, want)
		}

		if got, want := q.Get("api-key"), "testAPIkey"; got != want {
			t.Errorf("request query api-key = %q, want %q", got, want)
		}

		if ip.IP != "76.14.47.42" {
			t.Errorf("ip.IP = %q, want %q", ip.IP, "76.14.47.42")
		}

		if ip.CountryName != "United States" {
			t.Errorf("ip.CountryName = %q, want %q", ip.CountryName, "United States")
		}

		// the partial response the server sends for a request with fields
		// has no city; a city means the full document came back
		if ip.City != "" {
			t.Errorf("ip.City = %q, want %q (fields were not applied)", ip.City, "")
		}
	})

	t.Run("no_fields", func(t *testing.T) {
		ip, err := c.LookupFields("76.14.47.42", nil)
		if err != nil {
			t.Fatalf("LookupFields() unexpected error: %v", err)
		}

		q := lastQuery(t)

		if _, ok := q["fields"]; ok {
			t.Errorf("request query fields = %q, want no fields parameter", q.Get("fields"))
		}

		if got, want := q.Get("api-key"), "testAPIkey"; got != want {
			t.Errorf("request query api-key = %q, want %q", got, want)
		}

		if ip.IP != "76.14.47.42" {
			t.Errorf("ip.IP = %q, want %q", ip.IP, "76.14.47.42")
		}

		if ip.CountryName != "United States" {
			t.Errorf("ip.CountryName = %q, want %q", ip.CountryName, "United States")
		}

		if ip.City != "San Francisco" {
			t.Errorf("ip.City = %q, want %q", ip.City, "San Francisco")
		}
	})
}

func Test_client_RawLookup(t *testing.T) {
	ln, srvr, err := testHTTPServer("")
	if err != nil {
		t.Fatalf(`testHTTPServer("") returned unexpected error: %s`, err)
	}

	defer func() {
		_ = srvr.Close()
		_ = ln.Close()
	}()

	c := Client{
		c: newHTTPClient(),
		e: "http://" + ln.Addr().String() + "/",
		k: "testAPIkey",
	}

	tests := []struct {
		c    Client
		name string
		i    string
		o    string
		e    string
	}{
		{
			c:    c,
			name: "invalid_request",
			i:    "%ƒail",
			e:    "error building request to look up %ƒail",
		},
		{
			c:    c,
			name: "private_ipv4",
			i:    "192.168.0.1",
			e:    "192.168.0.1 is a private IP address",
		},
		{
			c:    c,
			name: "invalid_ip",
			i:    "bacon",
			e:    "bacon does not appear to be an IPv4 or IPv6 address",
		},
		{
			c:    c,
			name: "rate_limited",
			i:    "8.8.8.8",
			e:    "You have either exceeded your quota or that API key does not exist. Get a free API Key at https://ipdata.co/registration.html or contact support@ipdata.co to upgrade or register for a paid plan at https://ipdata.co/pricing.html.",
		},
		{
			c:    c,
			name: "unexpected_error",
			i:    "8.4.0.3",
			e:    "unexpected HTTP status code",
		},
		{
			c:    c,
			name: "invalid_api-key",
			i:    "8.8.4.4",
			e:    "API key does not exist.",
		},
		{
			c:    c,
			name: "valid_address",
			i:    "76.14.47.42",
			o:    testJSONValid,
		},
		{
			c:    Client{c: newHTTPClient(), e: "http://127.0.0.1:8404/", k: "testAPIkey"},
			name: "tcp_conn_err",
			i:    "76.14.47.42",
			e:    `http request to "http://127.0.0.1:8404/76.14.47.42" failed`,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			var err error

			resp, err = tt.c.RawLookup(tt.i)

			if len(tt.e) > 0 {
				if err == nil {
					t.Fatal("error expected but was nil")
				}

				if !strings.Contains(err.Error(), tt.e) {
					t.Fatalf("error message %q not found in error: %s", tt.e, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("RawLookup(%q) unexpected error: %s", tt.i, err)
			}

			defer func() {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected error reading response body: %s", err)
			}

			if str := string(body); str != tt.o {
				t.Fatalf("resp.Body = %q, want %q", str, tt.o)
			}
		})
	}
}

func mustParseURL(u string) *url.URL {
	v, err := url.Parse(u)
	if err != nil {
		panic(err)
	}

	return v
}

func Test_newGetRequestWithContext(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		key    string
		params url.Values

		want *http.Request
		err  string
	}{
		{
			name: "no_url",
			err:  "url cannot be an empty string",
		},
		{
			name: "no_api_key",
			url:  "http://localhost/",
			err:  "apiKey cannot be an empty string",
		},
		{
			name: "url",
			key:  "abc123",
			url:  "http://localhost/",
			want: &http.Request{
				Header: map[string][]string{
					"User-Agent": {userAgent},
					"Accept":     {"application/json"},
				},
				URL: mustParseURL("http://localhost/?api-key=abc123"),
			},
		},
		{
			name:   "url_with_params",
			key:    "abc123",
			url:    "http://localhost/",
			params: url.Values{"fields": {"ip,country_name"}},
			want: &http.Request{
				Header: map[string][]string{
					"User-Agent": {userAgent},
					"Accept":     {"application/json"},
				},
				URL: mustParseURL("http://localhost/?api-key=abc123&fields=ip%2Ccountry_name"),
			},
		},
		{
			name:   "params_do_not_replace_api_key",
			key:    "abc123",
			url:    "http://localhost/",
			params: url.Values{"api-key": {"other"}, "fields": {"ip"}},
			want: &http.Request{
				Header: map[string][]string{
					"User-Agent": {userAgent},
					"Accept":     {"application/json"},
				},
				URL: mustParseURL("http://localhost/?api-key=abc123&fields=ip"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.params.Encode()

			got, err := newGetRequestWithContext(context.Background(), tt.url, tt.key, tt.params)
			if cont := testErrCheck(t, "newGetRequestWithContext()", tt.err, err); !cont {
				return
			}

			if gots, wants := got.URL.String(), tt.want.URL.String(); gots != wants {
				t.Fatalf("got.URL = %q, want %q", gots, wants)
			}

			if gots, wants := got.URL.Query().Get("fields"), tt.params.Get("fields"); gots != wants {
				t.Fatalf("fields query parameter = %q, want %q", gots, wants)
			}

			if after := tt.params.Encode(); after != before {
				t.Fatalf("params = %q after the call, want them unchanged (%q)", after, before)
			}

			if gots, wants := got.Header.Get("User-Agent"), tt.want.Header.Get("User-Agent"); gots != wants {
				t.Fatalf("User-Agent = %q, want %q", gots, wants)
			}

			if gots, wants := got.Header.Get("Accept"), tt.want.Header.Get("Accept"); gots != wants {
				t.Fatalf("Accept = %q, want %q", gots, wants)
			}
		})
	}
}

func Test_newBulkPostRequestWithContext(t *testing.T) {
	tests := []struct {
		name string
		url  string
		key  string
		ips  []string

		want *http.Request
		err  string
	}{
		{
			name: "no_url",
			err:  "url cannot be an empty string",
		},
		{
			name: "no_api_key",
			url:  "http://localhost/",
			err:  "apiKey cannot be an empty string",
		},
		{
			name: "no_ips",
			key:  "abc123",
			url:  "http://localhost/",
			err:  "must provide at least one IP",
		},
		{
			name: "url",
			key:  "abc123",
			url:  "http://localhost/",
			ips:  []string{"8.8.8.8", "8.8.4.4"},
			want: &http.Request{
				Header: map[string][]string{
					"User-Agent":   {userAgent},
					"Accept":       {"application/json"},
					"Content-Type": {"application/json"},
				},
				URL: mustParseURL("http://localhost/?api-key=abc123"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newBulkPostRequestWithContext(context.Background(), tt.url, tt.key, tt.ips)
			if cont := testErrCheck(t, "newBulkPostRequestWithContext()", tt.err, err); !cont {
				return
			}

			if gots, wants := got.URL.String(), tt.want.URL.String(); gots != wants {
				t.Fatalf("got.URL = %q, want %q", gots, wants)
			}

			if gots, wants := got.Header.Get("User-Agent"), tt.want.Header.Get("User-Agent"); gots != wants {
				t.Fatalf("User-Agent = %q, want %q", gots, wants)
			}

			if gots, wants := got.Header.Get("Content-Type"), tt.want.Header.Get("Content-Type"); gots != wants {
				t.Fatalf("Content-Type = %q, want %q", gots, wants)
			}
		})
	}
}

func Test_decodeIP(t *testing.T) {
	tests := []struct {
		name string
		i    string
		o    IP
		e    string
	}{
		{
			name: "invalid_json",
			i:    "garbage",
			e:    "failed to parse JSON:",
		},
		{
			name: "valid_json",
			i:    testJSONValid,
			o: IP{
				IP: "76.14.47.42",
				ASN: ASN{
					ASN:    "AS11404",
					Name:   "vanoppen.biz LLC",
					Domain: "wavebroadband.com",
					Route:  "76.14.0.0/17",
					Type:   "isp",
				},
				Organization:  "vanoppen.biz LLC",
				City:          "San Francisco",
				Region:        "California",
				RegionCode:    "CA",
				Postal:        "94132",
				CountryName:   "United States",
				CountryCode:   "US",
				Flag:          tjFlagURL,
				EmojiFlag:     "\U0001F1FA\U0001F1F8",
				EmojiUnicode:  `U+1F1FA U+1F1F8`,
				ContinentName: "North America",
				ContinentCode: "NA",
				Latitude:      37.723,
				Longitude:     -122.4842,
				CallingCode:   "1",
				IsEU:          true,
				Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
				Currency: &Currency{
					Name:   "US Dollar",
					Code:   "USD",
					Symbol: "$",
					Native: "$",
					Plural: "US dollars",
				},
				Company: &Company{
					Name:    "vanoppen.biz LLC",
					Domain:  "wavebroadband.com",
					Network: "76.14.0.0/17",
					Type:    "isp",
				},
				Carrier: &Carrier{
					Name: "T-Mobile",
					MCC:  "310",
					MNC:  "260",
				},
				TimeZone: &TimeZone{
					Name:         "America/Los_Angeles",
					Abbreviation: "PST",
					Offset:       "-0800",
					IsDST:        false,
					CurrentTime:  "2019-02-27T15:00:32.745936-08:00",
				},
				Threat: &Threat{
					IsTOR:           false,
					IsProxy:         false,
					IsAnonymous:     false,
					IsKnownAttacker: false,
					IsKnownAbuser:   false,
					IsThreat:        true,
					IsBogon:         false,
					Blocklists:      []Blocklist{},
					Scores: Scores{
						VPNScore:    0,
						ProxyScore:  0,
						ThreatScore: 1,
						TrustScore:  99,
					},
				},
				Count:  "1234",
				Status: 200,
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			ip, err := decodeIP(strings.NewReader(tt.i))

			if len(tt.e) > 0 {
				if err == nil {
					t.Fatal("error expected but was nil")
				}

				if !strings.Contains(err.Error(), tt.e) {
					t.Fatalf("error message %q not found in error: %s", tt.e, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("DecodeIP(%+v) returned an unexpected error: %s", tt.i, err)
			}

			if a, b := ip.IP, tt.o.IP; a != b {
				t.Errorf("ip.IP = %q, want %q", a, b)
			}

			if ip.ASN != tt.o.ASN {
				t.Errorf("ip.ASN = %q, want %q", ip.ASN, tt.o.ASN)
			}

			if ip.Organization != tt.o.Organization {
				t.Errorf("ip.Organization = %q, want %q", ip.Organization, tt.o.Organization)
			}

			if ip.City != tt.o.City {
				t.Errorf("ip.City = %q, want %q", ip.City, tt.o.City)
			}

			if ip.Region != tt.o.Region {
				t.Errorf("ip.Region = %q, want %q", ip.Region, tt.o.Region)
			}

			if ip.Postal != tt.o.Postal {
				t.Errorf("ip.Postal = %q, want %q", ip.Postal, tt.o.Postal)
			}

			if ip.CountryName != tt.o.CountryName {
				t.Errorf("ip.CountryName = %q, want %q", ip.CountryName, tt.o.CountryName)
			}

			if ip.CountryCode != tt.o.CountryCode {
				t.Errorf("ip.CountryCode = %q, want %q", ip.CountryCode, tt.o.CountryCode)
			}

			if a, b := ip.Flag, tt.o.Flag; a != b {
				t.Errorf("ip.Flag = %q, want %q", a, b)
			}

			if ip.ContinentName != tt.o.ContinentName {
				t.Errorf("ip.ContinentName = %q, want %q", ip.ContinentName, tt.o.ContinentName)
			}

			if ip.ContinentCode != tt.o.ContinentCode {
				t.Errorf("ip.ContinentCode = %q, want %q", ip.ContinentCode, tt.o.ContinentCode)
			}

			if ip.Latitude != tt.o.Latitude {
				t.Errorf("ip.Latitude = %f, want %f", ip.Latitude, tt.o.Latitude)
			}

			if ip.Longitude != tt.o.Longitude {
				t.Errorf("ip.Longitude = %f, want %f", ip.Longitude, tt.o.Longitude)
			}

			if ip.CallingCode != tt.o.CallingCode {
				t.Errorf("ip.CallingCode = %q, want %q", ip.CallingCode, tt.o.CallingCode)
			}

			if ip.IsEU != tt.o.IsEU {
				t.Errorf("ip.IsEU = %v, want %v", ip.IsEU, tt.o.IsEU)
			}

			if ip.EmojiUnicode != tt.o.EmojiUnicode {
				t.Errorf("ip.EmojiUnicode = %q, want %q", ip.EmojiUnicode, tt.o.EmojiUnicode)
			}

			if a, b := len(ip.Languages), len(tt.o.Languages); a != b {
				t.Errorf("len(ip.Languages) = %d, want %d", a, b)
			}

			fn := func(t *testing.T, x, y []Language) {
				t.Helper()

				for i := range tt.o.Languages {
					if i >= len(ip.Languages) {
						t.Errorf("ip.Languages[%d] = [not present], want %#v", i, tt.o.Languages[i])
						continue
					}

					a, b := ip.Languages[i], tt.o.Languages[i]

					if a != b {
						t.Errorf("ip.Languages[%d] = %#v, want %#v", i, a, b)
					}
				}
			}

			if len(ip.Languages) >= len(tt.o.Languages) {
				fn(t, ip.Languages, tt.o.Languages)
			} else {
				fn(t, tt.o.Languages, ip.Languages)
			}

			if *ip.Currency != *tt.o.Currency {
				t.Errorf("ip.Currency = %#v, want %#v", ip.Currency, tt.o.Currency)
			}

			if a, b := *ip.TimeZone, *tt.o.TimeZone; a != b {
				t.Errorf("ip.TimeZone = %#v, want %#v", a, b)
			}

			if diff := cmp.Diff(tt.o.Threat, ip.Threat); diff != "" {
				t.Errorf("ip.Threat differs: (-want +got)\n%s", diff)
			}

			if diff := cmp.Diff(tt.o.Company, ip.Company); diff != "" {
				t.Errorf("ip.Company differs: (-want +got)\n%s", diff)
			}

			if diff := cmp.Diff(tt.o.Carrier, ip.Carrier); diff != "" {
				t.Errorf("ip.Carrier differs: (-want +got)\n%s", diff)
			}

			if ip.Count != tt.o.Count {
				t.Errorf("ip.Count = %q, want %q", ip.Count, tt.o.Count)
			}

			if ip.Status != tt.o.Status {
				t.Errorf("ip.Status = %d, want %d", ip.Status, tt.o.Status)
			}
		})
	}
}

func TestClient_RawBulkLookup(t *testing.T) {
	server := testBulkHTTPServer()

	defer func() {
		server.CloseClientConnections()
		server.Close()
	}()

	client := &Client{
		c: newHTTPClient(),
		e: "http://127.0.0.1:9085/",
	}

	tests := []struct {
		name string
		ips  []string

		setKey    string
		serverURL string

		wantStatus int
		wantBody   string
		err        string
	}{
		{
			name: "no_api_key",
			err:  "error building bulk lookup request: apiKey cannot be an empty string",
		},
		{
			name:   "no_ips",
			setKey: "badAPIkey",
			err:    "error building bulk lookup request: must provide at least one IP",
		},
		{
			name: "bad_host",
			ips:  []string{"1.1.1.1", "8.8.8.8"},
			err:  `http request to "http://127.0.0.1:9085/bulk" failed:`,
		},
		{
			name:      "bad_api_key",
			ips:       []string{"1.1.1.1", "8.8.8.8"},
			serverURL: server.URL + "/",
			err:       `You have either exceeded your quota or that API key does not exist. Get a free API Key at https://ipdata.co/registration.html or contact support@ipdata.co to upgrade or register for a paid plan at https://ipdata.co/pricing.html.`,
		},
		{
			name:   "bad_json",
			ips:    []string{"1.1.1.1", "8.8.4.4"},
			setKey: "testAPIkey",
			err:    `request failed (unexpected response): 403 Forbidden: invalid character 'i' looking for beginning of object key string`,
		},
		{
			name:       "good_ips",
			ips:        []string{"1.1.1.1", "8.8.8.8"},
			wantStatus: 200,
			wantBody:   testBulkJSONValid,
		},
		{
			name:       "good_ips_with_localhost",
			ips:        []string{"1.1.1.1", "8.8.8.8", "127.0.0.1"},
			wantStatus: 200,
			wantBody:   testBulkJSONWithLocalhost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setKey != "" {
				client.k = tt.setKey
			}

			if tt.serverURL != "" {
				client.e = tt.serverURL
			}

			got, err := client.RawBulkLookup(tt.ips)
			if cont := testErrCheck(t, "client.RawBulkLookup()", tt.err, err); !cont {
				return
			}

			defer func() {
				_, _ = io.Copy(io.Discard, got.Body)
				_ = got.Body.Close()
			}()

			if got.StatusCode != tt.wantStatus {
				t.Fatalf("got.StatusCode = %d, want %d", got.StatusCode, tt.wantStatus)
			}

			body, err := io.ReadAll(got.Body)
			testErrCheck(t, "io.ReadAll()", "", err)

			if b := string(body); b != tt.wantBody {
				t.Fatalf("got.Body = %q, want %q", b, tt.wantBody)
			}
		})
	}
}

func TestClient_BulkLookup(t *testing.T) {
	server := testBulkHTTPServer()

	defer func() {
		server.CloseClientConnections()
		server.Close()
	}()

	client := &Client{
		c: newHTTPClient(),
		e: "http://127.0.0.1:9085/",
	}

	tests := []struct {
		name string
		ips  []string

		setKey    string
		serverURL string

		want []*IP

		errStr string
		err    Error
	}{
		{
			name:   "no_api_key",
			errStr: "error building bulk lookup request: apiKey cannot be an empty string",
		},
		{
			name:      "bad_api_key",
			ips:       []string{"1.1.1.1", "8.8.8.8"},
			serverURL: server.URL + "/",
			setKey:    "badAPIkey",
			err: Error{
				m: `You have either exceeded your quota or that API key does not exist. Get a free API Key at https://ipdata.co/registration.html or contact support@ipdata.co to upgrade or register for a paid plan at https://ipdata.co/pricing.html.`,
				c: 403,
				i: -1,
			},
		},
		{
			name:   "bad_json",
			ips:    []string{"1.1.1.1", "4.4.2.2"},
			setKey: "testAPIkey",
			errStr: `failed to parse JSON: invalid character 'i' looking for beginning of object key string`,
		},
		{
			name: "good_ips",
			ips:  []string{"1.1.1.1", "8.8.8.8"},
			want: []*IP{
				{
					IP: "1.1.1.1",
					ASN: ASN{
						ASN:    "AS13335",
						Name:   "Cloudflare, Inc.",
						Domain: "cloudflare.com",
						Route:  "1.1.1.0/24",
						Type:   "hosting",
					},
					CountryName:   "Australia",
					CountryCode:   "AU",
					Flag:          "https://ipdata.co/flags/au.png",
					EmojiFlag:     "\U0001F1E6\U0001F1FA",
					EmojiUnicode:  "U+1F1E6 U+1F1FA",
					ContinentName: "Oceania",
					ContinentCode: "OC",
					Latitude:      -33.494,
					Longitude:     143.2104,
					CallingCode:   "61",
					IsEU:          false,
					Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
					Currency: &Currency{
						Name:   "Australian Dollar",
						Code:   "AUD",
						Symbol: "AU$",
						Native: "$",
						Plural: "Australian dollars",
					},
					Company: &Company{
						Name:    "Cloudflare, Inc.",
						Domain:  "cloudflare.com",
						Network: "1.1.1.0/24",
						Type:    "hosting",
					},
					TimeZone: &TimeZone{
						Name:         "Australia/Sydney",
						Abbreviation: "AEDT",
						Offset:       "+1100",
						IsDST:        true,
						CurrentTime:  "2019-11-02T20:27:59.021189+11:00",
					},
					Threat: &Threat{
						IsTOR:           false,
						IsProxy:         false,
						IsAnonymous:     false,
						IsKnownAttacker: false,
						IsKnownAbuser:   true,
						IsThreat:        true,
						IsBogon:         false,
						Blocklists:      []Blocklist{},
						Scores: Scores{
							VPNScore:    0,
							ProxyScore:  0,
							ThreatScore: 5,
							TrustScore:  70,
						},
					},
					Count: "1551",
				},
				{
					IP: "8.8.8.8",
					ASN: ASN{
						ASN:    "AS15169",
						Name:   "Google LLC",
						Domain: "google.com",
						Route:  "8.8.8.0/24",
						Type:   "hosting",
					},
					CountryName:   "United States",
					CountryCode:   "US",
					Flag:          "https://ipdata.co/flags/us.png",
					EmojiFlag:     "\U0001F1FA\U0001F1F8",
					EmojiUnicode:  "U+1F1FA U+1F1F8",
					ContinentName: "North America",
					ContinentCode: "NA",
					Latitude:      37.751,
					Longitude:     -97.822,
					CallingCode:   "1",
					IsEU:          false,
					Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
					Currency: &Currency{
						Name:   "US Dollar",
						Code:   "USD",
						Symbol: "$",
						Native: "$",
						Plural: "US dollars",
					},
					Company: &Company{
						Name:    "Google LLC",
						Domain:  "google.com",
						Network: "8.8.8.0/24",
						Type:    "business",
					},
					TimeZone: &TimeZone{
						Name:         "America/Chicago",
						Abbreviation: "CDT",
						Offset:       "-0500",
						IsDST:        true,
						CurrentTime:  "2019-11-02T04:27:59.022393-05:00",
					},
					Threat: &Threat{
						IsTOR:           false,
						IsProxy:         false,
						IsAnonymous:     false,
						IsKnownAttacker: false,
						IsKnownAbuser:   false,
						IsThreat:        false,
						IsBogon:         false,
						Blocklists:      []Blocklist{},
						Scores: Scores{
							TrustScore: 100,
						},
					},
					Count: "1551",
				},
			},
		},
		{
			name: "good_ips_with_localhost",
			ips:  []string{"1.1.1.1", "8.8.8.8", "127.0.0.1"},
			err: Error{
				m: `127.0.0.1 is a private IP address`,
				c: 200,
				i: 2,
			},
			want: []*IP{
				{
					IP: "1.1.1.1",
					ASN: ASN{
						ASN:    "AS13335",
						Name:   "Cloudflare, Inc.",
						Domain: "cloudflare.com",
						Route:  "1.1.1.0/24",
						Type:   "hosting",
					},
					CountryName:   "Australia",
					CountryCode:   "AU",
					Flag:          "https://ipdata.co/flags/au.png",
					EmojiFlag:     "\U0001F1E6\U0001F1FA",
					EmojiUnicode:  "U+1F1E6 U+1F1FA",
					ContinentName: "Oceania",
					ContinentCode: "OC",
					Latitude:      -33.494,
					Longitude:     143.2104,
					CallingCode:   "61",
					IsEU:          false,
					Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
					Currency: &Currency{
						Name:   "Australian Dollar",
						Code:   "AUD",
						Symbol: "AU$",
						Native: "$",
						Plural: "Australian dollars",
					},
					Company: &Company{
						Name:    "Cloudflare, Inc.",
						Domain:  "cloudflare.com",
						Network: "1.1.1.0/24",
						Type:    "hosting",
					},
					TimeZone: &TimeZone{
						Name:         "Australia/Sydney",
						Abbreviation: "AEDT",
						Offset:       "+1100",
						IsDST:        true,
						CurrentTime:  "2019-11-02T20:27:59.021189+11:00",
					},
					Threat: &Threat{
						IsTOR:           false,
						IsProxy:         false,
						IsAnonymous:     false,
						IsKnownAttacker: false,
						IsKnownAbuser:   true,
						IsThreat:        true,
						IsBogon:         false,
						Blocklists:      []Blocklist{},
						Scores: Scores{
							VPNScore:    0,
							ProxyScore:  0,
							ThreatScore: 5,
							TrustScore:  70,
						},
					},
					Count: "1551",
				},
				{
					IP: "8.8.8.8",
					ASN: ASN{
						ASN:    "AS15169",
						Name:   "Google LLC",
						Domain: "google.com",
						Route:  "8.8.8.0/24",
						Type:   "hosting",
					},
					CountryName:   "United States",
					CountryCode:   "US",
					Flag:          "https://ipdata.co/flags/us.png",
					EmojiFlag:     "\U0001F1FA\U0001F1F8",
					EmojiUnicode:  "U+1F1FA U+1F1F8",
					ContinentName: "North America",
					ContinentCode: "NA",
					Latitude:      37.751,
					Longitude:     -97.822,
					CallingCode:   "1",
					IsEU:          false,
					Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
					Currency: &Currency{
						Name:   "US Dollar",
						Code:   "USD",
						Symbol: "$",
						Native: "$",
						Plural: "US dollars",
					},
					Company: &Company{
						Name:    "Google LLC",
						Domain:  "google.com",
						Network: "8.8.8.0/24",
						Type:    "business",
					},
					TimeZone: &TimeZone{
						Name:         "America/Chicago",
						Abbreviation: "CDT",
						Offset:       "-0500",
						IsDST:        true,
						CurrentTime:  "2019-11-02T04:27:59.022393-05:00",
					},
					Threat: &Threat{
						IsTOR:           false,
						IsProxy:         false,
						IsAnonymous:     false,
						IsKnownAttacker: false,
						IsKnownAbuser:   false,
						IsThreat:        false,
						IsBogon:         false,
						Blocklists:      []Blocklist{},
						Scores: Scores{
							TrustScore: 100,
						},
					},
					Count: "1551",
				},
				nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setKey != "" {
				client.k = tt.setKey
			}

			if tt.serverURL != "" {
				client.e = tt.serverURL
			}

			got, err := client.BulkLookup(tt.ips)

			if iperr, ok := err.(Error); ok {
				if iperr != tt.err {
					t.Fatalf("iperr: %#v, want %#v", iperr, tt.err)
				}
			} else {
				if cont := testErrCheck(t, "client.RawBulkLookup()", tt.errStr, err); !cont {
					return
				}
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("IP slice differs: (-want +got)\n%s", diff)
			}
		})
	}
}

const testJSONValid = `{
	"ip": "76.14.47.42",
	"city": "San Francisco",
	"region": "California",
	"region_code": "CA",
	"country_name": "United States",
	"country_code": "US",
	"continent_name": "North America",
	"continent_code": "NA",
	"latitude": 37.723,
	"longitude": -122.4842,
	"asn": {
		"asn": "AS11404",
		"name": "vanoppen.biz LLC",
		"domain": "wavebroadband.com",
		"route": "76.14.0.0/17",
		"type": "isp"
	},
	"organisation": "vanoppen.biz LLC",
	"postal": "94132",
	"calling_code": "1",
	"flag": "https://ipdata.co/flags/us.png",
	"emoji_flag": "\ud83c\uddfa\ud83c\uddf8",
	"emoji_unicode": "U+1F1FA U+1F1F8",
	"is_eu": true,
	"languages": [
		{
			"name": "English",
			"native": "English",
			"code": "en"
		}
	],
	"currency": {
		"name": "US Dollar",
		"code": "USD",
		"symbol": "$",
		"native": "$",
		"plural": "US dollars"
	},
	"company": {
		"name": "vanoppen.biz LLC",
		"domain": "wavebroadband.com",
		"network": "76.14.0.0/17",
		"type": "isp"
	},
	"carrier": {
		"name": "T-Mobile",
		"mcc": "310",
		"mnc": "260"
	},
	"time_zone": {
		"name": "America/Los_Angeles",
		"abbr": "PST",
		"offset": "-0800",
		"is_dst": false,
		"current_time": "2019-02-27T15:00:32.745936-08:00"
	},
	"threat": {
		"is_tor": false,
		"is_vpn": false,
		"is_icloud_relay": false,
		"is_proxy": false,
		"is_datacenter": false,
		"is_anonymous": false,
		"is_known_attacker": false,
		"is_known_abuser": false,
		"is_threat": true,
		"is_bogon": false,
		"blocklists": [],
		"scores": {
			"vpn_score": 0,
			"proxy_score": 0,
			"threat_score": 1,
			"trust_score": 99
		}
	},
	"count": "1234",
	"status": 200
}`

const testBulkJSONValid = `[
  {
    "ip": "1.1.1.1",
    "is_eu": false,
    "city": null,
    "region": null,
    "region_code": null,
    "country_name": "Australia",
    "country_code": "AU",
    "continent_name": "Oceania",
    "continent_code": "OC",
    "latitude": -33.494,
    "longitude": 143.2104,
    "postal": null,
    "calling_code": "61",
    "flag": "https://ipdata.co/flags/au.png",
    "emoji_flag": "\ud83c\udde6\ud83c\uddfa",
    "emoji_unicode": "U+1F1E6 U+1F1FA",
    "asn": {
      "asn": "AS13335",
      "name": "Cloudflare, Inc.",
      "domain": "cloudflare.com",
      "route": "1.1.1.0/24",
      "type": "hosting"
    },
    "company": {
      "name": "Cloudflare, Inc.",
      "domain": "cloudflare.com",
      "network": "1.1.1.0/24",
      "type": "hosting"
    },
    "languages": [
      {
        "name": "English",
        "native": "English",
        "code": "en"
      }
    ],
    "currency": {
      "name": "Australian Dollar",
      "code": "AUD",
      "symbol": "AU$",
      "native": "$",
      "plural": "Australian dollars"
    },
    "time_zone": {
      "name": "Australia/Sydney",
      "abbr": "AEDT",
      "offset": "+1100",
      "is_dst": true,
      "current_time": "2019-11-02T20:27:59.021189+11:00"
    },
    "threat": {
      "is_tor": false,
      "is_vpn": false,
      "is_icloud_relay": false,
      "is_proxy": false,
      "is_datacenter": false,
      "is_anonymous": false,
      "is_known_attacker": false,
      "is_known_abuser": true,
      "is_threat": true,
      "is_bogon": false,
      "blocklists": [],
      "scores": {
        "vpn_score": 0,
        "proxy_score": 0,
        "threat_score": 5,
        "trust_score": 70
      }
    },
    "count": "1551"
  },
  {
    "ip": "8.8.8.8",
    "is_eu": false,
    "city": null,
    "region": null,
    "region_code": null,
    "country_name": "United States",
    "country_code": "US",
    "continent_name": "North America",
    "continent_code": "NA",
    "latitude": 37.751,
    "longitude": -97.822,
    "postal": null,
    "calling_code": "1",
    "flag": "https://ipdata.co/flags/us.png",
    "emoji_flag": "\ud83c\uddfa\ud83c\uddf8",
    "emoji_unicode": "U+1F1FA U+1F1F8",
    "asn": {
      "asn": "AS15169",
      "name": "Google LLC",
      "domain": "google.com",
      "route": "8.8.8.0/24",
      "type": "hosting"
    },
    "company": {
      "name": "Google LLC",
      "domain": "google.com",
      "network": "8.8.8.0/24",
      "type": "business"
    },
    "languages": [
      {
        "name": "English",
        "native": "English",
        "code": "en"
      }
    ],
    "currency": {
      "name": "US Dollar",
      "code": "USD",
      "symbol": "$",
      "native": "$",
      "plural": "US dollars"
    },
    "time_zone": {
      "name": "America/Chicago",
      "abbr": "CDT",
      "offset": "-0500",
      "is_dst": true,
      "current_time": "2019-11-02T04:27:59.022393-05:00"
    },
    "threat": {
      "is_tor": false,
      "is_vpn": false,
      "is_icloud_relay": false,
      "is_proxy": false,
      "is_datacenter": false,
      "is_anonymous": false,
      "is_known_attacker": false,
      "is_known_abuser": false,
      "is_threat": false,
      "is_bogon": false,
      "blocklists": [],
      "scores": {
        "vpn_score": 0,
        "proxy_score": 0,
        "threat_score": 0,
        "trust_score": 100
      }
    },
    "count": "1551"
  }
]`

const testBulkJSONWithLocalhost = `[
  {
    "ip": "1.1.1.1",
    "is_eu": false,
    "city": null,
    "region": null,
    "region_code": null,
    "country_name": "Australia",
    "country_code": "AU",
    "continent_name": "Oceania",
    "continent_code": "OC",
    "latitude": -33.494,
    "longitude": 143.2104,
    "postal": null,
    "calling_code": "61",
    "flag": "https://ipdata.co/flags/au.png",
    "emoji_flag": "\ud83c\udde6\ud83c\uddfa",
    "emoji_unicode": "U+1F1E6 U+1F1FA",
    "asn": {
      "asn": "AS13335",
      "name": "Cloudflare, Inc.",
      "domain": "cloudflare.com",
      "route": "1.1.1.0/24",
      "type": "hosting"
    },
    "company": {
      "name": "Cloudflare, Inc.",
      "domain": "cloudflare.com",
      "network": "1.1.1.0/24",
      "type": "hosting"
    },
    "languages": [
      {
        "name": "English",
        "native": "English",
        "code": "en"
      }
    ],
    "currency": {
      "name": "Australian Dollar",
      "code": "AUD",
      "symbol": "AU$",
      "native": "$",
      "plural": "Australian dollars"
    },
    "time_zone": {
      "name": "Australia/Sydney",
      "abbr": "AEDT",
      "offset": "+1100",
      "is_dst": true,
      "current_time": "2019-11-02T20:27:59.021189+11:00"
    },
    "threat": {
      "is_tor": false,
      "is_vpn": false,
      "is_icloud_relay": false,
      "is_proxy": false,
      "is_datacenter": false,
      "is_anonymous": false,
      "is_known_attacker": false,
      "is_known_abuser": true,
      "is_threat": true,
      "is_bogon": false,
      "blocklists": [],
      "scores": {
        "vpn_score": 0,
        "proxy_score": 0,
        "threat_score": 5,
        "trust_score": 70
      }
    },
    "count": "1551"
  },
  {
    "ip": "8.8.8.8",
    "is_eu": false,
    "city": null,
    "region": null,
    "region_code": null,
    "country_name": "United States",
    "country_code": "US",
    "continent_name": "North America",
    "continent_code": "NA",
    "latitude": 37.751,
    "longitude": -97.822,
    "postal": null,
    "calling_code": "1",
    "flag": "https://ipdata.co/flags/us.png",
    "emoji_flag": "\ud83c\uddfa\ud83c\uddf8",
    "emoji_unicode": "U+1F1FA U+1F1F8",
    "asn": {
      "asn": "AS15169",
      "name": "Google LLC",
      "domain": "google.com",
      "route": "8.8.8.0/24",
      "type": "hosting"
    },
    "company": {
      "name": "Google LLC",
      "domain": "google.com",
      "network": "8.8.8.0/24",
      "type": "business"
    },
    "languages": [
      {
        "name": "English",
        "native": "English",
        "code": "en"
      }
    ],
    "currency": {
      "name": "US Dollar",
      "code": "USD",
      "symbol": "$",
      "native": "$",
      "plural": "US dollars"
    },
    "time_zone": {
      "name": "America/Chicago",
      "abbr": "CDT",
      "offset": "-0500",
      "is_dst": true,
      "current_time": "2019-11-02T04:27:59.022393-05:00"
    },
    "threat": {
      "is_tor": false,
      "is_vpn": false,
      "is_icloud_relay": false,
      "is_proxy": false,
      "is_datacenter": false,
      "is_anonymous": false,
      "is_known_attacker": false,
      "is_known_abuser": false,
      "is_threat": false,
      "is_bogon": false,
      "blocklists": [],
      "scores": {
        "vpn_score": 0,
        "proxy_score": 0,
        "threat_score": 0,
        "trust_score": 100
      }
    },
    "count": "1551"
  },
  {
    "message": "127.0.0.1 is a private IP address"
  }
]`

// roundTripperFunc adapts a function to http.RoundTripper. It deliberately has
// no CloseIdleConnections method.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// connCounter counts the TCP connections an *http.Server accepted.
type connCounter struct {
	n atomic.Int32
}

func (cc *connCounter) connState(_ net.Conn, s http.ConnState) {
	if s == http.StateNew {
		cc.n.Add(1)
	}
}

// testReuseHandler serves canned lookup, error and bulk responses without
// checking the API key.
func testReuseHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/76.14.47.42", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testJSONValid)
	})

	mux.HandleFunc("/192.168.0.1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message": "192.168.0.1 is a private IP address"}`)
	})

	mux.HandleFunc("/bulk", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testBulkJSONValid)
	})

	return mux
}

// trustServerCert makes the transport of hc trust the certificate of the
// httptest TLS server srv. It must run before hc sends its first request.
func trustServerCert(t *testing.T, hc *http.Client, srv *httptest.Server) {
	t.Helper()

	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("hc.Transport is %T, want *http.Transport", hc.Transport)
	}

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
}

func Test_newHTTPClient_transport(t *testing.T) {
	tr, ok := newHTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatal("newHTTPClient().Transport is not an *http.Transport")
	}

	if !tr.ForceAttemptHTTP2 {
		t.Error("tr.ForceAttemptHTTP2 = false, want true")
	}

	if tr.HTTP2 == nil {
		t.Fatal("tr.HTTP2 = nil, want HTTP/2 keepalive configuration")
	}

	if got, want := tr.HTTP2.SendPingTimeout, 30*time.Second; got != want {
		t.Errorf("tr.HTTP2.SendPingTimeout = %s, want %s", got, want)
	}

	if got, want := tr.HTTP2.PingTimeout, 15*time.Second; got != want {
		t.Errorf("tr.HTTP2.PingTimeout = %s, want %s", got, want)
	}

	if got, want := tr.IdleConnTimeout, 60*time.Second; got != want {
		t.Errorf("tr.IdleConnTimeout = %s, want %s", got, want)
	}

	if tr.Proxy == nil {
		t.Error("tr.Proxy = nil, want http.ProxyFromEnvironment")
	}
}

func Test_newHTTPClient_http2(t *testing.T) {
	srv := httptest.NewUnstartedServer(testReuseHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	hc := newHTTPClient()
	trustServerCert(t, hc, srv)

	c := Client{c: hc, e: srv.URL + "/", k: "testAPIkey"}

	resp, err := c.RawLookup("76.14.47.42")
	if err != nil {
		t.Fatalf("RawLookup() unexpected error: %v", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("resp.Proto = %q, want %q", resp.Proto, "HTTP/2.0")
	}

	if resp.TLS == nil {
		t.Fatal("resp.TLS = nil, want the TLS connection state")
	}

	if resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("resp.TLS.NegotiatedProtocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
	}

	ip, err := c.Lookup("76.14.47.42")
	if err != nil {
		t.Fatalf("Lookup() unexpected error: %v", err)
	}

	if ip.IP != "76.14.47.42" {
		t.Fatalf("ip.IP = %q, want %q", ip.IP, "76.14.47.42")
	}
}

func Test_client_connectionReuse(t *testing.T) {
	tests := []struct {
		name  string
		tls   bool
		proto string
	}{
		{name: "http1_keepalive", proto: "HTTP/1.1"},
		{name: "https_http2", tls: true, proto: "HTTP/2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conns connCounter

			srv := httptest.NewUnstartedServer(testReuseHandler())
			srv.Config.ConnState = conns.connState

			hc := newHTTPClient()

			if tt.tls {
				srv.EnableHTTP2 = true
				srv.StartTLS()
				trustServerCert(t, hc, srv)
			} else {
				srv.Start()
			}

			defer srv.Close()

			c := Client{c: hc, e: srv.URL + "/", k: "testAPIkey"}

			for i := 0; i < 5; i++ {
				if _, err := c.Lookup("76.14.47.42"); err != nil {
					t.Fatalf("Lookup() #%d unexpected error: %v", i+1, err)
				}
			}

			// error responses must hand their connection back as well
			if _, err := c.Lookup("192.168.0.1"); err == nil {
				t.Fatal("Lookup() of a private address: error expected but was nil")
			}

			if _, err := c.RawLookup("192.168.0.1"); err == nil {
				t.Fatal("RawLookup() of a private address: error expected but was nil")
			}

			for i := 0; i < 3; i++ {
				if _, err := c.BulkLookup([]string{"1.1.1.1", "8.8.8.8"}); err != nil {
					t.Fatalf("BulkLookup() #%d unexpected error: %v", i+1, err)
				}
			}

			resp, err := c.RawLookup("76.14.47.42")
			if err != nil {
				t.Fatalf("RawLookup() unexpected error: %v", err)
			}

			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			if resp.Proto != tt.proto {
				t.Errorf("resp.Proto = %q, want %q", resp.Proto, tt.proto)
			}

			if n := conns.n.Load(); n != 1 {
				t.Fatalf("server accepted %d connections for 11 sequential requests, want 1", n)
			}

			// closing the idle connection forces the next request to dial again
			c.CloseIdleConnections()

			if _, err := c.Lookup("76.14.47.42"); err != nil {
				t.Fatalf("Lookup() after CloseIdleConnections() unexpected error: %v", err)
			}

			if n := conns.n.Load(); n != 2 {
				t.Fatalf("server accepted %d connections after CloseIdleConnections(), want 2", n)
			}
		})
	}
}

func TestClient_CloseIdleConnections(t *testing.T) {
	// a zero Client has no *http.Client and must not panic
	Client{}.CloseIdleConnections()

	// no Transport: delegates to http.DefaultTransport
	c, err := NewClient("testAPIkey", WithHTTPClient(&http.Client{}))
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	c.CloseIdleConnections()

	// a transport without a CloseIdleConnections method is a no-op
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("not used")
	})

	c, err = NewEUClient("testAPIkey", WithHTTPClient(&http.Client{Transport: rt}))
	if err != nil {
		t.Fatalf("NewEUClient() unexpected error: %v", err)
	}

	c.CloseIdleConnections()
}

// actions of a scriptedServer, one per request received
const (
	srvRespond = iota // answer with 200 and the configured body
	srvDrop           // read the request, then close the connection without answering
	srvPartial        // write the start of a response, then close the connection
	srvReject         // answer with a 403 API error
)

// scriptedServer is a raw HTTP/1.1 keep-alive server that follows a
// per-request script, so a test can drop a pooled connection at a precise
// point. Requests beyond the script are answered normally.
type scriptedServer struct {
	ln     net.Listener
	body   string
	script []int
	conns  atomic.Int32
	reqs   atomic.Int32
}

func newScriptedServer(t *testing.T, body string, script ...int) *scriptedServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() unexpected error: %v", err)
	}

	s := &scriptedServer{ln: ln, body: body, script: script}

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			s.conns.Add(1)

			go s.serve(conn)
		}
	}()

	return s
}

func (s *scriptedServer) url() string {
	return "http://" + s.ln.Addr().String() + "/"
}

func (s *scriptedServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()

		n := int(s.reqs.Add(1)) - 1

		action := srvRespond
		if n < len(s.script) {
			action = s.script[n]
		}

		switch action {
		case srvDrop:
			return
		case srvPartial:
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
			return
		case srvReject:
			const msg = `{"message":"rejected"}`
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(msg), msg)
		default:
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(s.body), s.body)
		}
	}
}

func TestClient_BulkLookup_staleConnectionRetry(t *testing.T) {
	ips := []string{"1.1.1.1", "8.8.8.8"}

	tests := []struct {
		name      string
		script    []int
		wantErr   string // substring of the second call's error, empty for success
		wantReqs  int32
		wantConns int32
	}{
		{
			// The pooled connection dies after the request was written and
			// before any response byte: the POST is replayed once, on a
			// fresh connection.
			name:      "reused_connection_dropped_is_retried_once",
			script:    []int{srvRespond, srvDrop, srvRespond},
			wantReqs:  3,
			wantConns: 2,
		},
		{
			// The replay fails as well, on a connection that was not reused:
			// no further attempt is made.
			name:      "retry_happens_at_most_once",
			script:    []int{srvRespond, srvDrop, srvDrop},
			wantErr:   `http request to "` + "http://",
			wantReqs:  3,
			wantConns: 2,
		},
		{
			// A response that started to arrive is never replayed.
			name:      "no_retry_after_response_bytes",
			script:    []int{srvRespond, srvPartial},
			wantErr:   `http request to "` + "http://",
			wantReqs:  2,
			wantConns: 1,
		},
		{
			// An HTTP error status is never replayed.
			name:      "no_retry_on_http_status",
			script:    []int{srvRespond, srvReject},
			wantErr:   "rejected",
			wantReqs:  2,
			wantConns: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newScriptedServer(t, testBulkJSONValid, tt.script...)

			client := &Client{c: newHTTPClient(), e: srv.url(), k: "testAPIkey"}
			defer client.CloseIdleConnections()

			// the first call leaves one kept-alive connection in the pool
			if _, err := client.BulkLookup(ips); err != nil {
				t.Fatalf("first BulkLookup() unexpected error: %v", err)
			}

			got, err := client.BulkLookup(ips)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("second BulkLookup() unexpected error: %v", err)
				}

				if len(got) != 2 || got[0] == nil || got[0].IP != "1.1.1.1" || got[1] == nil || got[1].IP != "8.8.8.8" {
					t.Fatalf("second BulkLookup() = %v, want the two canned results", got)
				}
			} else {
				if err == nil {
					t.Fatal("second BulkLookup(): error expected but was nil")
				}

				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("second BulkLookup() error = %q, should contain %q", err, tt.wantErr)
				}
			}

			if n := srv.reqs.Load(); n != tt.wantReqs {
				t.Errorf("server received %d requests, want %d", n, tt.wantReqs)
			}

			if n := srv.conns.Load(); n != tt.wantConns {
				t.Errorf("server accepted %d connections, want %d", n, tt.wantConns)
			}
		})
	}
}

func TestClient_BulkLookup_freshConnectionNotRetried(t *testing.T) {
	ips := []string{"1.1.1.1", "8.8.8.8"}

	// the very first connection is dropped: a failure on a connection that was
	// never used before is not retried
	srv := newScriptedServer(t, testBulkJSONValid, srvDrop, srvRespond)

	client := &Client{c: newHTTPClient(), e: srv.url(), k: "testAPIkey"}
	defer client.CloseIdleConnections()

	if _, err := client.BulkLookup(ips); err == nil {
		t.Fatal("first BulkLookup(): error expected but was nil")
	}

	if n := srv.reqs.Load(); n != 1 {
		t.Fatalf("server received %d requests after the failed call, want 1", n)
	}

	// the client is still usable afterwards
	got, err := client.BulkLookup(ips)
	if err != nil {
		t.Fatalf("second BulkLookup() unexpected error: %v", err)
	}

	if len(got) != 2 || got[0] == nil || got[0].IP != "1.1.1.1" {
		t.Fatalf("second BulkLookup() = %v, want the two canned results", got)
	}

	if n := srv.conns.Load(); n != 2 {
		t.Fatalf("server accepted %d connections, want 2", n)
	}
}

// Fixtures for the is_satellite, is_anycast and dated blocklist additions.
// testJSONAnycast also carries a key the package does not model
// (region_type), which encoding/json has to ignore.

// testJSONSatellite is a lookup of a satellite ISP address (excerpt).
const testJSONSatellite = `{
  "ip": "98.97.34.0",
  "is_satellite": true,
  "is_eu": false,
  "city": "Seattle",
  "country_code": "US",
  "asn": { "asn": "AS14593", "name": "Space Exploration Technologies Corporation", "domain": "spacex.com", "route": "98.97.32.0/21", "type": "business" },
  "threat": { "is_tor": false, "is_vpn": false, "is_icloud_relay": false, "is_proxy": false, "is_datacenter": false, "is_anonymous": false, "is_known_attacker": false, "is_known_abuser": false, "is_threat": false, "is_bogon": false, "blocklists": [], "scores": { "vpn_score": 0, "proxy_score": 1, "threat_score": 8, "trust_score": 97 } },
  "count": "0"
}`

// testJSONAnycast is a complete lookup of an anycast address whose blocklist
// entries carry first_seen, last_seen and days_seen.
const testJSONAnycast = `{
  "ip": "8.8.8.8",
  "is_anycast": true,
  "is_eu": false,
  "city": null,
  "region": null,
  "region_code": null,
  "region_type": null,
  "country_name": "United States",
  "country_code": "US",
  "continent_name": "North America",
  "continent_code": "NA",
  "latitude": 39.7599983215332,
  "longitude": -98.5,
  "postal": null,
  "calling_code": "1",
  "flag": "https://ipdata.co/flags/us.png",
  "emoji_flag": "🇺🇸",
  "emoji_unicode": "U+1F1FA U+1F1F8",
  "asn": { "asn": "AS15169", "name": "Google LLC", "domain": "about.google", "route": "8.8.8.0/24", "type": "hosting" },
  "company": { "name": "Google LLC", "domain": "about.google", "network": "8.8.8.0/24", "type": "hosting" },
  "languages": [ { "name": "English", "native": "English", "code": "en" } ],
  "currency": { "name": "US Dollar", "code": "USD", "symbol": "$", "native": "$", "plural": "US dollars" },
  "time_zone": { "name": null, "abbr": null, "offset": null, "is_dst": null, "current_time": null },
  "threat": {
    "is_tor": false, "is_vpn": false, "is_icloud_relay": false, "is_proxy": false, "is_datacenter": true,
    "is_anonymous": false, "is_known_attacker": false, "is_known_abuser": false, "is_threat": false, "is_bogon": false,
    "blocklists": [
      { "days_seen": 1, "first_seen": "2026-11-02", "last_seen": "2026-11-02", "name": "ipdata", "site": "https://ipdata.co", "type": "cloud" },
      { "days_seen": 1, "first_seen": "2026-11-02", "last_seen": "2026-11-02", "name": "ipdata", "site": "https://ipdata.co", "type": "open_resolvers" }
    ],
    "scores": { "vpn_score": 100, "proxy_score": 93, "threat_score": 100, "trust_score": 2 }
  },
  "count": "0"
}`

// testJSONVPNExit is a lookup of a VPN exit (excerpt): neither top-level flag
// is present, and the third blocklist entry has no dates.
const testJSONVPNExit = `{
  "ip": "187.13.250.1",
  "is_eu": false,
  "threat": {
    "is_tor": false, "is_vpn": true, "is_icloud_relay": false, "is_proxy": false, "is_datacenter": true,
    "is_anonymous": true, "is_known_attacker": true, "is_known_abuser": true, "is_threat": true, "is_bogon": false,
    "blocklists": [
      { "days_seen": 2, "first_seen": "2026-10-31", "last_seen": "2026-11-02", "name": "Gluetun", "site": "https://github.com/qdm12/gluetun", "type": "vpn" },
      { "days_seen": 1, "first_seen": "2026-11-02", "last_seen": "2026-11-02", "name": "ipdata", "site": "https://ipdata.co", "type": "cloud" },
      { "name": "ipdata", "site": "https://ipdata.co", "type": "vpn" },
      { "days_seen": 2, "first_seen": "2026-10-31", "last_seen": "2026-11-02", "name": "NordVPN", "site": "https://nordvpn.com", "type": "vpn" },
      { "days_seen": 2, "first_seen": "2026-10-31", "last_seen": "2026-11-02", "name": "Wikimedia Global Blocklist", "site": "https://wikimedia.org", "type": "general" },
      { "days_seen": 2, "first_seen": "2026-10-31", "last_seen": "2026-11-02", "name": "X4BNet", "site": "https://github.com/X4BNet/lists_vpn", "type": "vpn" }
    ],
    "scores": { "vpn_score": 100, "proxy_score": 99, "threat_score": 100, "trust_score": 0 }
  },
  "count": "0"
}`

// testBulkJSONNewFields is a bulk response carrying the three fixtures above.
const testBulkJSONNewFields = "[" + testJSONSatellite + "," + testJSONAnycast + "," + testJSONVPNExit + "]"

// typed values of the three fixtures; keys the API left out read false, empty
// or nil
var (
	testIPSatellite = IP{
		IP: "98.97.34.0",
		ASN: ASN{
			ASN:    "AS14593",
			Name:   "Space Exploration Technologies Corporation",
			Domain: "spacex.com",
			Route:  "98.97.32.0/21",
			Type:   "business",
		},
		City:        "Seattle",
		CountryCode: "US",
		IsSatellite: true,
		Threat: &Threat{
			Blocklists: []Blocklist{},
			Scores:     Scores{VPNScore: 0, ProxyScore: 1, ThreatScore: 8, TrustScore: 97},
		},
		Count: "0",
	}

	testIPAnycast = IP{
		IP: "8.8.8.8",
		ASN: ASN{
			ASN:    "AS15169",
			Name:   "Google LLC",
			Domain: "about.google",
			Route:  "8.8.8.0/24",
			Type:   "hosting",
		},
		CountryName:   "United States",
		CountryCode:   "US",
		Flag:          "https://ipdata.co/flags/us.png",
		EmojiFlag:     "\U0001F1FA\U0001F1F8",
		EmojiUnicode:  "U+1F1FA U+1F1F8",
		ContinentName: "North America",
		ContinentCode: "NA",
		Latitude:      39.7599983215332,
		Longitude:     -98.5,
		CallingCode:   "1",
		IsAnycast:     true,
		Languages:     []Language{{Name: "English", Native: "English", Code: "en"}},
		Currency: &Currency{
			Name:   "US Dollar",
			Code:   "USD",
			Symbol: "$",
			Native: "$",
			Plural: "US dollars",
		},
		Company: &Company{
			Name:    "Google LLC",
			Domain:  "about.google",
			Network: "8.8.8.0/24",
			Type:    "hosting",
		},
		TimeZone: &TimeZone{},
		Threat: &Threat{
			IsDatacenter: true,
			Blocklists: []Blocklist{
				{Name: "ipdata", Site: "https://ipdata.co", Type: "cloud", FirstSeen: "2026-11-02", LastSeen: "2026-11-02", DaysSeen: intPtr(1)},
				{Name: "ipdata", Site: "https://ipdata.co", Type: "open_resolvers", FirstSeen: "2026-11-02", LastSeen: "2026-11-02", DaysSeen: intPtr(1)},
			},
			Scores: Scores{VPNScore: 100, ProxyScore: 93, ThreatScore: 100, TrustScore: 2},
		},
		Count: "0",
	}

	testIPVPNExit = IP{
		IP: "187.13.250.1",
		Threat: &Threat{
			IsVPN:           true,
			IsDatacenter:    true,
			IsAnonymous:     true,
			IsKnownAttacker: true,
			IsKnownAbuser:   true,
			IsThreat:        true,
			Blocklists: []Blocklist{
				{Name: "Gluetun", Site: "https://github.com/qdm12/gluetun", Type: "vpn", FirstSeen: "2026-10-31", LastSeen: "2026-11-02", DaysSeen: intPtr(2)},
				{Name: "ipdata", Site: "https://ipdata.co", Type: "cloud", FirstSeen: "2026-11-02", LastSeen: "2026-11-02", DaysSeen: intPtr(1)},
				{Name: "ipdata", Site: "https://ipdata.co", Type: "vpn"},
				{Name: "NordVPN", Site: "https://nordvpn.com", Type: "vpn", FirstSeen: "2026-10-31", LastSeen: "2026-11-02", DaysSeen: intPtr(2)},
				{Name: "Wikimedia Global Blocklist", Site: "https://wikimedia.org", Type: "general", FirstSeen: "2026-10-31", LastSeen: "2026-11-02", DaysSeen: intPtr(2)},
				{Name: "X4BNet", Site: "https://github.com/X4BNet/lists_vpn", Type: "vpn", FirstSeen: "2026-10-31", LastSeen: "2026-11-02", DaysSeen: intPtr(2)},
			},
			Scores: Scores{VPNScore: 100, ProxyScore: 99, ThreatScore: 100, TrustScore: 0},
		},
		Count: "0",
	}
)

func Test_decodeIP_newFields(t *testing.T) {
	tests := []struct {
		name string
		json string
		want IP
	}{
		{name: "satellite_isp", json: testJSONSatellite, want: testIPSatellite},
		{name: "anycast_with_dated_blocklists", json: testJSONAnycast, want: testIPAnycast},
		{name: "vpn_exit_entry_without_dates", json: testJSONVPNExit, want: testIPVPNExit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeIP(strings.NewReader(tt.json))
			if err != nil {
				t.Fatalf("decodeIP() unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("IP differs: (-want +got)\n%s", diff)
			}
		})
	}
}

func Test_client_Lookup_newFields(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/98.97.34.0", testAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testJSONSatellite)
	}))

	mux.HandleFunc("/8.8.8.8", testAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testJSONAnycast)
	}))

	mux.HandleFunc("/187.13.250.1", testAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, testJSONVPNExit)
	}))

	server := httptest.NewServer(mux)
	defer server.Close()

	c := Client{c: newHTTPClient(), e: server.URL + "/", k: "testAPIkey"}

	tests := []struct {
		name string
		ip   string
		want IP
	}{
		{name: "satellite_isp", ip: "98.97.34.0", want: testIPSatellite},
		{name: "anycast_with_dated_blocklists", ip: "8.8.8.8", want: testIPAnycast},
		{name: "vpn_exit_entry_without_dates", ip: "187.13.250.1", want: testIPVPNExit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Lookup(tt.ip)
			if err != nil {
				t.Fatalf("Lookup(%q) unexpected error: %v", tt.ip, err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Lookup(%q) differs: (-want +got)\n%s", tt.ip, diff)
			}
		})
	}
}

func TestClient_BulkLookup_newFields(t *testing.T) {
	server := testBulkHTTPServer()
	defer server.Close()

	client := &Client{c: newHTTPClient(), e: server.URL + "/", k: "testAPIkey"}

	got, err := client.BulkLookup([]string{"98.97.34.0", "8.8.8.8", "187.13.250.1"})
	if err != nil {
		t.Fatalf("BulkLookup() unexpected error: %v", err)
	}

	want := []*IP{&testIPSatellite, &testIPAnycast, &testIPVPNExit}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("IP slice differs: (-want +got)\n%s", diff)
	}
}

// TestClient_truncatedErrorResponse covers an error response whose body cannot
// be read to the end: the server announces more bytes than it sends and then
// closes the connection. The returned error names the status and carries the
// read error exactly once.
func TestClient_truncatedErrorResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"message":`)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/8.8.8.8", handler)
	mux.HandleFunc("/bulk", handler)

	server := httptest.NewServer(mux)
	defer server.Close()

	c := Client{c: newHTTPClient(), e: server.URL + "/", k: "testAPIkey"}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "Lookup",
			call: func() error {
				_, err := c.Lookup("8.8.8.8")
				return err
			},
		},
		{
			name: "RawLookup",
			call: func() error {
				_, err := c.RawLookup("8.8.8.8")
				return err
			},
		},
		{
			name: "BulkLookup",
			call: func() error {
				_, err := c.BulkLookup([]string{"1.1.1.1", "8.8.8.8"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatalf("%s() returned no error, want a body read error", tt.name)
			}

			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("%s() error = %v, want it to wrap io.ErrUnexpectedEOF", tt.name, err)
			}

			msg := err.Error()

			if prefix := `failed to read body from response with status code "500 Internal Server Error": `; !strings.HasPrefix(msg, prefix) {
				t.Errorf("%s() error = %q, want prefix %q", tt.name, msg, prefix)
			}

			if n := strings.Count(msg, io.ErrUnexpectedEOF.Error()); n != 1 {
				t.Errorf("%s() error = %q, mentions the read error %d times, want once", tt.name, msg, n)
			}
		})
	}
}

func TestNewClient_WithTimeout(t *testing.T) {
	t.Run("default_http_client", func(t *testing.T) {
		c, err := NewClient("testAPIkey", WithTimeout(5*time.Second))
		if err != nil {
			t.Fatalf("NewClient() unexpected error: %v", err)
		}

		if c.c == nil {
			t.Fatal("c.c should not be nil")
		}

		if got, want := c.c.Timeout, 5*time.Second; got != want {
			t.Fatalf("c.c.Timeout = %s, want %s", got, want)
		}

		if _, ok := c.c.Transport.(*http.Transport); !ok {
			t.Fatalf("c.c.Transport is %T, want the *http.Transport of newHTTPClient()", c.c.Transport)
		}
	})

	t.Run("custom_http_client", func(t *testing.T) {
		rt := &http.Transport{}
		custom := &http.Client{Transport: rt, Timeout: time.Minute}

		tests := []struct {
			name string
			opts []Option
		}{
			{
				name: "timeout_after_http_client",
				opts: []Option{WithHTTPClient(custom), WithTimeout(5 * time.Second)},
			},
			{
				name: "timeout_before_http_client",
				opts: []Option{WithTimeout(5 * time.Second), WithHTTPClient(custom)},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c, err := NewEUClient("testAPIkey", tt.opts...)
				if err != nil {
					t.Fatalf("NewEUClient() unexpected error: %v", err)
				}

				if c.c == custom {
					t.Fatal("c.c is the caller's *http.Client, want a copy")
				}

				if c.c.Transport != http.RoundTripper(rt) {
					t.Fatalf("c.c.Transport = %#v, want the custom transport", c.c.Transport)
				}

				if got, want := c.c.Timeout, 5*time.Second; got != want {
					t.Fatalf("c.c.Timeout = %s, want %s", got, want)
				}

				if got, want := custom.Timeout, time.Minute; got != want {
					t.Fatalf("custom.Timeout = %s, want %s: the caller's client was modified", got, want)
				}
			})
		}
	})

	t.Run("zero_means_no_limit", func(t *testing.T) {
		custom := &http.Client{Timeout: time.Minute}

		c, err := NewClient("testAPIkey", WithHTTPClient(custom), WithTimeout(0))
		if err != nil {
			t.Fatalf("NewClient() unexpected error: %v", err)
		}

		if c.c.Timeout != 0 {
			t.Fatalf("c.c.Timeout = %s, want 0", c.c.Timeout)
		}

		if got, want := custom.Timeout, time.Minute; got != want {
			t.Fatalf("custom.Timeout = %s, want %s: the caller's client was modified", got, want)
		}
	})

	t.Run("without_option", func(t *testing.T) {
		c, err := NewClient("testAPIkey")
		if err != nil {
			t.Fatalf("NewClient() unexpected error: %v", err)
		}

		if c.c.Timeout != 0 {
			t.Fatalf("c.c.Timeout = %s, want 0", c.c.Timeout)
		}
	})
}

// TestClient_WithTimeout_request sends requests to a server that only answers
// once the client has given up, and checks that every lookup fails with a
// timeout error instead of waiting for that answer.
func TestClient_WithTimeout_request(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// reading the body lets the server notice the client going away, and
		// cancel r.Context(), while the handler waits
		_, _ = io.Copy(io.Discard, r.Body)

		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			_, _ = io.WriteString(w, testJSONValid)
		}
	}))
	defer server.Close()

	c, err := NewClient("testAPIkey", WithTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}

	c.e = server.URL + "/"

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "Lookup",
			call: func() error {
				_, err := c.Lookup("8.8.8.8")
				return err
			},
		},
		{
			name: "LookupFields",
			call: func() error {
				_, err := c.LookupFields("8.8.8.8", []string{"ip"})
				return err
			},
		},
		{
			name: "BulkLookup",
			call: func() error {
				_, err := c.BulkLookup([]string{"1.1.1.1", "8.8.8.8"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatalf("%s() returned no error, want a timeout", tt.name)
			}

			var nerr net.Error
			if !errors.As(err, &nerr) || !nerr.Timeout() {
				t.Fatalf("%s() error = %v, want an error whose Timeout() reports true", tt.name, err)
			}
		})
	}
}
