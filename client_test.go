// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
)

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
				io.WriteString(w, "API key does not exist.")
				return
			}

			next(w, r)
		}
	}

	// 200 response code
	mux.HandleFunc("/76.14.47.42", amw(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testJSONValid)
	}))

	// 200 response code -- invalid JSON
	mux.HandleFunc("/76.14.42.42", amw(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "{")
	}))

	// 400 response code
	mux.HandleFunc("/192.168.0.1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "192.168.0.1 is a private IP address")
	})

	mux.HandleFunc("/bacon", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "bacon does not appear to be an IPv4 or IPv6 address")
	})

	// 401 response code
	mux.HandleFunc("/8.8.4.4", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "API key does not exist.")
	})

	mux.HandleFunc("/8.4.0.3", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "unexpected HTTP status code")
	})

	// 429 response code
	mux.HandleFunc("/8.8.8.8", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(
			w,
			"You have exceeded your free tier limit of 1500 requests. Register for a paid plan at https://ipdata.co to make more requests.",
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

	go server.Serve(l)

	return l, server, nil
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name string
		i    string
		e    string
		k    string
	}{
		{"no_api_key", "", "https://api.ipdata.co/", ""},
		{"with_api_key", "testAPIkey", "https://api.ipdata.co/", "testAPIkey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(tt.i)

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

const tjFlagURL = "https://ipdata.co/flags/us.png"

func Test_client_Lookup(t *testing.T) {
	ln, srvr, err := testHTTPServer("")
	if err != nil {
		t.Fatalf(`testHTTPServer("") returned unexpected error: %s`, err)
	}

	defer ln.Close()
	defer srvr.Close()

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
			e:    "failed to parse JSON: unexpected EOF",
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
			e:    "You have exceeded your free tier limit of 1500 requests. Register for a paid plan at https://ipdata.co to make more requests.",
		},
		{
			name: "valid_address",
			i:    "76.14.47.42",
			o: IP{
				IP:            "76.14.47.42",
				ASN:           "AS11404",
				Organization:  "vanoppen.biz LLC",
				City:          "San Francisco",
				Region:        "California",
				Postal:        "94132",
				CountryName:   "United States",
				CountryCode:   "US",
				Flag:          tjFlagURL,
				EmojiUnicode:  `"U+1F1FA U+1F1F8"`,
				ContinentName: "North America",
				ContinentCode: "NA",
				Latitude:      37.723,
				Longitude:     -122.4842,
				CallingCode:   "1",
				Languages:     []Language{},
				Currency: &Currency{
					Name:   "US Dollar",
					Code:   "USD",
					Symbol: "$",
					Native: "$",
					Plural: "US dollars",
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
				},
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

			if a, b := *ip.Threat, *tt.o.Threat; a != b {
				t.Errorf("ip.Threat = %#v, want %#v", a, b)
			}
		})
	}
}

func Test_client_Request(t *testing.T) {
	ln, srvr, err := testHTTPServer("")
	if err != nil {
		t.Fatalf(`testHTTPServer("") returned unexpected error: %s`, err)
	}

	defer ln.Close()
	defer srvr.Close()

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
			e:    "(ratelimited)",
		},
		{
			c:    c,
			name: "unexpected_error",
			i:    "8.4.0.3",
			e:    "unexpected http status: 403 Forbidden",
		},
		{
			c:    c,
			name: "invalid_api-key",
			i:    "8.8.4.4",
			e:    "(authentication failure)",
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

			resp, err = tt.c.Request(tt.i)

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
				t.Fatalf("Request(%q) unexpected error: %s", tt.i, err)
			}

			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected error reading response body: %s", err)
			}

			if str := string(body); str != tt.o {
				t.Fatalf("resp.Body = %q, want %q", str, tt.o)
			}
		})
	}
}

func Test_client_Lookup_error(t *testing.T) {
	ln, srvr, err := testHTTPServer("")
	if err != nil {
		t.Fatalf(`testHTTPServer("") returned unexpected error: %s`, err)
	}

	defer ln.Close()
	defer srvr.Close()

	c := Client{
		c: newHTTPClient(),
		e: "http://" + ln.Addr().String() + "/",
	}

	_, err = c.Request("8.8.8.8")
	if err != nil {
		rerr, ok := errors.Cause(err).(interface {
			RateLimited() bool
		})

		if !ok {
			t.Fatal("error does not implement RateLimited interface")
		}

		if !rerr.RateLimited() {
			t.Fatal("error returned did not indicate it was RateLimited")
		}
	}
}
