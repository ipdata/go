// Copyright (c) 2017, 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
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

			defer func() {
				_, _ = io.Copy(ioutil.Discard, resp.Body)
				_ = resp.Body.Close()
			}()

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

func mustParseURL(u string) *url.URL {
	v, err := url.Parse(u)
	if err != nil {
		panic(err)
	}

	return v
}

func Test_newRequest(t *testing.T) {
	tests := []struct {
		name string
		url  string
		key  string

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
				Header: map[string][]string{"User-Agent": []string{userAgent}},
				URL:    mustParseURL("http://localhost/?api-key=abc123"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newRequest(tt.url, tt.key)
			if cont := testErrCheck(t, "newRequest()", tt.err, err); !cont {
				return
			}

			if gots, wants := got.URL.String(), tt.want.URL.String(); gots != wants {
				t.Fatalf("got.URL = %q, want %q", gots, wants)
			}

			if gots, wants := got.Header.Get("User-Agent"), tt.want.Header.Get("User-Agent"); gots != wants {
				t.Fatalf("User-Agent = %q, want %q", gots, wants)
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
				IP:            "76.14.47.42",
				ASN:           "AS11404",
				Organization:  "vanoppen.biz LLC",
				City:          "San Francisco",
				Region:        "California",
				Postal:        "94132",
				CountryName:   "United States",
				CountryCode:   "US",
				Flag:          tjFlagURL,
				EmojiUnicode:  `U+1F1FA U+1F1F8`,
				ContinentName: "North America",
				ContinentCode: "NA",
				Latitude:      37.723,
				Longitude:     -122.4842,
				CallingCode:   "1",
				IsEU:          true,
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

			if a, b := *ip.Threat, *tt.o.Threat; a != b {
				t.Errorf("ip.Threat = %#v, want %#v", a, b)
			}
		})
	}
}

var testJSONValid = `{
    "ip": "76.14.47.42",
    "city": "San Francisco",
    "region": "California",
    "country_name": "United States",
    "country_code": "US",
    "continent_name": "North America",
    "continent_code": "NA",
    "latitude": 37.723,
    "longitude": -122.4842,
    "asn": "AS11404",
    "organisation": "vanoppen.biz LLC",
    "postal": "94132",
    "calling_code": "1",
    "flag": "https://ipdata.co/flags/us.png",
	"emoji_unicode": "U+1F1FA U+1F1F8",
	"is_eu": true,
	"languages": [
		{
			"name": "English",
			"native": "English"
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
		"name": "America/Los_Angeles",
		"abbr": "PST",
		"offset": "-0800",
		"is_dst": false,
		"current_time": "2019-02-27T15:00:32.745936-08:00"
	},
	"threat": {
		"is_tor": false,
		"is_proxy": false,
		"is_anonymous": false,
		"is_known_attacker": false,
		"is_known_abuser": false,
		"is_threat": true,
		"is_bogon": false
	}
}`
