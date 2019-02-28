// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"strings"
	"testing"
)

func TestDecodeIP(t *testing.T) {
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
			ip, err := DecodeIP(strings.NewReader(tt.i))

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
