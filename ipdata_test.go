// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func Test_transpose(t *testing.T) {
	tests := []struct {
		i RawIP
		o IP
	}{
		{
			i: RawIP{
				ASN:            "AS11404",
				Organization:   "vanoppen.biz LLC",
				City:           "San Francisco",
				Region:         "California",
				Postal:         "94132",
				CountryName:    "United States",
				CountryCode:    "US",
				ContinentName:  "North America",
				ContinentCode:  "NA",
				Latitude:       37.723,
				Longitude:      -122.4842,
				CallingCode:    "1",
				Currency:       "USD",
				CurrencySymbol: "$",
			},
			o: IP{
				ASN:            "AS11404",
				Organization:   "vanoppen.biz LLC",
				City:           "San Francisco",
				Region:         "California",
				Postal:         "94132",
				CountryName:    "United States",
				CountryCode:    "US",
				ContinentName:  "North America",
				ContinentCode:  "NA",
				Latitude:       37.723,
				Longitude:      -122.4842,
				CallingCode:    "1",
				Currency:       "USD",
				CurrencySymbol: "$",
			},
		},
	}

	for _, tt := range tests {
		ip := transpose(tt.i)

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

		if ip.Currency != tt.o.Currency {
			t.Errorf("ip.Currency = %q, want %q", ip.Currency, tt.o.Currency)
		}

		if ip.CurrencySymbol != tt.o.CurrencySymbol {
			t.Errorf("ip.CurrencySymbol = %q, want %q", ip.CurrencySymbol, tt.o.CurrencySymbol)
		}
	}
}

func Test_ripToIP(t *testing.T) {
	tjFlagURL, err := url.Parse("https://ipdata.co/flags/us.png")
	if err != nil {
		t.Fatalf("failed to parse URL: %s", err)
	}

	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Fatalf("failed to load location: %s", err)
	}

	tests := []struct {
		name string
		i    RawIP
		o    IP
		e    string
	}{
		{
			name: "invalid_flag",
			i:    RawIP{Flag: `http://%ƒail`},
			e:    "failed to parse flag",
		},
		{
			name: "invalid_timezone",
			i:    RawIP{TimeZone: `http://%ƒail`},
			e:    "failed to parse timezone",
		},
		{
			name: "valid_RawIP",
			i: RawIP{
				IP:             "76.14.47.42",
				ASN:            "AS11404",
				Organization:   "vanoppen.biz LLC",
				City:           "San Francisco",
				Region:         "California",
				Postal:         "94132",
				CountryName:    "United States",
				CountryCode:    "US",
				Flag:           "https://ipdata.co/flags/us.png",
				ContinentName:  "North America",
				ContinentCode:  "NA",
				Latitude:       37.723,
				Longitude:      -122.4842,
				CallingCode:    "1",
				Currency:       "USD",
				CurrencySymbol: "$",
				TimeZone:       "America/Los_Angeles",
			},
			o: IP{
				IP:             net.ParseIP("76.14.47.42"),
				ASN:            "AS11404",
				Organization:   "vanoppen.biz LLC",
				City:           "San Francisco",
				Region:         "California",
				Postal:         "94132",
				CountryName:    "United States",
				CountryCode:    "US",
				Flag:           tjFlagURL,
				ContinentName:  "North America",
				ContinentCode:  "NA",
				Latitude:       37.723,
				Longitude:      -122.4842,
				CallingCode:    "1",
				Currency:       "USD",
				CurrencySymbol: "$",
				TimeZone:       loc,
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			ip, err := ripToIP(tt.i)

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
				t.Fatalf("ripToIP(%+v) returned an unexpected error: %s", tt.i, err)
			}

			if a, b := ip.IP.String(), tt.o.IP.String(); a != b {
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

			if a, b := ip.Flag.String(), tt.o.Flag.String(); a != b {
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

			if ip.Currency != tt.o.Currency {
				t.Errorf("ip.Currency = %q, want %q", ip.Currency, tt.o.Currency)
			}

			if ip.CurrencySymbol != tt.o.CurrencySymbol {
				t.Errorf("ip.CurrencySymbol = %q, want %q", ip.CurrencySymbol, tt.o.CurrencySymbol)
			}

			if a, b := ip.TimeZone.String(), tt.o.TimeZone.String(); a != b {
				t.Errorf("ip.TimeZone = %q, want %q", a, b)
			}
		})
	}
}

func TestDecodeRawIP(t *testing.T) {
	tests := []struct {
		name string
		i    string
		o    RawIP
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
			o: RawIP{
				IP:             "76.14.47.42",
				ASN:            "AS11404",
				Organization:   "vanoppen.biz LLC",
				City:           "San Francisco",
				Region:         "California",
				Postal:         "94132",
				CountryName:    "United States",
				CountryCode:    "US",
				Flag:           "https://ipdata.co/flags/us.png",
				ContinentName:  "North America",
				ContinentCode:  "NA",
				Latitude:       37.723,
				Longitude:      -122.4842,
				CallingCode:    "1",
				Currency:       "USD",
				CurrencySymbol: "$",
				TimeZone:       "America/Los_Angeles",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			ip, err := DecodeRawIP(strings.NewReader(tt.i))

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

			if ip.IP != tt.o.IP {
				t.Errorf("ip.IP = %q, want %q", ip.IP, tt.o.IP)
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

			if ip.Flag != tt.o.Flag {
				t.Errorf("ip.Flag = %q, want %q", ip.Flag, tt.o.Flag)
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

			if ip.Currency != tt.o.Currency {
				t.Errorf("ip.Currency = %q, want %q", ip.Currency, tt.o.Currency)
			}

			if ip.CurrencySymbol != tt.o.CurrencySymbol {
				t.Errorf("ip.CurrencySymbol = %q, want %q", ip.CurrencySymbol, tt.o.CurrencySymbol)
			}

			if ip.TimeZone != tt.o.TimeZone {
				t.Errorf("ip.TimeZone = %q, want %q", ip.TimeZone, tt.o.TimeZone)
			}
		})
	}
}

func TestDecodeIP(t *testing.T) {
	tjFlagURL, err := url.Parse("https://ipdata.co/flags/us.png")
	if err != nil {
		t.Fatalf("failed to parse URL: %s", err)
	}

	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Fatalf("failed to load location: %s", err)
	}

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
			name: "invalid_field",
			i:    `{"flag":"http://%ƒail"}`,
			e:    "failed to parse flag",
		},
		{
			name: "valid_json",
			i:    testJSONValid,
			o: IP{
				IP:             net.ParseIP("76.14.47.42"),
				ASN:            "AS11404",
				Organization:   "vanoppen.biz LLC",
				City:           "San Francisco",
				Region:         "California",
				Postal:         "94132",
				CountryName:    "United States",
				CountryCode:    "US",
				Flag:           tjFlagURL,
				ContinentName:  "North America",
				ContinentCode:  "NA",
				Latitude:       37.723,
				Longitude:      -122.4842,
				CallingCode:    "1",
				Currency:       "USD",
				CurrencySymbol: "$",
				TimeZone:       loc,
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

			if a, b := ip.IP.String(), tt.o.IP.String(); a != b {
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

			if a, b := ip.Flag.String(), tt.o.Flag.String(); a != b {
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

			if ip.Currency != tt.o.Currency {
				t.Errorf("ip.Currency = %q, want %q", ip.Currency, tt.o.Currency)
			}

			if ip.CurrencySymbol != tt.o.CurrencySymbol {
				t.Errorf("ip.CurrencySymbol = %q, want %q", ip.CurrencySymbol, tt.o.CurrencySymbol)
			}

			if a, b := ip.TimeZone.String(), tt.o.TimeZone.String(); a != b {
				t.Errorf("ip.TimeZone = %q, want %q", a, b)
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
    "currency": "USD",
    "currency_symbol": "$",
    "calling_code": "1",
    "flag": "https://ipdata.co/flags/us.png",
    "time_zone": "America/Los_Angeles"
}`
