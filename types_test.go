// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_IP_String(t *testing.T) {
	ip := IP{IP: "8.8.8.8"}
	if ip.String() != "8.8.8.8" {
		t.Errorf("ip.String() = %q, want %q", ip.String(), "8.8.8.8")
	}
}

func Test_bulkToIP(t *testing.T) {
	bip := bulkIP{
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
		Languages:     []Language{{Name: "English (US)", Native: "en-us"}},
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
	}

	ip := &IP{
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
		Languages:     []Language{{Name: "English (US)", Native: "en-us"}},
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
	}

	got := bulkToIP(bip)
	if diff := cmp.Diff(ip, got); diff != "" {
		t.Fatalf("IP differs: (-want +got)\n%s", diff)
	}
}
