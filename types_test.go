// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"encoding/json"
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
		RegionCode:    "CA",
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
		IsSatellite:   true,
		IsAnycast:     true,
		Languages:     []Language{{Name: "English (US)", Native: "en-us", Code: "en"}},
		Currency: &Currency{
			Name:   "US Dollar",
			Code:   "USD",
			Symbol: "$",
			Native: "$",
			Plural: "US dollars",
		},
		Carrier: &Carrier{
			Name: "T-Mobile",
			MCC:  "310",
			MNC:  "260",
		},
		Company: &Company{
			Name:    "vanoppen.biz LLC",
			Domain:  "wavebroadband.com",
			Network: "76.14.0.0/17",
			Type:    "isp",
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
			Blocklists: []Blocklist{
				{Name: "ipdata", Site: "https://ipdata.co", Type: "vpn"},
				{Name: "NordVPN", Site: "https://nordvpn.com", Type: "vpn", FirstSeen: "2026-10-31", LastSeen: "2026-11-02", DaysSeen: intPtr(2)},
			},
		},
		Count: "1234",
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
		RegionCode:    "CA",
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
		IsSatellite:   true,
		IsAnycast:     true,
		Languages:     []Language{{Name: "English (US)", Native: "en-us", Code: "en"}},
		Currency: &Currency{
			Name:   "US Dollar",
			Code:   "USD",
			Symbol: "$",
			Native: "$",
			Plural: "US dollars",
		},
		Carrier: &Carrier{
			Name: "T-Mobile",
			MCC:  "310",
			MNC:  "260",
		},
		Company: &Company{
			Name:    "vanoppen.biz LLC",
			Domain:  "wavebroadband.com",
			Network: "76.14.0.0/17",
			Type:    "isp",
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
			Blocklists: []Blocklist{
				{Name: "ipdata", Site: "https://ipdata.co", Type: "vpn"},
				{Name: "NordVPN", Site: "https://nordvpn.com", Type: "vpn", FirstSeen: "2026-10-31", LastSeen: "2026-11-02", DaysSeen: intPtr(2)},
			},
		},
		Count: "1234",
	}

	got := bulkToIP(bip)
	if diff := cmp.Diff(ip, got); diff != "" {
		t.Fatalf("IP differs: (-want +got)\n%s", diff)
	}
}

// intPtr returns a pointer to i, for the optional integer fields of fixtures.
func intPtr(i int) *int {
	return &i
}

func Test_Blocklist_marshalOptionalFields(t *testing.T) {
	// the fields a feed did not report are left out when encoding, mirroring
	// the API response
	tests := []struct {
		name string
		in   Blocklist
		want string
	}{
		{
			name: "without_dates",
			in:   Blocklist{Name: "ipdata", Site: "https://ipdata.co", Type: "vpn"},
			want: `{"name":"ipdata","site":"https://ipdata.co","type":"vpn"}`,
		},
		{
			name: "with_dates",
			in: Blocklist{
				Name:      "NordVPN",
				Site:      "https://nordvpn.com",
				Type:      "vpn",
				FirstSeen: "2026-10-31",
				LastSeen:  "2026-11-02",
				DaysSeen:  intPtr(2),
			},
			want: `{"name":"NordVPN","site":"https://nordvpn.com","type":"vpn","first_seen":"2026-10-31","last_seen":"2026-11-02","days_seen":2}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("json.Marshal() unexpected error: %v", err)
			}

			if string(got) != tt.want {
				t.Fatalf("json.Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}
