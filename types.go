// Copyright (c) 2017, 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

// IP is a struct that represents the JSON response from the https://ipdata.co
// API.
type IP struct {
	IP           string `json:"ip"`
	ASN          ASN    `json:"asn"`
	Organization string `json:"organisation"`

	City       string `json:"city"`
	Region     string `json:"region"`
	RegionCode string `json:"region_code"`
	Postal     string `json:"postal"`

	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`

	Flag         string `json:"flag"`
	EmojiFlag    string `json:"emoji_flag"`
	EmojiUnicode string `json:"emoji_unicode"`

	ContinentName string `json:"continent_name"`
	ContinentCode string `json:"continent_code"`

	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	CallingCode string `json:"calling_code"`

	IsEU bool `json:"is_eu"`

	Languages []Language `json:"language,omitempty"`

	Currency *Currency `json:"currency,omitempty"`

	Carrier *Carrier `json:"carrier,omitempty"`

	TimeZone *TimeZone `json:"time_zone,omitempty"`

	Threat *Threat `json:"threat,omitempty"`
}

func (ip IP) String() string {
	return ip.IP
}

// ASN represents the Autonomous System Number data returned from the API.
type ASN struct {
	ASN    string `json:"asn"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Route  string `json:"route"`
	Type   string `json:"type"`
}

// Carrier represents the carrier data returned from the API.
type Carrier struct {
	Name string `json:"name"`
	MCC  string `json:"mcc"`
	MNC  string `json:"mnc"`
}

// Language represents the language object within the JSON response from the
// API. This provides information about the language(s) where that IP resides.
type Language struct {
	Name   string `json:"name"`
	Native string `json:"native"`
}

// Currency represents the currency object within the JSON response from the
// API. This provides information about the currency where that IP resides.
type Currency struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Symbol string `json:"symbol"`
	Native string `json:"native"`
	Plural string `json:"plural"`
}

// TimeZone represents the time_zone object within the JSON response from the
// API. This provides information about the timezone where that IP resides.
type TimeZone struct {
	Name         string `json:"name"`
	Abbreviation string `json:"abbr"`
	Offset       string `json:"offset"`
	IsDST        bool   `json:"is_dst"`
	CurrentTime  string `json:"current_time,omitempty"`
}

// Threat represents the threat object within the JSON response from the API.
// This provides information about what type of threat this IP may be.
type Threat struct {
    IsTOR            bool        `json:"is_tor"`
    IsVPN            bool        `json:"is_vpn"`
    IsICloudRelay    bool        `json:"is_icloud_relay"`
    IsProxy          bool        `json:"is_proxy"`
    IsDatacenter     bool        `json:"is_datacenter"`
    IsAnonymous      bool        `json:"is_anonymous"`
    IsKnownAttacker  bool        `json:"is_known_attacker"`
    IsKnownAbuser    bool        `json:"is_known_abuser"`
    IsThreat         bool        `json:"is_threat"`
    IsBogon          bool        `json:"is_bogon"`
    Blocklists       []Blocklist `json:"blocklists"`
    Scores           Scores      `json:"scores"`
}

type Blocklist struct {
    Name string `json:"name"`
    Site string `json:"site"`
    Type string `json:"type"`
}


type Scores struct {
    VPNScore    int `json:"vpn_score"`
    ProxyScore  int `json:"proxy_score"`
    ThreatScore int `json:"threat_score"`
    TrustScore  int `json:"trust_score"`
}

type bulkIP struct {
	IP           string `json:"ip"`
	ASN          ASN    `json:"asn"`
	Organization string `json:"organisation"`

	City   string `json:"city"`
	Region string `json:"region"`
	Postal string `json:"postal"`

	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`

	Flag         string `json:"flag"`
	EmojiFlag    string `json:"emoji_flag"`
	EmojiUnicode string `json:"emoji_unicode"`

	ContinentName string `json:"continent_name"`
	ContinentCode string `json:"continent_code"`

	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	CallingCode string `json:"calling_code"`

	IsEU bool `json:"is_eu"`

	Languages []Language `json:"language,omitempty"`

	Currency *Currency `json:"currency,omitempty"`

	TimeZone *TimeZone `json:"time_zone,omitempty"`

	Threat *Threat `json:"threat,omitempty"`

	Message string `json:"message"`
}

func bulkToIP(bip bulkIP) *IP {
	ip := IP{
		IP:            bip.IP,
		ASN:           bip.ASN,
		Organization:  bip.Organization,
		City:          bip.City,
		Region:        bip.Region,
		Postal:        bip.Postal,
		CountryName:   bip.CountryName,
		CountryCode:   bip.CountryCode,
		Flag:          bip.Flag,
		EmojiFlag:     bip.EmojiFlag,
		EmojiUnicode:  bip.EmojiUnicode,
		ContinentName: bip.ContinentName,
		ContinentCode: bip.ContinentCode,
		Latitude:      bip.Latitude,
		Longitude:     bip.Longitude,
		CallingCode:   bip.CallingCode,
		IsEU:          bip.IsEU,
		Currency:      bip.Currency,
		TimeZone:      bip.TimeZone,
		Threat:        bip.Threat,
	}

	if len(bip.Languages) > 0 {
		ip.Languages = bip.Languages
	}

	return &ip
}
