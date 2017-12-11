// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"net"
	"net/url"
	"time"
)

// IP is the representation of the metadata available from the https://ipdata.co
// API. This struct is meant to be a parsed version of the RawIP struct, where
// fields are replaced by ones with a more useful type. One example is
// converting the TimeZone of RawIP to be a *time.Location.
type IP struct {
	IP           net.IP
	ASN          string
	Organization string

	City   string
	Region string
	Postal string

	CountryName string
	CountryCode string
	Flag        *url.URL

	ContinentName string
	ContinentCode string

	Latitude  float64
	Longitude float64

	CallingCode string

	Currency       string
	CurrencySymbol string

	TimeZone *time.Location
}

func (ip IP) String() string {
	return ip.IP.String()
}

// RawIP is a struct that represents the raw JSON response from the
// https://ipdata.co API.
type RawIP struct {
	IP           string `json:"ip"`
	ASN          string `json:"asn"`
	Organization string `json:"organisation"`

	City   string `json:"city"`
	Region string `json:"region"`
	Postal string `json:"postal"`

	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`
	Flag        string `json:"flag"`

	ContinentName string `json:"continent_name"`
	ContinentCode string `json:"continent_code"`

	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	CallingCode string `json:"calling_code"`

	Currency       string `json:"currency"`
	CurrencySymbol string `json:"currency_symbol"`

	TimeZone string `json:"time_zone"`
}

func (ip RawIP) String() string {
	return ip.IP
}
