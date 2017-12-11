// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// DecodeIP is a function to decode an io.Reader as the JSON representation of
// an IP from the ipdata.co API. This also converts JSON fields to a type better
// suited for Go, like converting the TimeZone field to a *time.Location. If
// you'd prefer to work with the raw data from the API, with no transformations
// to Go types, use the DecodeRawIP function.
func DecodeIP(r io.Reader) (IP, error) {
	rip, err := DecodeRawIP(r)
	if err != nil {
		return IP{}, err
	}

	pip, err := ripToIP(rip)
	if err != nil {
		return IP{}, err
	}

	return pip, nil
}

// DecodeRawIP takes an io.Reader, and tries to parse the JSON document
// representing an IP address from https://ipdata.co. Unlike DecodeIP, this
// function does not convert the response to Go types and keeps them as the form
// given back by the API.
func DecodeRawIP(r io.Reader) (RawIP, error) {
	dec := json.NewDecoder(r)

	rip := RawIP{}

	if err := dec.Decode(&rip); err != nil {
		return RawIP{}, fmt.Errorf("failed to parse JSON: %s", err)
	}

	return rip, nil
}

func ripToIP(rip RawIP) (IP, error) {
	var err error

	// parse the country flag URL if one was provided
	var flag *url.URL
	if len(rip.Flag) > 0 {
		flag, err = url.Parse(rip.Flag)
		if err != nil {
			return IP{}, fmt.Errorf("failed to parse flag %q: %s", rip.Flag, err)
		}
	}

	// parse the timezone if one was provided
	var loc *time.Location
	if len(rip.TimeZone) > 0 {
		loc, err = time.LoadLocation(rip.TimeZone)
		if err != nil {
			return IP{}, fmt.Errorf("failed to parse timezone %q: %s", rip.TimeZone, err)
		}
	}

	// take a RawIP and transpose it with an IP
	// this is a copy of the fields on the RawIP
	pip := transpose(rip)

	// set the IP address on the new IP struct
	pip.IP = net.ParseIP(rip.IP)

	// if we parsed out a flag URL
	if flag != nil {
		pip.Flag = flag
	}

	// if we parsed out a TimeZone location
	if loc != nil {
		pip.TimeZone = loc
	}

	return pip, nil
}

func transpose(r RawIP) IP {
	return IP{
		ASN:            r.ASN,
		Organization:   r.Organization,
		City:           r.City,
		Region:         r.Region,
		Postal:         r.Postal,
		CountryName:    r.CountryName,
		CountryCode:    r.CountryCode,
		ContinentName:  r.ContinentName,
		ContinentCode:  r.ContinentCode,
		Latitude:       r.Latitude,
		Longitude:      r.Longitude,
		CallingCode:    r.CallingCode,
		Currency:       r.Currency,
		CurrencySymbol: r.CurrencySymbol,
	}
}
