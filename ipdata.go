// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"encoding/json"
	"fmt"
	"io"
)

// DecodeIP is a function to decode an io.Reader as the JSON representation of
// an IP from the ipdata.co API. This also converts JSON fields to a type better
// suited for Go, like converting the TimeZone field to a *time.Location. If
// you'd prefer to work with the raw data from the API, with no transformations
// to Go types, use the DecodeRawIP function.
func DecodeIP(r io.Reader) (IP, error) {
	dec := json.NewDecoder(r)

	ip := IP{}

	if err := dec.Decode(&ip); err != nil {
		return IP{}, fmt.Errorf("failed to parse JSON: %s", err)
	}

	return ip, nil
}
