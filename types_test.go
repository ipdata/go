// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"testing"
)

func Test_IP_String(t *testing.T) {
	ip := IP{IP: "8.8.8.8"}
	if ip.String() != "8.8.8.8" {
		t.Errorf("ip.String() = %q, want %q", ip.String(), "8.8.8.8")
	}
}
