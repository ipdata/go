// Copyright (c) 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import "testing"

func TestError(t *testing.T) {
	const wantStr = "test"
	const wantInt = 42

	ev := Error{
		m: "test",
		c: 42,
	}

	if got := ev.Error(); got != wantStr {
		t.Fatalf("ev.Error() = %q, want %q", got, wantStr)
	}

	if got := ev.Code(); got != wantInt {
		t.Fatalf("ev.Code() = %d, want %d", got, wantInt)
	}
}
