// Copyright (c) 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import "testing"

func TestError(t *testing.T) {
	const wantStr = "test"
	const wantCode = 42
	const wantIndex = 84

	ev := Error{
		m: "test",
		c: 42,
		i: 84,
	}

	if got := ev.Error(); got != wantStr {
		t.Fatalf("ev.Error() = %q, want %q", got, wantStr)
	}

	if got := ev.Code(); got != wantCode {
		t.Fatalf("ev.Code() = %d, want %d", got, wantCode)
	}

	if got := ev.Index(); got != wantIndex {
		t.Fatalf("ev.Index() = %d, want %d", got, wantIndex)
	}
}
