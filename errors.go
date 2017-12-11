// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

type rateErr struct {
	m string
	r bool
}

func (e rateErr) Error() string {
	return e.m
}

func (e rateErr) RateLimited() bool {
	return e.r
}
