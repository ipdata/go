// Copyright (c) 2017, 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

// Error represents an error returned from the ipdata.co API. This error value
// will be used whenever the HTTP request to the API completed, but the HTTP
// status code indicated failure. The Error() method will return the JSON
// message sent by the API, if present, and Code() returns the numeric HTTP
// status code.
type Error struct {
	m string
	c int
}

// Error returns the message JSON field sent from the ipdata.co API. This also
// satisfies the error interface.
func (e Error) Error() string {
	return e.m
}

// Code returns the HTTP Status code returned from the ipdata.co API.
func (e Error) Code() int {
	return e.c
}
