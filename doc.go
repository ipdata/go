// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

// Package ipdata is a client for the https://ipdata.co API. It provides
// functions for looking up data, as well as parsing the data in a programmatic
// way. The simplest usage is to build a new client and then use the Lookup
// method.
//
// If you have any problems with this client, please raise an issue on GitHub:
//
// * https://github.com/theckman/go-ipdata/issues
//
// Example usage:
//
// 	import "github.com/theckman/go-ipdata"
//
// 	ipd := ipdata.NewClient("") // API key is optional
// 	data, err := ipd.Lookup("8.8.8.8")
package ipdata
