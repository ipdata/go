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
//	import "github.com/ipdata/go"
//
//	ipd, err := ipdata.NewClient("YOUR_API_KEY")
//	if err != nil {
//		panic(err)
//	}
//
//	data, err := ipd.Lookup("8.8.8.8")
//
// A Client keeps a pool of persistent HTTPS connections (HTTP/2 when the
// server negotiates it) for as long as it lives, so build one Client and reuse
// it for every lookup instead of creating one per request. A Client is safe
// for concurrent use by multiple goroutines; call CloseIdleConnections at
// shutdown to release the pooled connections.
package ipdata
