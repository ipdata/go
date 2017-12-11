// Copyright (c) 2017 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/pkg/errors"
)

// Version is the package version
const Version = "0.1.0"

// fqpn is the Fully Qualified Package Name for use in the client's User-Agent
const fqpn = "github.com/theckman/go-ipdata"

const (
	apiEndpoint   = "https://api.ipdata.co/"
	apiAuthHeader = "api-key"
)

var userAgent = fmt.Sprintf(
	"go-ipdata/%s (%s) Go-http-client/%s (%s %s)",
	Version, fqpn, runtime.Version(), runtime.GOOS, runtime.GOARCH,
)

// Client is the interface to represent the functionality presented by the
// https://ipdata.co API.
type Client interface {
	// Lookup takes an IP address to look up the details for. An empty string
	// means you want the information about the current node's pubilc IP
	// address.
	Lookup(ip string) (IP, error)
}

type client struct {
	c *http.Client // http client
	e string       // api endpoint
	k string       // api key
}

// NewClient takes an optional API key and returns a Client. If you do not have
// an API key use an empty string ("").
func NewClient(apiKey string) Client {
	return client{
		c: newHTTPClient(),
		e: apiEndpoint,
		k: apiKey,
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		},
	}
}

// Lookup is to satisfy the Client interface.
func (c client) Lookup(ip string) (IP, error) {
	// build request
	req, err := newRequest(c.e+ip, c.k)
	if err != nil {
		return IP{}, errors.Wrapf(err, "error building request to look up %s", ip)
	}

	// action request
	resp, err := c.c.Do(req)
	if err != nil {
		return IP{}, errors.Wrapf(err, "http request to %q failed", resp.Request.URL.String())
	}

	// janitorial duties
	defer resp.Body.Close()

	// response handling by status code
	// 200:     OK, maybe...
	// 400,429: possible failure modes
	// everything else: ¯\_(ツ)_/¯
	switch resp.StatusCode {
	case 200:
		// we can try and parse
		return DecodeIP(resp.Body)
	case 400, 429:
		// provide response body as error to consumer
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return IP{}, errors.Wrapf(err, "failed to read body from response with status code %q: %s", resp.Status, err)
		}

		if resp.StatusCode == 429 {
			return IP{}, errors.Errorf("looking up %q failed due to ratelimits: %s", ip, string(body))
		}

		return IP{}, errors.Errorf("looking up %q failed: %s", ip, string(body))
	default:
		// bail with a generic error
		return IP{}, errors.Errorf("looking up %q failed: unexpected http status: %s", ip, resp.Status)
	}
}

func newRequest(url, apiKey string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	// set the api key header (if set)
	if len(apiKey) > 0 {
		req.Header.Set(apiAuthHeader, apiKey)
	}

	return req, nil
}
