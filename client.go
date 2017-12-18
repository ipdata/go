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
const Version = "0.4.1"

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

// Client is the struct to represent the functionality presented by the
// https://ipdata.co API.
type Client struct {
	c *http.Client // http client
	e string       // api endpoint
	k string       // api key
}

// NewClient takes an optional API key and returns a Client. If you do not have
// an API key use an empty string ("").
func NewClient(apiKey string) Client {
	return Client{
		c: newHTTPClient(),
		e: apiEndpoint,
		k: apiKey,
	}
}

// Request uses the internal mechanics to make an HTTP request to the API and
// returns the HTTP response. This allows consumers of the API to implement
// their own behaviors.
func (c Client) Request(ip string) (*http.Response, error) {
	// build request
	req, err := newRequest(c.e+ip, c.k)
	if err != nil {
		return nil, errors.Wrapf(err, "error building request to look up %s", ip)
	}

	// action request
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "http request to %q failed", req.URL.String())
	}

	switch resp.StatusCode {
	case http.StatusOK: // 200
		// we can try and parse
		return resp, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusTooManyRequests: // 400, 401, 429
		// provide response body as error to consumer
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read body from response with status code %q: %s", resp.Status, err)
		}

		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.Errorf("request for %q failed (authentication failure): %s", ip, string(body))
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			rerr := rateErr{r: true, m: string(body)}
			return nil, errors.Wrapf(rerr, "request for %q failed (ratelimited)")
		}

		return nil, errors.Errorf("request for %q failed: %s", ip, string(body))
	default:
		// bail with a generic error
		return nil, errors.Errorf("request for %q failed: unexpected http status: %s", ip, resp.Status)
	}
}

// LookupRaw takes an IP address to look up the details for. An empty string
// means you want the information about the current node's public IP address.
//
// This method is a little more performant than Lookup as it does not convert
// the RawIP struct to an IP struct.
func (c Client) LookupRaw(ip string) (RawIP, error) {
	resp, err := c.Request(ip)
	if err != nil {
		return RawIP{}, err
	}

	defer resp.Body.Close()

	rip, err := DecodeRawIP(resp.Body)
	if err != nil {
		return RawIP{}, err
	}

	return rip, nil
}

// Lookup takes an IP address to look up the details for. An empty string means
// you want the information about the current node's pubilc IP address.
func (c Client) Lookup(ip string) (IP, error) {
	resp, err := c.Request(ip)
	if err != nil {
		return IP{}, err
	}

	defer resp.Body.Close()

	pip, err := DecodeIP(resp.Body)
	if err != nil {
		return IP{}, err
	}

	return pip, nil
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
