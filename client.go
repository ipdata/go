// Copyright (c) 2017, 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/pkg/errors"
)

// Version is the package version
const Version = "0.6.0"

// fqpn is the Fully Qualified Package Name for use in the client's User-Agent
const fqpn = "github.com/theckman/go-ipdata"

const (
	apiEndpoint  = "https://api.ipdata.co/"
	apiAuthParam = "api-key"
)

var userAgent = fmt.Sprintf(
	"go-ipdata/%s (%s) Go-http-client/%s (%s %s)",
	Version, fqpn, runtime.Version(), runtime.GOOS, runtime.GOARCH,
)

var errAPIKey = errors.New("apiKey cannot be an empty string")

// Client is the struct to represent the functionality presented by the
// https://ipdata.co API.
type Client struct {
	c *http.Client // http client
	e string       // api endpoint
	k string       // api key
}

// NewClient takes an optional API key and returns a Client. If you do not have
// an API key use an empty string ("").
func NewClient(apiKey string) (Client, error) {
	if len(apiKey) == 0 {
		return Client{}, errAPIKey
	}

	return Client{
		c: newHTTPClient(),
		e: apiEndpoint,
		k: apiKey,
	}, nil
}

type apiErr struct {
	Message string `json:"message"`
}

// RawLookup uses the internal mechanics to make an HTTP request to the API and
// returns the HTTP response. This allows consumers of the API to implement
// their own behaviors. If an API error occurs, the error value will be of type
// Error.
func (c Client) RawLookup(ip string) (*http.Response, error) {
	// build request
	req, err := newRequest(c.e+ip, c.k)
	if err != nil {
		return nil, errors.Wrapf(err, "error building request to look up %s", ip)
	}

	// action request
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "http request to %q failed", req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
	}

	switch resp.StatusCode {
	case http.StatusOK: // 200
		// we can try and parse
		return resp, nil
	default:
		// provide response body as error to consumer
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read body from response with status code %q: %s", resp.Status, err)
		}

		var a apiErr

		if err := json.Unmarshal(body, &a); err != nil {
			return nil, errors.Errorf("request for %q failed (unexpected response): %s: %v", ip, resp.Status, err)
		}

		return nil, Error{m: a.Message, c: resp.StatusCode}
	}
}

func decodeIP(r io.Reader) (IP, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return IP{}, err
	}

	ip := IP{}

	if err := json.Unmarshal(body, &ip); err != nil {
		return IP{}, fmt.Errorf("failed to parse JSON: %s", err)
	}

	return ip, nil
}

// Lookup takes an IP address to look up the details for. An empty string means
// you want the information about the current node's pubilc IP address. If an
// API error occurs, the error value will be of type Error.
func (c Client) Lookup(ip string) (IP, error) {
	resp, err := c.RawLookup(ip)
	if err != nil {
		return IP{}, err
	}

	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	pip, err := decodeIP(resp.Body)
	if err != nil {
		return IP{}, err
	}

	return pip, nil
}

func newRequest(urlStr, apiKey string) (*http.Request, error) {
	if len(urlStr) == 0 {
		return nil, errors.New("url cannot be an empty string")
	}

	if len(apiKey) == 0 {
		return nil, errAPIKey
	}

	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	q := url.Values{apiAuthParam: []string{apiKey}}
	req.URL.RawQuery = q.Encode()

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
