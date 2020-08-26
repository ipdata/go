// Copyright (c) 2017, 2019 Tim Heckman
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package ipdata

import (
	"bytes"
	"context"
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
const Version = "0.7.1"

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
	return c.RawLookupWithContext(context.Background(), ip)
}

// RawLookupWithContext is a RawLookup that uses a provided context.Context.
func (c Client) RawLookupWithContext(ctx context.Context, ip string) (*http.Response, error) {
	// build request
	req, err := newGetRequestWithContext(ctx, c.e+ip, c.k)
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

		return nil, newError(a.Message, resp.StatusCode)
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
	return c.LookupWithContext(context.Background(), ip)
}

// LookupWithContext is a Lookup that uses a provided context.Context.
func (c Client) LookupWithContext(ctx context.Context, ip string) (IP, error) {
	resp, err := c.RawLookupWithContext(ctx, ip)
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

func newGetRequest(urlStr, apiKey string) (*http.Request, error) {
	ctx := context.Background()
	return newGetRequestWithContext(ctx, urlStr, apiKey)
}

func newGetRequestWithContext(ctx context.Context, urlStr, apiKey string) (*http.Request, error) {
	if len(urlStr) == 0 {
		return nil, errors.New("url cannot be an empty string")
	}

	if len(apiKey) == 0 {
		return nil, errAPIKey
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	q := url.Values{apiAuthParam: []string{apiKey}}
	req.URL.RawQuery = q.Encode()

	return req, nil
}

// RawBulkLookup takes a set of IP addresses, and returns the response from the
// API.
func (c *Client) RawBulkLookup(ips []string) (*http.Response, error) {
	return c.RawBulkLookupWithContext(context.Background(), ips)
}

// RawBulkLookupWithContext is a RawBulkLookup with a provided context.Context.
	func (c *Client) RawBulkLookupWithContext(ctx context.Context, ips []string) (*http.Response, error) {
	// build request
	req, err := newBulkPostRequestWithContext(ctx, c.e+"bulk", c.k, ips)
	if err != nil {
		return nil, errors.Wrap(err, "error building bulk lookup request")
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
			return nil, errors.Errorf("request failed (unexpected response): %s: %v", resp.Status, err)
		}

		return nil, newError(a.Message, resp.StatusCode)
	}
}

func newBulkPostRequest(urlStr, apiKey string, ips []string) (*http.Request, error) {
	return newBulkPostRequestWithContext(context.Background(), urlStr, apiKey, ips)
}

func newBulkPostRequestWithContext(ctx context.Context, urlStr, apiKey string, ips []string) (*http.Request, error) {
	if len(urlStr) == 0 {
		return nil, errors.New("url cannot be an empty string")
	}

	if len(apiKey) == 0 {
		return nil, errAPIKey
	}

	if len(ips) == 0 {
		return nil, errors.New("must provide at least one IP")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(ips); err != nil {
		return nil, errors.Wrap(err, "failed to encode JSON")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	q := url.Values{apiAuthParam: []string{apiKey}}
	req.URL.RawQuery = q.Encode()

	return req, nil
}

// BulkLookup takes a set of IP addresses, and returns a set of results from the
// API. If the request failed, or something was wrong with one of the inputs,
// the error value will be of type Error. If err is non-nil, the []*IP slice may
// contain data (if it was able to process some of the inputs). The error value
// will contain the index of the first error in the bulk response.
//
// Please note, any IPs that had a failed lookup will be a nil entry in the
// slice when an error is returned. So if you start to use the []*IP when err !=
// nil, you will need to add explicit nil checks to avoid pointer derefence
// panics.
func (c *Client) BulkLookup(ips []string) ([]*IP, error) {
	return c.BulkLookupWithContext(context.Background(), ips)
}

// BulkLookupWithContext is a BulkLookup with a provided context.Context.
func (c *Client) BulkLookupWithContext(ctx context.Context, ips []string) ([]*IP, error) {
	resp, err := c.RawBulkLookupWithContext(ctx, ips)
	if err != nil {
		return nil, err
	}

	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	var bip []bulkIP

	if err := json.Unmarshal(body, &bip); err != nil {
		return nil, errors.Wrap(err, "failed to parse JSON")
	}

	res := make([]*IP, len(bip))
	var retErr error

	for i, ip := range bip {
		if len(ip.Message) > 0 && retErr == nil {
			retErr = Error{
				m: ip.Message,
				c: resp.StatusCode,
				i: i,
			}
			continue
		}

		res[i] = bulkToIP(ip)
	}

	if retErr != nil {
		return res, retErr
	}

	return res, nil // avoid nil interface check problem
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
