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
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

// Version is the package version
const Version = "0.8.2"

// fqpn is the Fully Qualified Package Name for use in the client's User-Agent
const fqpn = "github.com/ipdata/go"

const (
	apiEndpoint    = "https://api.ipdata.co/"
	euAPIEndpoint  = "https://eu-api.ipdata.co/"
	apiAuthParam   = "api-key"
	apiFieldsParam = "fields"
)

var userAgent = fmt.Sprintf(
	"go-ipdata/%s (%s) Go-http-client/%s (%s %s)",
	Version, fqpn, runtime.Version(), runtime.GOOS, runtime.GOARCH,
)

var errAPIKey = errors.New("apiKey cannot be an empty string")

// Option is a functional option for configuring the Client.
type Option func(*Client)

// WithHTTPClient sets the underlying *http.Client used by the Client. This
// allows callers to configure custom timeouts, proxies, transports, or
// instrument the client with tracing (e.g. OpenTelemetry).
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.c = httpClient
	}
}

// WithTimeout sets a time limit for every request made through the Client, by
// setting Timeout on the *http.Client it uses. The limit covers the whole
// request, from dialling the connection to the end of reading the response
// body, including the body of a response returned by RawLookup or
// RawBulkLookup. Without this option no overall limit is set and a request is
// bounded only by the context passed to the WithContext methods; a context
// deadline and the time limit combine, and the earlier one wins. A request
// that exceeds the limit fails with an error whose Timeout method reports
// true, and a bulk lookup is never replayed after a timeout.
//
// The limit is applied once all options have been processed, so it also
// covers an *http.Client supplied with WithHTTPClient, whatever the order of
// the options: the Client then uses a copy of that *http.Client with Timeout
// set, and the caller's value is left untouched. A zero d means no limit.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
		c.hasTimeout = true
	}
}

// Client is the struct to represent the functionality presented by the
// https://ipdata.co API.
//
// A Client owns a pool of persistent HTTPS connections (HTTP/2 where the
// server negotiates it, HTTP/1.1 keep-alive otherwise) that is reused for
// every request made through it. Build one Client per process, or one per API
// key or endpoint, and keep it for the lifetime of the program: every new
// Client pays a fresh TCP and TLS handshake. A Client is safe for concurrent
// use by multiple goroutines. Call CloseIdleConnections at shutdown to release
// the pooled connections.
type Client struct {
	c *http.Client // http client
	e string       // api endpoint
	k string       // api key

	// timeout is the request time limit given to WithTimeout, and hasTimeout
	// records that the option was used at all; newClient applies it to c.
	timeout    time.Duration
	hasTimeout bool
}

// NewClient takes an API key and optional Options, and returns a Client that
// uses the default endpoint (https://api.ipdata.co/).
func NewClient(apiKey string, opts ...Option) (Client, error) {
	return newClient(apiEndpoint, apiKey, opts)
}

// NewEUClient takes an API key and optional Options, and returns a Client that
// uses the EU endpoint (https://eu-api.ipdata.co/). This ensures that all
// requests are routed through EU data centers only (Frankfurt, Paris, Ireland),
// which can be useful for GDPR compliance.
func NewEUClient(apiKey string, opts ...Option) (Client, error) {
	return newClient(euAPIEndpoint, apiKey, opts)
}

// newClient builds a Client for endpoint, applies the options and then the
// request time limit set with WithTimeout, if any.
func newClient(endpoint, apiKey string, opts []Option) (Client, error) {
	if len(apiKey) == 0 {
		return Client{}, errAPIKey
	}

	c := Client{
		c: newHTTPClient(),
		e: endpoint,
		k: apiKey,
	}

	for _, opt := range opts {
		opt(&c)
	}

	if c.hasTimeout && c.c != nil {
		// work on a copy: an *http.Client supplied through WithHTTPClient
		// may be shared with other users
		hc := *c.c
		hc.Timeout = c.timeout
		c.c = &hc
	}

	return c, nil
}

// CloseIdleConnections closes the pooled connections of the underlying
// *http.Client that are currently idle. Requests in flight are not
// interrupted, and the Client stays usable: the next request simply dials a
// new connection. Call it at shutdown, or before a long idle period, to
// release sockets eagerly instead of waiting for the 60 second idle timeout.
// It is a no-op for a Client that has no *http.Client, or whose custom
// transport does not implement CloseIdleConnections.
func (c Client) CloseIdleConnections() {
	if c.c == nil {
		return
	}

	c.c.CloseIdleConnections()
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
	return c.rawLookup(ctx, ip, nil)
}

// rawLookup sends the GET request for ip, with params (which may be nil) and
// the API key as the query string, and returns the response when its status is
// 200 OK. Any other status becomes an error, of type Error when the body holds
// the API's JSON message, and the response body is closed.
func (c Client) rawLookup(ctx context.Context, ip string, params url.Values) (*http.Response, error) {
	// build request
	req, err := newGetRequestWithContext(ctx, c.e+ip, c.k, params)
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
		// provide response body as error to consumer; closing the body hands
		// the connection back to the pool
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read body from response with status code %q", resp.Status)
		}

		var a apiErr

		if err := json.Unmarshal(body, &a); err != nil {
			return nil, errors.Errorf("request for %q failed (unexpected response): %s: %v", ip, resp.Status, err)
		}

		return nil, newError(a.Message, resp.StatusCode)
	}
}

func decodeIP(r io.Reader) (IP, error) {
	body, err := io.ReadAll(r)
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
// you want the information about the current node's public IP address. If an
// API error occurs, the error value will be of type Error.
func (c Client) Lookup(ip string) (IP, error) {
	return c.LookupWithContext(context.Background(), ip)
}

// LookupWithContext is a Lookup that uses a provided context.Context.
func (c Client) LookupWithContext(ctx context.Context, ip string) (IP, error) {
	return c.lookup(ctx, ip, nil)
}

// LookupFields takes an IP address and a list of fields to return. Only the
// specified fields will be populated in the response. If an API error occurs,
// the error value will be of type Error.
func (c Client) LookupFields(ip string, fields []string) (IP, error) {
	return c.LookupFieldsWithContext(context.Background(), ip, fields)
}

// LookupFieldsWithContext is a LookupFields that uses a provided context.Context.
func (c Client) LookupFieldsWithContext(ctx context.Context, ip string, fields []string) (IP, error) {
	var params url.Values
	if len(fields) > 0 {
		params = url.Values{apiFieldsParam: []string{strings.Join(fields, ",")}}
	}

	return c.lookup(ctx, ip, params)
}

// lookup performs rawLookup and decodes the body of the 200 OK response.
func (c Client) lookup(ctx context.Context, ip string, params url.Values) (IP, error) {
	resp, err := c.rawLookup(ctx, ip, params)
	if err != nil {
		return IP{}, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	pip, err := decodeIP(resp.Body)
	if err != nil {
		return IP{}, err
	}

	return pip, nil
}

// newGetRequestWithContext builds the GET request for urlStr. Its query string
// is built from params plus the API key, which always takes precedence over a
// value in params; params may be nil and is left unchanged.
func newGetRequestWithContext(ctx context.Context, urlStr, apiKey string, params url.Values) (*http.Request, error) {
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

	q := make(url.Values, len(params)+1)
	for name, values := range params {
		q[name] = values
	}
	q.Set(apiAuthParam, apiKey)
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
	resp, err := c.doBulkRequest(ctx, ips)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK: // 200
		// we can try and parse
		return resp, nil
	default:
		// provide response body as error to consumer; closing the body hands
		// the connection back to the pool
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read body from response with status code %q", resp.Status)
		}

		var a apiErr

		if err := json.Unmarshal(body, &a); err != nil {
			return nil, errors.Errorf("request failed (unexpected response): %s: %v", resp.Status, err)
		}

		return nil, newError(a.Message, resp.StatusCode)
	}
}

// doBulkRequest builds and sends the bulk lookup POST.
//
// The bulk endpoint is not idempotent, so net/http only replays the request on
// its own when nothing was written to the connection yet. When a pooled
// connection that the server side had already dropped is picked, the request
// bytes go out and the read then fails (EOF, reset) before any response byte
// arrived; net/http discards that connection and reports the error. In exactly
// that situation doBulkRequest sends the request one more time, over a fresh
// or another pooled connection. It never retries after a response started to
// arrive, on an HTTP status, after a cancellation or timeout, or when the
// failed connection was not a reused one.
func (c *Client) doBulkRequest(ctx context.Context, ips []string) (*http.Response, error) {
	var ct connTracker

	// build request
	req, err := newBulkPostRequestWithContext(ct.trace(ctx), c.e+"bulk", c.k, ips)
	if err != nil {
		return nil, errors.Wrap(err, "error building bulk lookup request")
	}

	// action request
	resp, err := c.c.Do(req)
	if err != nil && ctx.Err() == nil && ct.staleConn(err) {
		// the body of the first request has been consumed: build a new one
		retry, rerr := newBulkPostRequestWithContext(ctx, c.e+"bulk", c.k, ips)
		if rerr == nil {
			resp, err = c.c.Do(retry)
		}
	}

	if err != nil {
		return nil, errors.Wrapf(err, "http request to %q failed", req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
	}

	return resp, nil
}

// connTracker records, through net/http/httptrace, whether the connection a
// request went out on had been used before and whether any byte of the
// response arrived. Both facts are needed to tell a request that was lost on a
// stale pooled connection apart from one the server may have acted on.
type connTracker struct {
	reused       atomic.Bool
	gotFirstByte atomic.Bool
}

// trace returns ctx with the tracker's hooks attached; hooks already present
// in ctx keep running.
func (ct *connTracker) trace(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			ct.reused.Store(info.Reused)
		},
		GotFirstResponseByte: func() {
			ct.gotFirstByte.Store(true)
		},
	})
}

// staleConn reports whether err, returned by (*http.Client).Do, means the
// request died on a previously used connection before the server answered:
// the connection was reused, no response byte arrived, and the failure is
// neither a cancellation nor a timeout.
func (ct *connTracker) staleConn(err error) bool {
	if !ct.reused.Load() || ct.gotFirstByte.Load() {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return false
	}

	return true
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
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
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

// newHTTPClient builds the *http.Client a Client uses unless WithHTTPClient
// supplies one. Its transport keeps a pool of persistent connections for the
// lifetime of the Client: TCP keepalive probes every 30 seconds, pooled
// connections are closed after 60 seconds idle, HTTP/2 is negotiated through
// ALPN with an HTTP/1.1 fallback (ForceAttemptHTTP2 is needed because a custom
// DialContext otherwise switches the automatic HTTP/2 setup off), and idle
// HTTP/2 connections are health checked with a PING frame every 30 seconds,
// closing the connection when no answer arrives within 15 seconds.
func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: true,
			HTTP2: &http.HTTP2Config{
				SendPingTimeout: 30 * time.Second,
				PingTimeout:     15 * time.Second,
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		},
	}
}
