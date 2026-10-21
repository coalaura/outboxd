package openpgp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coalaura/outboxd/internal/netpolicy"
)

const (
	wkdLoadTimeout   = 2 * time.Minute
	wkdLookupTimeout = 10 * time.Second
	wkdDialTimeout   = 3 * time.Second
	wkdMaxIPs        = 8
	wkdMaxKeyBytes   = 1 << 20
)

type wkdClient struct {
	lookupIP  func(context.Context, string, string) ([]net.IP, error)
	dial      func(context.Context, string, string) (net.Conn, error)
	tlsConfig *tls.Config
}

func (client *wkdClient) lookup(ctx context.Context, recipient string) ([]byte, error) {
	local, domain, err := splitSender(recipient)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, wkdLookupTimeout)
	defer cancel()

	host := "openpgpkey." + domain
	path := "/.well-known/openpgpkey/" + domain + "/hu/"

	// Resolve once, without search suffixes, then pin the checked addresses for
	// the connection. Only an absent advanced host permits the direct method.
	ips, err := client.lookupIP(ctx, "ip", host+".")
	if err != nil {
		dnsError, ok := errors.AsType[*net.DNSError](err)
		if !ok || !dnsError.IsNotFound {
			return nil, fmt.Errorf("resolve advanced WKD host: %w", err)
		}

		host = domain
		path = "/.well-known/openpgpkey/hu/"

		ips, err = client.lookupIP(ctx, "ip", host+".")
		if err != nil {
			return nil, fmt.Errorf("resolve direct WKD host: %w", err)
		}
	}

	if len(ips) == 0 {
		return nil, errors.New("WKD host has no addresses")
	}

	for _, address := range ips {
		if netpolicy.Restricted(address) {
			return nil, fmt.Errorf("WKD host resolves to restricted destination %s", address)
		}
	}

	endpoint := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     path + wkdHash(wkdLocalPart(local)),
		RawQuery: "l=" + url.QueryEscape(local),
	}

	return client.fetch(ctx, &endpoint, ips[:min(len(ips), wkdMaxIPs)])
}

func (client *wkdClient) fetch(ctx context.Context, endpoint *url.URL, ips []net.IP) ([]byte, error) {
	transport := &http.Transport{
		TLSClientConfig:        client.tlsConfig,
		TLSHandshakeTimeout:    wkdDialTimeout,
		ResponseHeaderTimeout:  wkdLookupTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort(endpoint.Host, "443") {
				return nil, errors.New("unexpected WKD dial target")
			}

			var dialError error

			for _, ip := range ips {
				dialCtx, cancel := context.WithTimeout(ctx, wkdDialTimeout)
				connection, err := client.dial(dialCtx, "tcp", net.JoinHostPort(ip.String(), "443"))
				cancel()

				if err == nil {
					return connection, nil
				}

				dialError = err

				if ctx.Err() != nil {
					break
				}
			}

			return nil, dialError
		},
	}

	defer transport.CloseIdleConnections()

	// Proxies and redirects could bypass address pinning or disclose the mailbox
	// to another origin. Neither is used for recipient discovery.
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   wkdLookupTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "application/octet-stream")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch WKD key: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WKD returned HTTP %d", response.StatusCode)
	}

	if response.ContentLength > wkdMaxKeyBytes {
		return nil, errors.New("WKD key exceeds size limit")
	}

	keyData, err := io.ReadAll(io.LimitReader(response.Body, wkdMaxKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read WKD key: %w", err)
	}

	if len(keyData) > wkdMaxKeyBytes {
		return nil, errors.New("WKD key exceeds size limit")
	}

	return keyData, nil
}

func newWKDClient() *wkdClient {
	dialer := &net.Dialer{Timeout: wkdDialTimeout}

	return &wkdClient{
		lookupIP:  net.DefaultResolver.LookupIP,
		dial:      dialer.DialContext,
		tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
}
