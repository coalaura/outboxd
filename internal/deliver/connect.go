package deliver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

func (d *Deliverer) effectiveTLS() outboundTLS {
	mode := d.cfg.Delivery.TLSMode

	insecure := d.cfg.Delivery.InsecureTLSAllowed()
	allowPlain := d.cfg.Delivery.PlaintextAllowed()

	return outboundTLS{
		requireSTARTTLS:    mode == "required" || !allowPlain,
		insecureSkipVerify: insecure,
		allowPlaintext:     allowPlain && mode != "required",
	}
}

func (d *Deliverer) connect(ctx context.Context, host string, noExtensions bool) (*Client, error) {
	ips, err := d.lookupHostIPs(ctx, host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, errNoUsableIP
	}

	var last error

	for _, ip := range ips {
		client, err := d.dialAndSession(ctx, host, ip, noExtensions)
		if err == nil {
			return client, nil
		}

		last = err
	}

	if last == nil {
		last = errNoUsableIP
	}

	return nil, last
}

func (d *Deliverer) dialAndSession(ctx context.Context, mxHost string, ip net.IP, noExtensions bool) (*Client, error) {
	// Policy is fixed before dialing. Never reconnect with a weaker verification policy.
	policy := d.effectiveTLS()

	network, local := d.bindFor(ip)

	addr := net.JoinHostPort(ip.String(), "25")

	dialer := d.dialer

	nd, ok := dialer.(*net.Dialer)
	if ok {
		cp := *nd

		cp.Timeout = d.connTO

		if local != nil {
			cp.LocalAddr = local
		}

		dialer = &cp
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.connTO)

	conn, err := dialer.DialContext(dialCtx, network, addr)

	cancel()

	if err != nil {
		return nil, err
	}

	client := NewClient(conn, d.command, d.submission)

	client.bindContext(ctx)

	err = client.Greet()
	if err != nil {
		client.Close()

		return nil, err
	}

	err = client.EHLO(d.cfg.Server.Hostname)
	if err != nil {
		code := smtpCode(err)
		if !policy.allowPlaintext || !noExtensions || (code != 500 && code != 502 && code != 504) {
			client.Close()

			return nil, err
		}

		err = client.HELO(d.cfg.Server.Hostname)
		if err != nil {
			client.Close()

			return nil, err
		}

		return client, nil
	}

	hasTLS, _ := client.Extension("STARTTLS")
	if !hasTLS {
		if policy.requireSTARTTLS || !policy.allowPlaintext {
			client.Close()

			return nil, errTLSRequired
		}

		return client, nil
	}

	// STARTTLS is advertised: attempt once with the pre-chosen verification policy.
	// Failure must not downgrade to plaintext or reconnect insecurely.
	err = d.upgradeTLS(client, mxHost, policy)
	if err != nil {
		client.Close()

		return nil, fmt.Errorf("%w: %v", errTLSFailed, err)
	}

	err = client.EHLO(d.cfg.Server.Hostname)
	if err != nil {
		client.Close()

		return nil, err
	}

	return client, nil
}

func (d *Deliverer) upgradeTLS(client *Client, mxHost string, policy outboundTLS) error {
	cfg := &tls.Config{
		ServerName: mxHost, // SNI is the MX hostname even when dialing an explicit IP
		MinVersion: tls.VersionTLS12,
	}

	// InsecureSkipVerify is set only when the configured policy is explicitly insecure
	// (tls_mode=opportunistic_insecure, or legacy require_valid_mx_tls_certificate=false).
	// It is never used as a second-chance fallback after verified STARTTLS fails.
	if policy.insecureSkipVerify {
		cfg.InsecureSkipVerify = true
	}

	if d.tlsRootCAs != nil {
		cfg.RootCAs = d.tlsRootCAs
	}

	return client.StartTLS(cfg)
}

func (d *Deliverer) bindFor(ip net.IP) (network string, local net.Addr) {
	ip4 := ip.To4()
	if ip4 != nil {
		network = "tcp4"

		b := d.cfg.Delivery.BindIPv4
		if b != "" {
			lip := net.ParseIP(b)
			if lip != nil {
				local = &net.TCPAddr{IP: lip}
			}
		}

		return network, local
	}

	network = "tcp6"

	b := d.cfg.Delivery.BindIPv6
	if b != "" {
		lip := net.ParseIP(b)
		if lip != nil {
			local = &net.TCPAddr{IP: lip}
		}
	}

	return network, local
}
