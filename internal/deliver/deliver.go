package deliver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

const lifetimeDetail = "maximum queue lifetime exceeded"

// Logger receives operational messages.
type Logger interface {
	Printf(format string, values ...any)
	Println(values ...any)
}

// Resolver looks up MX and address records.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Dialer opens outbound TCP connections (LocalAddr should already be set as needed).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type netResolver struct {
	r *net.Resolver
}

func (n netResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return n.r.LookupMX(ctx, name)
}

func (n netResolver) LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error) {
	addrs, err := n.r.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, len(addrs))
	for i, a := range addrs {
		out[i] = a.AsSlice()
	}
	return out, nil
}

var (
	errNullMX              = errors.New("domain does not accept mail (null MX)")
	errNoSuchDomain        = errors.New("recipient domain does not exist")
	errSMTPUTF8Unsupported = errors.New("destination does not support SMTPUTF8")
	err8BITMIMEUnsupported = errors.New("destination does not support 8BITMIME")
	errTLSRequired         = errors.New("TLS required but STARTTLS not available")
	errTLSFailed           = errors.New("STARTTLS failed; refusing plaintext downgrade")
	errNoUsableIP          = errors.New("no usable destination address")
	errPrivateDestination  = errors.New("destination address is not publicly routable")
)

// outboundTLS is the effective TLS policy for one dial attempt, computed before connect.
type outboundTLS struct {
	// requireSTARTTLS rejects destinations that do not advertise STARTTLS.
	requireSTARTTLS bool
	// insecureSkipVerify disables certificate verification on the single STARTTLS attempt.
	// Used only when the configured policy is explicitly insecure; never as a fallback
	// after a verified handshake failure.
	insecureSkipVerify bool
	// allowPlaintext permits continuing without TLS when STARTTLS is not advertised.
	// An advertised STARTTLS that fails must never fall back to plaintext.
	allowPlaintext bool
}

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

// Signer produces DKIM-Signature headers for locally generated messages (DSNs).
type Signer interface {
	Signature(message []byte) (string, error)
}

// Deliverer drains the queue towards destination MX servers.
type Deliverer struct {
	cfg    *config.Config
	queue  *queue.Queue
	log    Logger
	signer Signer

	resolver Resolver
	dialer   Dialer

	// tlsRootCAs is an optional test/production root pool override for verified STARTTLS.
	// When nil, Go's system roots are used.
	tlsRootCAs *x509.CertPool

	// orderIPs optionally reorders resolved candidate addresses before dial attempts.
	// Production defaults to a light shuffle. Tests may replace it for deterministic order.
	orderIPs func([]net.IP)

	// active bounds concurrent attempt goroutines (including domain waiters).
	active  chan struct{}
	global  chan struct{}
	domains *domainLimiter

	command    time.Duration
	submission time.Duration
	lifetime   time.Duration
	initial    time.Duration
	maximum    time.Duration
	connTO     time.Duration

	allowlist map[string]struct{}

	// fatal signals Run to stop on queue persistence failure
	mu    sync.Mutex
	fatal error
}

// New builds the outbound delivery worker pool.
func New(cfg *config.Config, spool *queue.Queue, log Logger) *Deliverer {
	return NewWithSigner(cfg, spool, log, nil)
}

// NewWithSigner is New with an optional DKIM signer for failure DSNs.
func NewWithSigner(cfg *config.Config, spool *queue.Queue, log Logger, signer Signer) *Deliverer {
	// Cap attempt workers above global MX concurrency so domain waiters
	// do not block scheduling, but prevent unbounded goroutine growth.
	attemptLimit := cfg.Delivery.GlobalConcurrency * 4
	if attemptLimit < 8 {
		attemptLimit = 8
	}

	d := &Deliverer{
		cfg:    cfg,
		queue:  spool,
		log:    log,
		signer: signer,

		resolver: netResolver{r: net.DefaultResolver},
		dialer:   &net.Dialer{Timeout: config.Duration(cfg.Delivery.ConnectionTimeout)},
		orderIPs: shuffleIPs,

		active:  make(chan struct{}, attemptLimit),
		global:  make(chan struct{}, cfg.Delivery.GlobalConcurrency),
		domains: newDomainLimiter(cfg.Delivery.DomainConcurrency),

		command:    config.Duration(cfg.Delivery.CommandTimeout),
		submission: config.Duration(cfg.Delivery.SubmissionTimeout),
		lifetime:   config.Duration(cfg.Delivery.MaximumLifetime),
		initial:    config.Duration(cfg.Delivery.InitialRetryDelay),
		maximum:    config.Duration(cfg.Delivery.MaximumRetryDelay),
		connTO:     config.Duration(cfg.Delivery.ConnectionTimeout),

		allowlist: make(map[string]struct{}),
	}
	for _, a := range cfg.Delivery.DestinationAllowlist {
		ip := net.ParseIP(a)
		if ip != nil {
			d.allowlist[ip.String()] = struct{}{}
		}
	}
	return d
}

// SetResolver replaces the DNS resolver (tests).
func (d *Deliverer) SetResolver(r Resolver) {
	d.resolver = r
}

// SetDialer replaces the dialer (tests).
func (d *Deliverer) SetDialer(dialer Dialer) {
	d.dialer = dialer
}

// SetTLSRootCAs replaces the root cert pool used for verified STARTTLS (tests).
func (d *Deliverer) SetTLSRootCAs(pool *x509.CertPool) {
	d.tlsRootCAs = pool
}

// Run delivers queued messages until ctx is cancelled or a fatal queue error occurs.
func (d *Deliverer) Run(ctx context.Context) error {
	d.log.Printf("Delivery started with %d queued message(s)\n", d.queue.Len())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		if err := d.fatalErr(); err != nil {
			cancel()
			wg.Wait()
			return err
		}

		envelope, err := d.queue.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				if ferr := d.fatalErr(); ferr != nil {
					return ferr
				}
				return nil
			}
			return err
		}

		if ctx.Err() != nil {
			d.queue.Requeue(envelope)
			if ferr := d.fatalErr(); ferr != nil {
				return ferr
			}
			return nil
		}

		// Bound concurrent attempt goroutines (domain wait does not hold MX slots).
		select {
		case d.active <- struct{}{}:
		case <-ctx.Done():
			d.queue.Requeue(envelope)
			if ferr := d.fatalErr(); ferr != nil {
				return ferr
			}
			return nil
		}

		wg.Go(func() {
			defer func() { <-d.active }()
			if err := d.attempt(ctx, envelope); err != nil {
				d.setFatal(err)
				cancel()
			}
		})
	}
}

func (d *Deliverer) setFatal(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fatal == nil {
		d.fatal = err
	}
}

func (d *Deliverer) fatalErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fatal
}

func (d *Deliverer) attempt(ctx context.Context, envelope *queue.Envelope) error {
	if ctx.Err() != nil {
		d.queue.Requeue(envelope)
		return nil
	}

	expired, err := d.expire(envelope)
	if err != nil {
		return err
	}
	if expired {
		return nil
	}

	envelope.Attempts++
	envelope.LastError = ""

	groups := make(map[string][]int, len(envelope.Recipients))
	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status != queue.StatusPending {
			continue
		}
		groups[recipient.Domain] = append(groups[recipient.Domain], i)
	}

	// Fairness: acquire domain first without holding a global connection slot.
	for domain, indexes := range groups {
		if ctx.Err() != nil {
			break
		}
		if err := d.domains.acquire(ctx, domain); err != nil {
			break
		}
		err := d.domain(ctx, envelope, domain, indexes)
		d.domains.release(domain)
		if err != nil {
			envelope.LastError = fmt.Sprintf("%s: %s", domain, err)
		}
	}

	switch {
	case envelope.Pending() == 0:
		return d.complete(envelope)
	case envelope.Attempts >= d.cfg.Delivery.MaxAttempts:
		for i := range envelope.Recipients {
			recipient := &envelope.Recipients[i]
			if recipient.Status == queue.StatusPending {
				recipient.Status = queue.StatusFailed
				// Preserve the most useful diagnostic for DSN/dead-letter.
				switch {
				case recipient.Detail != "":
					// keep capability-specific or prior MX detail
				case envelope.LastError != "":
					recipient.Detail = envelope.LastError
				default:
					recipient.Detail = "delivery attempts exhausted"
				}
			}
		}
		d.log.Printf("giving up on %s after %d attempts: %s\n", envelope.ID, envelope.Attempts, envelope.LastError)
		return d.failTerminal(envelope)
	default:
		envelope.NextAttempt = time.Now().Add(d.backoff(envelope.Attempts))
		deadline := envelope.Created.Add(d.lifetime)
		if deadline.Before(envelope.NextAttempt) {
			envelope.NextAttempt = deadline
		}
		d.log.Printf("retrying %s in %s: %s\n", envelope.ID, time.Until(envelope.NextAttempt).Round(time.Second), envelope.LastError)
		if err := d.queue.Retry(envelope); err != nil {
			return fmt.Errorf("retry %s: %w", envelope.ID, err)
		}
		return nil
	}
}

func (d *Deliverer) expire(envelope *queue.Envelope) (bool, error) {
	if time.Now().Before(envelope.Created.Add(d.lifetime)) {
		return false, nil
	}

	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status == queue.StatusPending {
			recipient.Status = queue.StatusFailed
			recipient.Detail = lifetimeDetail
		}
	}
	envelope.LastError = lifetimeDetail
	d.log.Printf("expiring %s after %s\n", envelope.ID, d.lifetime)
	return true, d.failTerminal(envelope)
}

func (d *Deliverer) complete(envelope *queue.Envelope) error {
	var delivered, failed int
	for i := range envelope.Recipients {
		switch envelope.Recipients[i].Status {
		case queue.StatusSent:
			delivered++
		case queue.StatusFailed:
			failed++
		}
	}
	d.log.Printf("completed %s: %d delivered, %d failed\n", envelope.ID, delivered, failed)

	// All-recipient permanent failure → dead-letter with preserved diagnostics.
	if delivered == 0 && failed > 0 {
		return d.failTerminal(envelope)
	}

	if err := d.ensureDSN(envelope); err != nil {
		return fmt.Errorf("dsn %s: %w", envelope.ID, err)
	}
	if err := d.queue.Finish(envelope); err != nil {
		return fmt.Errorf("finish %s: %w", envelope.ID, err)
	}
	return nil
}

func (d *Deliverer) failTerminal(envelope *queue.Envelope) error {
	if err := d.ensureDSN(envelope); err != nil {
		return fmt.Errorf("dsn %s: %w", envelope.ID, err)
	}
	if err := d.queue.Bury(envelope); err != nil {
		return fmt.Errorf("bury %s: %w", envelope.ID, err)
	}
	return nil
}

func (d *Deliverer) domain(ctx context.Context, envelope *queue.Envelope, domain string, indexes []int) error {
	hosts, err := d.hosts(ctx, domain)
	if err != nil {
		if errors.Is(err, errNullMX) || errors.Is(err, errNoSuchDomain) {
			d.reject(envelope, indexes, err.Error())
			return nil
		}
		return err
	}

	var (
		last              error
		sawEligible       bool
		capabilityOnly    = true
		sawUTF8CapErr     bool
		sawEightBitCapErr bool
	)

	for _, host := range hosts {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Hold global only around MX I/O.
		if err := d.acquireGlobal(ctx); err != nil {
			return err
		}
		done, err := d.send(ctx, envelope, host, indexes)
		d.releaseGlobal()
		if done {
			return nil
		}
		if err == nil {
			// send returned without completing or failing recipients permanently.
			capabilityOnly = false
			continue
		}
		sawEligible = true
		if errors.Is(err, errSMTPUTF8Unsupported) {
			sawUTF8CapErr = true
			if last == nil {
				last = err
			}
			continue
		}
		if errors.Is(err, err8BITMIMEUnsupported) {
			sawEightBitCapErr = true
			if last == nil {
				last = err
			}
			continue
		}
		// Any non-capability outcome means this is not a capability-only failure set.
		capabilityOnly = false
		if errors.Is(err, errPrivateDestination) {
			last = err
			continue
		}
		last = err
	}

	if sawEligible && capabilityOnly && (sawUTF8CapErr || sawEightBitCapErr) {
		d.reject(envelope, indexes, capabilityDetail(sawUTF8CapErr, sawEightBitCapErr))
		return nil
	}
	if last != nil && errors.Is(last, errPrivateDestination) {
		d.reject(envelope, indexes, last.Error())
		return nil
	}
	if last == nil {
		last = errors.New("no usable MX host")
	}
	return last
}

// capabilityDetail builds a permanent capability diagnostic without string-matching
// transient transport errors. When both requirements failed across candidates, both
// are reported.
func capabilityDetail(needUTF8, needEight bool) string {
	switch {
	case needUTF8 && needEight:
		return errSMTPUTF8Unsupported.Error() + "; " + err8BITMIMEUnsupported.Error()
	case needUTF8:
		return errSMTPUTF8Unsupported.Error()
	case needEight:
		return err8BITMIMEUnsupported.Error()
	default:
		return "required SMTP capability missing"
	}
}

func (d *Deliverer) acquireGlobal(ctx context.Context) error {
	select {
	case d.global <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Deliverer) releaseGlobal() {
	select {
	case <-d.global:
	default:
	}
}

func (d *Deliverer) send(ctx context.Context, envelope *queue.Envelope, host string, indexes []int) (bool, error) {
	client, err := d.connect(ctx, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	if envelope.SMTPUTF8 {
		supported, _ := client.Extension("SMTPUTF8")
		if !supported {
			_ = client.Quit()
			return false, errSMTPUTF8Unsupported
		}
	}
	if envelope.EightBit {
		supported, _ := client.Extension("8BITMIME")
		if !supported {
			_ = client.Quit()
			return false, err8BITMIMEUnsupported
		}
	}

	err = client.Mail(envelope.Sender, MailOpts{
		Size:     envelope.Size,
		UTF8:     envelope.SMTPUTF8,
		EightBit: envelope.EightBit,
	})
	if err != nil {
		if errors.Is(err, errSMTPUTF8Unsupported) || errors.Is(err, err8BITMIMEUnsupported) {
			_ = client.Quit()
			return false, err
		}
		if permanent(err) {
			d.reject(envelope, indexes, describe(err))
			return true, nil
		}
		return false, err
	}

	accepted := make([]int, 0, len(indexes))
	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		if recipient.Status != queue.StatusPending {
			continue
		}
		err = client.Rcpt(recipient.Address)
		if err == nil {
			accepted = append(accepted, index)
			continue
		}
		if permanent(err) {
			recipient.Status = queue.StatusFailed
			recipient.Detail = describe(err)
			continue
		}
		recipient.Detail = describe(err)
	}

	if len(accepted) == 0 {
		_ = client.Quit()
		return true, nil
	}

	reader, err := d.queue.Reader(envelope.ID)
	if err != nil {
		return false, err
	}
	defer reader.Close()

	dw, err := client.Data()
	if err != nil {
		if permanent(err) {
			d.reject(envelope, accepted, describe(err))
			return true, nil
		}
		return false, err
	}

	_, err = io.Copy(dw, reader)
	if err != nil {
		_ = dw.Close()
		return false, err
	}
	if err := dw.Close(); err != nil {
		if permanent(err) {
			d.reject(envelope, accepted, describe(err))
			return true, nil
		}
		return false, err
	}

	reply := dw.Reply()
	for _, index := range accepted {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusSent
		recipient.Detail = fmt.Sprintf("%s: %s", host, strings.TrimSpace(reply))
	}
	_ = client.Quit()
	return true, nil
}

func (d *Deliverer) connect(ctx context.Context, host string) (*Client, error) {
	ips, err := d.lookupHostIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errNoUsableIP
	}

	var last error
	var sawPublic bool
	for _, ip := range ips {
		if err := d.checkDestination(ip); err != nil {
			last = err
			continue
		}
		sawPublic = true
		client, err := d.dialAndSession(ctx, host, ip)
		if err == nil {
			return client, nil
		}
		last = err
	}
	if !sawPublic && last != nil {
		return nil, last
	}
	if last == nil {
		last = errNoUsableIP
	}
	return nil, last
}

func (d *Deliverer) lookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	network := d.lookupNetwork()
	addrs, err := d.resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	if d.orderIPs != nil {
		d.orderIPs(addrs)
	}
	return addrs, nil
}

// shuffleIPs is the production candidate-IP ordering: light shuffle for multi-A.
func shuffleIPs(addrs []net.IP) {
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
}

func (d *Deliverer) lookupNetwork() string {
	has4 := d.cfg.Delivery.BindIPv4 != "" || d.cfg.Delivery.BindIPv6 == ""
	has6 := d.cfg.Delivery.BindIPv6 != ""
	switch {
	case has4 && has6:
		return "ip"
	case has6 && !has4:
		return "ip6"
	default:
		return "ip4"
	}
}

func (d *Deliverer) checkDestination(ip net.IP) error {
	if d.cfg.Delivery.AllowPrivateDestinations {
		return nil
	}
	if d.allowlisted(ip) {
		return nil
	}
	if isRestricted(ip) {
		return fmt.Errorf("%w: %s", errPrivateDestination, ip)
	}
	return nil
}

func (d *Deliverer) allowlisted(ip net.IP) bool {
	if _, ok := d.allowlist[ip.String()]; ok {
		return true
	}
	// Also match canonical IPv4 forms.
	if ip4 := ip.To4(); ip4 != nil {
		if _, ok := d.allowlist[ip4.String()]; ok {
			return true
		}
	}
	return false
}

func isRestricted(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 0 {
			return true
		}
		if b[0] == 192 && b[1] == 0 && b[2] == 2 {
			return true
		}
		if b[0] == 198 && b[1] == 51 && b[2] == 100 {
			return true
		}
		if b[0] == 203 && b[1] == 0 && b[2] == 113 {
			return true
		}
		if b[0] >= 240 {
			return true
		}
	}
	return false
}

func (d *Deliverer) dialAndSession(ctx context.Context, mxHost string, ip net.IP) (*Client, error) {
	// Policy is fixed before dialing. Never reconnect with a weaker verification policy.
	policy := d.effectiveTLS()

	network, local := d.bindFor(ip)
	addr := net.JoinHostPort(ip.String(), "25")

	dialer := d.dialer
	if nd, ok := dialer.(*net.Dialer); ok {
		cp := *nd
		cp.Timeout = d.connTO
		if local != nil {
			cp.LocalAddr = local
		}
		dialer = &cp
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	client := NewClient(conn, d.command, d.submission)
	if err := client.Greet(); err != nil {
		client.Close()
		return nil, err
	}
	if err := client.EHLO(d.cfg.Server.Hostname); err != nil {
		client.Close()
		return nil, err
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
	if err := d.upgradeTLS(client, mxHost, policy); err != nil {
		client.Close()
		return nil, fmt.Errorf("%w: %v", errTLSFailed, err)
	}
	if err := client.EHLO(d.cfg.Server.Hostname); err != nil {
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
	if ip4 := ip.To4(); ip4 != nil {
		network = "tcp4"
		if b := d.cfg.Delivery.BindIPv4; b != "" {
			if lip := net.ParseIP(b); lip != nil {
				local = &net.TCPAddr{IP: lip}
			}
		}
		return network, local
	}
	network = "tcp6"
	if b := d.cfg.Delivery.BindIPv6; b != "" {
		if lip := net.ParseIP(b); lip != nil {
			local = &net.TCPAddr{IP: lip}
		}
	}
	return network, local
}

func (d *Deliverer) hosts(ctx context.Context, domain string) ([]string, error) {
	records, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		dnsErr, ok := errors.AsType[*net.DNSError](err)
		if !ok || !dnsErr.IsNotFound {
			return nil, err
		}
		_, err = d.resolver.LookupNetIP(ctx, d.lookupNetwork(), domain)
		if err != nil {
			if dnsErr, ok := errors.AsType[*net.DNSError](err); ok && dnsErr.IsNotFound {
				return nil, errNoSuchDomain
			}
			return nil, err
		}
		return []string{domain}, nil
	}

	if len(records) == 0 {
		return []string{domain}, nil
	}

	if len(records) == 1 && records[0].Host == "." {
		return nil, errNullMX
	}

	// Shuffle equal preferences, then stable-sort by preference.
	rand.Shuffle(len(records), func(i, j int) {
		records[i], records[j] = records[j], records[i]
	})
	slices.SortStableFunc(records, func(a, b *net.MX) int {
		return int(a.Pref) - int(b.Pref)
	})

	hosts := make([]string, 0, len(records))
	for _, record := range records {
		host := strings.TrimSuffix(record.Host, ".")
		if host != "" && host != "." {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return nil, errNullMX
	}
	return hosts, nil
}

func (d *Deliverer) reject(envelope *queue.Envelope, indexes []int, detail string) {
	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusFailed
		recipient.Detail = detail
	}
}

func (d *Deliverer) backoff(attempts int) time.Duration {
	delay := d.initial
	for range attempts - 1 {
		delay *= 2
		if delay >= d.maximum {
			delay = d.maximum
			break
		}
	}
	spread := int64(delay / 5)
	if spread <= 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(spread)) - delay/10
}
