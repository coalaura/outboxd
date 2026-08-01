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

const (
	lifetimeDetail             = "maximum queue lifetime exceeded"
	exhaustedDetail            = "delivery attempts exhausted"
	terminalEnhancedCode       = "5.4.7"
	storageRetryDelay          = 30 * time.Second
	defaultAdmissionRetryDelay = 30 * time.Second
)

var (
	errBodyTooShort = errors.New("queued body shorter than envelope size")
	errBodyTooLong  = errors.New("queued body longer than envelope size")
)

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

	// active bounds concurrent attempt goroutines. Run admits the first pending
	// domain before spawning, so these slots are never consumed by domain waiters.
	active  chan struct{}
	global  chan struct{}
	domains *domainLimiter

	command    time.Duration
	submission time.Duration
	lifetime   time.Duration
	initial    time.Duration
	maximum    time.Duration
	connTO     time.Duration
	admission  time.Duration

	allowlist map[string]struct{}

	// next pulls the next due envelope. Nil means use queue.Next (tests may override).
	next func(context.Context) (*queue.Envelope, error)

	// reader opens a queued message body. Tests may replace it.
	reader func(string) (io.ReadCloser, error)

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
	// Cap attempt workers above global MX concurrency while preventing unbounded
	// goroutine growth.
	attemptLimit := max(cfg.Delivery.GlobalConcurrency*4, 8)

	d := &Deliverer{
		cfg:    cfg,
		queue:  spool,
		log:    log,
		signer: signer,

		resolver: netResolver{r: net.DefaultResolver},
		dialer:   &net.Dialer{Timeout: config.Duration(cfg.Delivery.ConnectionTimeout)},
		orderIPs: shuffleIPs,
		next:     spool.Next,
		reader: func(id string) (io.ReadCloser, error) {
			return spool.Reader(id)
		},

		active:  make(chan struct{}, attemptLimit),
		global:  make(chan struct{}, cfg.Delivery.GlobalConcurrency),
		domains: newDomainLimiter(cfg.Delivery.DomainConcurrency),

		command:    config.Duration(cfg.Delivery.CommandTimeout),
		submission: config.Duration(cfg.Delivery.SubmissionTimeout),
		lifetime:   config.Duration(cfg.Delivery.MaximumLifetime),
		initial:    config.Duration(cfg.Delivery.InitialRetryDelay),
		maximum:    config.Duration(cfg.Delivery.MaximumRetryDelay),
		connTO:     config.Duration(cfg.Delivery.ConnectionTimeout),
		admission:  defaultAdmissionRetryDelay,

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

	// Registered first so it runs last: cancel() must fire before we wait.
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	next := d.next
	if next == nil {
		next = d.queue.Next
	}

	for {
		err := d.fatalErr()
		if err != nil {
			cancel()
			wg.Wait()
			return err
		}

		envelope, err := next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				ferr := d.fatalErr()
				if ferr != nil {
					return ferr
				}

				return nil
			}

			return err
		}

		if ctx.Err() != nil {
			d.queue.Requeue(envelope)

			ferr := d.fatalErr()
			if ferr != nil {
				return ferr
			}

			return nil
		}

		admittedDomain := nextPendingDomain(envelope)
		if !d.domains.tryAcquire(admittedDomain) {
			// Admission is an in-memory scheduling decision, not a delivery attempt.
			d.queue.RequeueAfter(envelope, d.admission)
			continue
		}

		// Bound concurrent attempt goroutines after domain-aware admission.
		select {
		case d.active <- struct{}{}:
		case <-ctx.Done():
			d.domains.release(admittedDomain)
			d.queue.Requeue(envelope)

			ferr := d.fatalErr()
			if ferr != nil {
				return ferr
			}

			return nil
		}

		wg.Go(func() {
			defer func() { <-d.active }()

			err := d.attemptAdmitted(ctx, envelope, admittedDomain)
			if err != nil {
				if queue.IsStoragePressure(err) {
					d.queue.RequeueAfter(envelope, storageRetryDelay)
					d.log.Printf("storage pressure handling %s; retrying queue state in %s: %s\n", envelope.ID, storageRetryDelay, err)
					return
				}

				d.setFatal(err)
				cancel()
			}
		})
	}
}

func nextPendingDomain(envelope *queue.Envelope) string {
	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status == queue.StatusPending {
			return recipient.Domain
		}
	}

	return ""
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
	domain := nextPendingDomain(envelope)
	if !d.domains.tryAcquire(domain) {
		envelope.NextAttempt = time.Now().Add(d.admission)
		d.log.Printf("rescheduling %s for domain capacity in %s\n", envelope.ID, d.admission)
		if err := d.queue.Retry(envelope); err != nil {
			return fmt.Errorf("reschedule %s for domain capacity: %w", envelope.ID, err)
		}
		return nil
	}

	return d.attemptAdmitted(ctx, envelope, domain)
}

func (d *Deliverer) attemptAdmitted(ctx context.Context, envelope *queue.Envelope, admittedDomain string) error {
	heldDomain := admittedDomain
	defer func() {
		if heldDomain != "" {
			d.domains.release(heldDomain)
		}
	}()

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

	deadline := envelope.Created.Add(d.lifetime)
	current, ok := ctx.Deadline()
	if !ok || deadline.Before(current) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	envelope.Attempts++
	envelope.LastError = ""

	groups := make(map[string][]int, len(envelope.Recipients))
	groupOrder := make([]string, 0, len(envelope.Recipients))

	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status != queue.StatusPending {
			continue
		}

		_, ok := groups[recipient.Domain]
		if !ok {
			groupOrder = append(groupOrder, recipient.Domain)
		}

		groups[recipient.Domain] = append(groups[recipient.Domain], i)
	}

	diagnostics := make([]string, 0, len(groupOrder))

	for _, domain := range groupOrder {
		indexes := groups[domain]
		if ctx.Err() != nil {
			break
		}
		if heldDomain != domain {
			if !d.domains.tryAcquire(domain) {
				diagnostics = append(diagnostics, normalizeDiagnostic(fmt.Sprintf("%s: delivery concurrency unavailable", domain)))
				break
			}
			heldDomain = domain
		}

		previousDetails := make([]string, len(indexes))
		for i, index := range indexes {
			previousDetails[i] = envelope.Recipients[index].Detail
		}
		err := d.domain(ctx, envelope, domain, indexes)
		d.domains.release(domain)
		heldDomain = ""

		if ctx.Err() != nil {
			for i, index := range indexes {
				recipient := &envelope.Recipients[index]
				if recipient.Status == queue.StatusPending {
					recipient.Detail = previousDetails[i]
				}
			}
			break
		}
		if err != nil {
			detail := normalizeDiagnostic(fmt.Sprintf("%s: %s", domain, err))
			diagnostics = append(diagnostics, detail)
			for _, index := range indexes {
				recipient := &envelope.Recipients[index]
				if recipient.Status == queue.StatusPending && recipient.Detail == "" {
					recipient.Detail = detail
				}
			}
		}
	}

	envelope.LastError = normalizeDiagnostic(strings.Join(diagnostics, "; "))

	switch {
	case envelope.Pending() == 0:
		return d.complete(envelope)
	case ctx.Err() != nil && time.Now().Before(deadline):
		envelope.Attempts--
		envelope.NextAttempt = time.Now()
		err = d.queue.Retry(envelope)
		if err != nil {
			return fmt.Errorf("retry canceled %s: %w", envelope.ID, err)
		}

		return nil
	case ctx.Err() != nil:
		return d.expirePending(envelope)
	case envelope.Attempts >= d.cfg.Delivery.MaxAttempts:

		for i := range envelope.Recipients {
			recipient := &envelope.Recipients[i]
			if recipient.Status == queue.StatusPending {
				recipient.Status = queue.StatusFailed

				// Preserve the most useful diagnostic for DSN/dead-letter.
				switch {
				case recipient.Detail != "":
					// keep capability-specific or prior MX detail
				default:
					recipient.Detail = exhaustedDetail
				}

				recipient.Code = 554
				recipient.EnhancedCode = terminalEnhancedCode
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

		err = d.queue.Retry(envelope)
		if err != nil {
			return fmt.Errorf("retry %s: %w", envelope.ID, err)
		}

		return nil
	}
}

func (d *Deliverer) expire(envelope *queue.Envelope) (bool, error) {
	if time.Now().Before(envelope.Created.Add(d.lifetime)) {
		return false, nil
	}

	return true, d.expirePending(envelope)
}

func (d *Deliverer) expirePending(envelope *queue.Envelope) error {
	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status == queue.StatusPending {
			recipient.Status = queue.StatusFailed
			recipient.Detail = lifetimeDetail
			recipient.Code = 554
			recipient.EnhancedCode = terminalEnhancedCode
		}
	}

	envelope.LastError = lifetimeDetail
	d.log.Printf("expiring %s after %s\n", envelope.ID, d.lifetime)
	return d.failTerminal(envelope)
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

	err := d.ensureDSN(envelope)
	if err != nil {
		return fmt.Errorf("dsn %s: %w", envelope.ID, err)
	}

	err = d.queue.Finish(envelope)
	if err != nil {
		if errors.Is(err, queue.ErrCleanup) {
			d.log.Printf("finished %s with deferred cleanup: %s\n", envelope.ID, err)
			return nil
		}

		return fmt.Errorf("finish %s: %w", envelope.ID, err)
	}

	return nil
}

func (d *Deliverer) failTerminal(envelope *queue.Envelope) error {
	err := d.ensureDSN(envelope)
	if err != nil {
		return fmt.Errorf("dsn %s: %w", envelope.ID, err)
	}

	err = d.queue.Bury(envelope)
	if err != nil {
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
		sawRetryable      bool
		capabilityOnly    = true
		sawUTF8CapErr     bool
		sawEightBitCapErr bool
	)

	for _, host := range hosts {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Hold global only around MX I/O.
		err = d.acquireGlobal(ctx)
		if err != nil {
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
			sawRetryable = true
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
			// Do not overwrite a prior retryable diagnostic with a private-destination
			// error; mixed outcomes must stay temporary (same class as capability mix).
			if last == nil {
				last = err
			}

			continue
		}

		sawRetryable = true
		last = err
	}

	if sawEligible && capabilityOnly && (sawUTF8CapErr || sawEightBitCapErr) {
		d.reject(envelope, indexes, capabilityDetail(sawUTF8CapErr, sawEightBitCapErr))
		return nil
	}

	if last != nil && !sawRetryable && errors.Is(last, errPrivateDestination) {
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
	// Called only after a successful acquireGlobal.
	<-d.global
}

func (d *Deliverer) send(ctx context.Context, envelope *queue.Envelope, host string, indexes []int) (bool, error) {
	client, err := d.connect(ctx, host, !envelope.SMTPUTF8 && !envelope.EightBit)
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
			d.rejectSMTP(envelope, indexes, err)
			return true, nil
		}

		return false, err
	}

	accepted := make([]int, 0, len(indexes))
	temporary := make([]string, 0, len(indexes))

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
			d.rejectSMTP(envelope, []int{index}, err)
			continue
		}

		recipient.Detail = describe(err)
		temporary = append(temporary, fmt.Sprintf("%s: %s", recipient.Address, recipient.Detail))
	}

	if len(accepted) == 0 {
		_ = client.Quit()
		if len(temporary) > 0 {
			return false, fmt.Errorf("temporary RCPT failures: %s", strings.Join(temporary, "; "))
		}
		return true, nil
	}

	openReader := d.reader
	if openReader == nil {
		openReader = func(id string) (io.ReadCloser, error) { return d.queue.Reader(id) }
	}

	reader, err := openReader(envelope.ID)
	if err != nil {
		return false, err
	}

	defer reader.Close()

	dw, err := client.Data()
	if err != nil {
		if permanent(err) {
			d.rejectSMTP(envelope, accepted, err)
			return true, nil
		}

		return false, err
	}

	written, err := io.Copy(dw, io.LimitReader(reader, envelope.Size+1))
	if err != nil {
		// Closing DotWriter emits the DATA terminator. Abort the transport instead.
		_ = client.Close()
		return false, err
	}

	if written != envelope.Size {
		// Closing DotWriter emits the DATA terminator, so body integrity failures
		// must abort the transport directly.
		_ = client.Close()
		if written < envelope.Size {
			return false, fmt.Errorf("%w: got %d, want %d", errBodyTooShort, written, envelope.Size)
		}

		return false, fmt.Errorf("%w: got at least %d, want %d", errBodyTooLong, written, envelope.Size)
	}

	err = dw.Close()
	if err != nil {
		if permanent(err) {
			d.rejectSMTP(envelope, accepted, err)
			return true, nil
		}

		return false, err
	}

	reply := dw.Reply()

	for _, index := range accepted {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusSent
		recipient.Detail = normalizeDiagnostic(fmt.Sprintf("%s: %s", host, reply))
	}

	_ = client.Quit()
	if len(temporary) > 0 {
		return false, fmt.Errorf("temporary RCPT failures: %s", strings.Join(temporary, "; "))
	}
	return true, nil
}

func (d *Deliverer) connect(ctx context.Context, host string, noExtensions bool) (*Client, error) {
	ips, err := d.lookupHostIPs(ctx, host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, errNoUsableIP
	}

	var (
		last      error
		sawPublic bool
	)

	for _, ip := range ips {
		err = d.checkDestination(ip)
		if err != nil {
			last = err
			continue
		}

		sawPublic = true
		client, err := d.dialAndSession(ctx, host, ip, noExtensions)
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
	_, ok := d.allowlist[ip.String()]
	if ok {
		return true
	}

	// Also match canonical IPv4 forms.
	ip4 := ip.To4()
	if ip4 != nil {
		_, ok := d.allowlist[ip4.String()]
		if ok {
			return true
		}
	}

	return false
}

func isRestricted(ip net.IP) bool {
	if ip == nil {
		return true
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}

	addr = addr.Unmap()

	for _, prefix := range restrictedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

var restrictedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
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

	conn, err := dialer.DialContext(ctx, network, addr)
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

func (d *Deliverer) hosts(ctx context.Context, domain string) ([]string, error) {
	records, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		dnsErr, ok := errors.AsType[*net.DNSError](err)
		if !ok || !dnsErr.IsNotFound {
			return nil, err
		}

		_, err = d.resolver.LookupNetIP(ctx, d.lookupNetwork(), domain)
		if err != nil {
			dnsErr, ok = errors.AsType[*net.DNSError](err)
			if ok && dnsErr.IsNotFound {
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
	detail = normalizeDiagnostic(detail)

	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusFailed
		recipient.Detail = detail
	}
}

func (d *Deliverer) rejectSMTP(envelope *queue.Envelope, indexes []int, err error) {
	detail := describe(err)
	code := smtpCode(err)
	enhanced := smtpEnhancedCode(err)

	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusFailed
		recipient.Detail = detail
		recipient.Code = code
		recipient.EnhancedCode = enhanced
	}
}

func (d *Deliverer) backoff(attempts int) time.Duration {
	delay := d.initial

	for range attempts - 1 {
		if delay >= d.maximum || delay > d.maximum/2 {
			delay = d.maximum
			break
		}

		delay *= 2
	}

	spread := int64(delay / 5)
	if spread <= 0 {
		return delay
	}

	delta := time.Duration(rand.Int64N(spread)) - delay/10
	if delta > 0 && delay > d.maximum-delta {
		return d.maximum
	}

	delay += delta
	if delay > d.maximum {
		return d.maximum
	}

	return delay
}
