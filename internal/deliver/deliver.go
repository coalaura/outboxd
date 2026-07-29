package deliver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/emersion/go-smtp"
)

const lifetimeDetail = "maximum queue lifetime exceeded"

// Logger receives operational messages.
type Logger interface {
	Printf(format string, values ...any)
	Println(values ...any)
}

var (
	errNullMX              = errors.New("domain does not accept mail (null MX)")
	errNoSuchDomain        = errors.New("recipient domain does not exist")
	errSMTPUTF8Unsupported = errors.New("destination does not support SMTPUTF8")
)

// Deliverer drains the queue towards the destination MX servers.
type Deliverer struct {
	cfg   *config.Config
	queue *queue.Queue
	log   Logger

	resolver *net.Resolver
	dialer   *net.Dialer
	network  string

	global  chan struct{}
	domains *domainLimiter

	command    time.Duration
	submission time.Duration
	lifetime   time.Duration
	initial    time.Duration
	maximum    time.Duration
}

// New builds the outbound delivery worker pool.
func New(cfg *config.Config, spool *queue.Queue, log Logger) *Deliverer {
	dialer := &net.Dialer{Timeout: config.Duration(cfg.Delivery.ConnectionTimeout)}
	network := "tcp"

	if cfg.DNS.PublicIPv6 == "" {
		network = "tcp4"

		ip := net.ParseIP(cfg.DNS.PublicIPv4)
		if ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	return &Deliverer{
		cfg:   cfg,
		queue: spool,
		log:   log,

		resolver: net.DefaultResolver,
		dialer:   dialer,
		network:  network,

		global:  make(chan struct{}, cfg.Delivery.GlobalConcurrency),
		domains: newDomainLimiter(cfg.Delivery.DomainConcurrency),

		command:    config.Duration(cfg.Delivery.CommandTimeout),
		submission: config.Duration(cfg.Delivery.SubmissionTimeout),
		lifetime:   config.Duration(cfg.Delivery.MaximumLifetime),
		initial:    config.Duration(cfg.Delivery.InitialRetryDelay),
		maximum:    config.Duration(cfg.Delivery.MaximumRetryDelay),
	}
}

// Run delivers queued messages until ctx is cancelled.
func (d *Deliverer) Run(ctx context.Context) error {
	d.log.Printf("Delivery started with %d queued message(s)\n", d.queue.Len())

	var wg sync.WaitGroup

	defer wg.Wait()

	for {
		envelope, err := d.queue.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		select {
		case d.global <- struct{}{}:
		case <-ctx.Done():
			return nil
		}

		wg.Go(func() {
			defer func() {
				<-d.global
			}()

			d.attempt(ctx, envelope)
		})
	}
}

func (d *Deliverer) attempt(ctx context.Context, envelope *queue.Envelope) {
	if ctx.Err() != nil {
		return
	}

	if d.expire(envelope) {
		return
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

	for domain, indexes := range groups {
		if ctx.Err() != nil {
			break
		}

		err := d.domains.acquire(ctx, domain)
		if err != nil {
			break
		}

		err = d.domain(ctx, envelope, domain, indexes)

		d.domains.release(domain)

		if err != nil {
			envelope.LastError = fmt.Sprintf("%s: %s", domain, err)
		}
	}

	switch {
	case envelope.Pending() == 0:
		d.finish(envelope)
	case envelope.Attempts >= d.cfg.Delivery.MaxAttempts:
		for i := range envelope.Recipients {
			recipient := &envelope.Recipients[i]

			if recipient.Status == queue.StatusPending {
				recipient.Status = queue.StatusFailed
				recipient.Detail = "delivery attempts exhausted"
			}
		}

		d.log.Printf("giving up on %s after %d attempts: %s\n", envelope.ID, envelope.Attempts, envelope.LastError)

		err := d.queue.Bury(envelope)
		if err != nil {
			d.log.Printf("failed to bury %s: %v\n", envelope.ID, err)
		}
	default:
		envelope.NextAttempt = time.Now().Add(d.backoff(envelope.Attempts))

		deadline := envelope.Created.Add(d.lifetime)
		if deadline.Before(envelope.NextAttempt) {
			envelope.NextAttempt = deadline
		}

		d.log.Printf("retrying %s in %s: %s\n", envelope.ID, time.Until(envelope.NextAttempt).Round(time.Second), envelope.LastError)

		err := d.queue.Retry(envelope)
		if err != nil {
			d.log.Printf("failed to reschedule %s: %v\n", envelope.ID, err)
		}
	}
}

func (d *Deliverer) expire(envelope *queue.Envelope) bool {
	if time.Now().Before(envelope.Created.Add(d.lifetime)) {
		return false
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

	err := d.queue.Bury(envelope)
	if err != nil {
		d.log.Printf("failed to bury expired message %s: %v\n", envelope.ID, err)
	}

	return true
}

func (d *Deliverer) finish(envelope *queue.Envelope) {
	var delivered int

	for i := range envelope.Recipients {
		if envelope.Recipients[i].Status == queue.StatusSent {
			delivered++
		}
	}

	d.log.Printf("completed %s: %d delivered, %d failed\n", envelope.ID, delivered, len(envelope.Recipients)-delivered)

	err := d.queue.Finish(envelope)
	if err != nil {
		d.log.Printf("failed to remove %s: %v\n", envelope.ID, err)
	}
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
		last               error
		allUTF8Unsupported = len(hosts) > 0
	)

	for _, host := range hosts {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		done, err := d.send(ctx, envelope, host, indexes)
		if done {
			return nil
		}

		if errors.Is(err, errSMTPUTF8Unsupported) {
			if last == nil {
				last = err
			}

			continue
		}

		allUTF8Unsupported = false
		last = err
	}

	if allUTF8Unsupported && last != nil {
		d.reject(envelope, indexes, errSMTPUTF8Unsupported.Error())

		return nil
	}

	if last == nil {
		last = errors.New("no usable MX host")
	}

	return last
}

func (d *Deliverer) send(ctx context.Context, envelope *queue.Envelope, host string, indexes []int) (bool, error) {
	client, err := d.connect(ctx, host)
	if err != nil {
		return false, err
	}

	defer client.Close()

	client.CommandTimeout = d.command
	client.SubmissionTimeout = d.submission

	if envelope.SMTPUTF8 {
		supported, _ := client.Extension("SMTPUTF8")
		if !supported {
			client.Quit()

			return false, errSMTPUTF8Unsupported
		}
	}

	err = client.Mail(envelope.Sender, &smtp.MailOptions{
		Size: envelope.Size,
		UTF8: envelope.SMTPUTF8,
	})

	if err != nil {
		if permanent(err) {
			d.reject(envelope, indexes, describe(err))

			return true, nil
		}

		return false, err
	}

	accepted := make([]int, 0, len(indexes))

	for _, index := range indexes {
		recipient := &envelope.Recipients[index]

		// An earlier MX in this attempt already rejected the address for good.
		if recipient.Status != queue.StatusPending {
			continue
		}

		err = client.Rcpt(recipient.Address, nil)
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
		client.Quit()

		return true, nil
	}

	reader, err := d.queue.Reader(envelope.ID)
	if err != nil {
		return false, err
	}

	defer reader.Close()

	data, err := client.Data()
	if err != nil {
		if permanent(err) {
			d.reject(envelope, accepted, describe(err))

			return true, nil
		}

		return false, err
	}

	_, err = io.Copy(data, reader)
	if err != nil {
		return false, err
	}

	response, err := data.CloseWithResponse()
	if err != nil {
		if permanent(err) {
			d.reject(envelope, accepted, describe(err))

			return true, nil
		}

		return false, err
	}

	for _, index := range accepted {
		recipient := &envelope.Recipients[index]

		recipient.Status = queue.StatusSent
		recipient.Detail = fmt.Sprintf("%s: %s", host, strings.TrimSpace(response.StatusText))
	}

	client.Quit()

	return true, nil
}

func (d *Deliverer) connect(ctx context.Context, host string) (*smtp.Client, error) {
	required := d.cfg.Delivery.TLSMode == "required"
	requireValidCertificate := d.cfg.Delivery.RequireValidMXTLSCert

	client, verifiedErr := d.dial(ctx, host, true)
	if verifiedErr == nil {
		return client, nil
	}

	var unverifiedErr error

	if requireValidCertificate {
		if required {
			return nil, verifiedErr
		}
	} else {
		client, unverifiedErr = d.dial(ctx, host, false)
		if unverifiedErr == nil {
			return client, nil
		}

		if required {
			return nil, errors.Join(verifiedErr, unverifiedErr)
		}
	}

	conn, plainErr := d.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
	if plainErr != nil {
		return nil, errors.Join(verifiedErr, unverifiedErr, plainErr)
	}

	client = smtp.NewClient(conn)

	helloErr := client.Hello(d.cfg.Server.Hostname)
	if helloErr != nil {
		client.Close()

		return nil, errors.Join(verifiedErr, unverifiedErr, helloErr)
	}

	return client, nil
}

func (d *Deliverer) dial(ctx context.Context, host string, verify bool) (*smtp.Client, error) {
	conn, err := d.dialer.DialContext(ctx, d.network, net.JoinHostPort(host, "25"))
	if err != nil {
		return nil, err
	}

	client, err := smtp.NewClientStartTLS(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// Deliberate: opportunistic TLS to an unknown MX is still better than plaintext,
		// most MX certificates are not publicly trusted.
		InsecureSkipVerify: !verify,
	})

	if err != nil {
		conn.Close()

		return nil, err
	}

	err = client.Hello(d.cfg.Server.Hostname)
	if err != nil {
		client.Close()

		return nil, err
	}

	return client, nil
}

func (d *Deliverer) hosts(ctx context.Context, domain string) ([]string, error) {
	records, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		dnsErr, ok := errors.AsType[*net.DNSError](err)
		if !ok || !dnsErr.IsNotFound {
			return nil, err
		}

		_, err = d.resolver.LookupNetIP(ctx, "ip", domain)
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

	rand.Shuffle(len(records), func(i, j int) {
		records[i], records[j] = records[j], records[i]
	})

	slices.SortStableFunc(records, func(a, b *net.MX) int {
		return int(a.Pref) - int(b.Pref)
	})

	hosts := make([]string, 0, len(records))

	for _, record := range records {
		host := strings.TrimSuffix(record.Host, ".")

		if host != "" {
			hosts = append(hosts, host)
		}
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

func permanent(err error) bool {
	if smtpErr, ok := errors.AsType[*smtp.SMTPError](err); ok {
		return smtpErr.Code >= 500
	}

	return false
}

func describe(err error) string {
	if smtpErr, ok := errors.AsType[*smtp.SMTPError](err); ok {
		return fmt.Sprintf("%d %s", smtpErr.Code, strings.TrimSpace(smtpErr.Message))
	}

	return err.Error()
}
