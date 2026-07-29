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

// Logger receives operational messages.
type Logger interface {
	Printf(format string, values ...any)
	Println(values ...any)
}

var errNullMX = errors.New("domain does not accept mail (null MX)")

// Deliverer drains the queue towards the destination MX servers.
type Deliverer struct {
	cfg   *config.Config
	queue *queue.Queue
	log   Logger

	resolver *net.Resolver
	dialer   *net.Dialer

	global  chan struct{}
	domains *domainLimiter

	command    time.Duration
	submission time.Duration
	initial    time.Duration
	maximum    time.Duration
}

// New builds the outbound delivery worker pool.
func New(cfg *config.Config, spool *queue.Queue, log Logger) *Deliverer {
	return &Deliverer{
		cfg:   cfg,
		queue: spool,
		log:   log,

		resolver: net.DefaultResolver,
		dialer:   &net.Dialer{Timeout: config.Duration(cfg.Delivery.ConnectionTimeout)},

		global:  make(chan struct{}, cfg.Delivery.GlobalConcurrency),
		domains: newDomainLimiter(cfg.Delivery.DomainConcurrency),

		command:    config.Duration(cfg.Delivery.CommandTimeout),
		submission: config.Duration(cfg.Delivery.SubmissionTimeout),
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
			return nil
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

		d.log.Printf("retrying %s in %s: %s\n", envelope.ID, time.Until(envelope.NextAttempt).Round(time.Second), envelope.LastError)

		err := d.queue.Retry(envelope)
		if err != nil {
			d.log.Printf("failed to reschedule %s: %v\n", envelope.ID, err)
		}
	}
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
		if errors.Is(err, errNullMX) {
			d.reject(envelope, indexes, err.Error())

			return nil
		}

		return err
	}

	var last error

	for _, host := range hosts {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		done, err := d.send(ctx, envelope, host, indexes)
		if done {
			return nil
		}

		last = err
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

	err = client.Mail(envelope.Sender, &smtp.MailOptions{Size: envelope.Size})
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

	client, err := d.dial(ctx, host, true)
	if err == nil {
		return client, nil
	}

	if required && d.cfg.Delivery.RequireValidMXTLSCert {
		return nil, err
	}

	client, verifyErr := d.dial(ctx, host, false)
	if verifyErr == nil {
		return client, nil
	}

	if required {
		return nil, errors.Join(err, verifyErr)
	}

	conn, plainErr := d.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
	if plainErr != nil {
		return nil, errors.Join(err, verifyErr, plainErr)
	}

	return smtp.NewClient(conn), nil
}

func (d *Deliverer) dial(ctx context.Context, host string, verify bool) (*smtp.Client, error) {
	conn, err := d.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
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
		if dnsErr, ok := errors.AsType[*net.DNSError](err); ok && dnsErr.IsNotFound {
			return []string{domain}, nil
		}

		return nil, err
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
