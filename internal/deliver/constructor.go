package deliver

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

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

// New builds the outbound delivery worker pool.
func New(cfg *config.Config, spool *queue.Queue, log Logger) *Deliverer {
	return NewWithSigner(cfg, spool, log, nil)
}

// NewWithSigner is New with an optional DKIM signer for failure DSNs.
func NewWithSigner(cfg *config.Config, spool *queue.Queue, log Logger, signer Signer) *Deliverer {
	defaults := config.Default().Delivery

	var debugLog debugLogger

	if cfg.LogLevel == "debug" {
		debugLog, _ = log.(debugLogger)
	}

	userConcurrency := cfg.Delivery.UserConcurrency
	if userConcurrency <= 0 {
		userConcurrency = defaults.UserConcurrency
	}

	maxMX := cfg.Delivery.MaxMXCandidates
	if maxMX <= 0 {
		maxMX = defaults.MaxMXCandidates
	}

	maxIP := cfg.Delivery.MaxIPCandidatesPerMX
	if maxIP <= 0 {
		maxIP = defaults.MaxIPCandidatesPerMX
	}

	dnsTimeout := config.Duration(cfg.Delivery.DNSTimeout)
	if dnsTimeout <= 0 {
		dnsTimeout = config.Duration(defaults.DNSTimeout)
	}

	attemptTimeout := config.Duration(cfg.Delivery.AttemptTimeout)
	if attemptTimeout <= 0 {
		attemptTimeout = config.Duration(defaults.AttemptTimeout)
	}

	// Cap attempt workers above global MX concurrency while preventing unbounded
	// goroutine growth.
	attemptLimit := max(cfg.Delivery.GlobalConcurrency*4, 8)

	d := &Deliverer{
		cfg:      cfg,
		queue:    spool,
		log:      log,
		signer:   signer,
		debugLog: debugLog,

		resolver:    netResolver{r: net.DefaultResolver},
		dialer:      &net.Dialer{Timeout: config.Duration(cfg.Delivery.ConnectionTimeout)},
		tlsSessions: tls.NewLRUClientSessionCache(64),
		orderIPs:    shuffleIPs,
		orderMX:     shuffleMX,
		next:        spool.Next,
		reader: func(id string, body int) (io.ReadCloser, error) {
			return spool.ReaderVariant(id, body)
		},

		active:  make(chan struct{}, attemptLimit),
		global:  make(chan struct{}, cfg.Delivery.GlobalConcurrency),
		domains: newDomainLimiter(cfg.Delivery.DomainConcurrency),
		users:   newDomainLimiter(userConcurrency),

		command:    config.Duration(cfg.Delivery.CommandTimeout),
		submission: config.Duration(cfg.Delivery.SubmissionTimeout),
		lifetime:   config.Duration(cfg.Delivery.MaximumLifetime),
		initial:    config.Duration(cfg.Delivery.InitialRetryDelay),
		maximum:    config.Duration(cfg.Delivery.MaximumRetryDelay),
		connTO:     config.Duration(cfg.Delivery.ConnectionTimeout),
		dnsTO:      dnsTimeout,
		attemptTO:  attemptTimeout,
		admission:  defaultAdmissionRetryDelay,
		maxMX:      maxMX,
		maxIP:      maxIP,

		allowlist: make(map[string]struct{}),
	}

	for _, a := range cfg.Delivery.DestinationAllowlist {
		ip := net.ParseIP(a)
		if ip != nil {
			d.allowlist[ip.String()] = struct{}{}
		}
	}

	d.users.onRelease = func(owner string) {
		d.wakeAdmission(admissionUser, owner)
	}

	d.domains.onRelease = func(domain string) {
		d.wakeAdmission(admissionDomain, domain)
	}

	return d
}
