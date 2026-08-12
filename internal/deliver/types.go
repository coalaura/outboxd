package deliver

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
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

	// orderIPs rotates sorted candidates before truncation. Production shuffles;
	// tests may replace it for deterministic ordering.
	orderIPs func([]net.IP)
	// orderMX rotates one sorted equal-preference group before truncation.
	orderMX func([]*net.MX)

	// active bounds concurrent attempt goroutines. Run admits the first pending
	// domain before spawning, so these slots are never consumed by domain waiters.
	active  chan struct{}
	global  chan struct{}
	domains *domainLimiter
	users   *domainLimiter

	command    time.Duration
	submission time.Duration
	lifetime   time.Duration
	initial    time.Duration
	maximum    time.Duration
	connTO     time.Duration
	dnsTO      time.Duration
	attemptTO  time.Duration
	admission  time.Duration
	maxMX      int
	maxIP      int

	allowlist map[string]struct{}

	// next pulls the next due envelope. Nil means use queue.Next (tests may override).
	next func(context.Context) (*queue.Envelope, error)

	// reader opens a queued message body. Tests may replace it.
	reader func(string) (io.ReadCloser, error)

	// fatal signals Run to stop on queue persistence failure
	mu    sync.Mutex
	fatal error
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
