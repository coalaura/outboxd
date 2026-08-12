package smtpd

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/emersion/go-smtp"
)

const (
	DefaultSubmissionAddr  = ":587"
	DefaultImplicitTLSAddr = ":465"

	maxResponseLength = 256

	defaultDataTimeout = 5 * time.Minute
)

// Logger receives operational messages.
type Logger interface {
	Printf(format string, values ...any)
	Println(values ...any)
}

// Server runs both submission listeners against a shared backend.
type Server struct {
	cfg         *config.Config
	queue       *queue.Queue
	signer      *sign.Signer
	log         Logger
	queueAdd    func(context.Context, *queue.Envelope, []byte) error
	signMessage func(context.Context, []byte) (string, error)

	connLimit   *connectionLimiter
	connections *connectionTracker
	authLimit   *authLimiter
	rates       *submissionLimiter

	// Bound concurrent Argon2id derivations (worker slots).
	hashing chan struct{}

	// Bound concurrent DATA parsing, normalization, signing, and queueing.
	dataWork chan struct{}

	starttls *smtp.Server
	implicit *smtp.Server

	starttlsListener net.Listener
	implicitListener net.Listener

	// shutdownHook is invoked once when shutdown starts (tests).
	shutdownHook func()

	// serveEntered is invoked once when a Serve loop has started (tests).
	serveEntered func()

	// shutdownContext builds the context used for graceful Shutdown (tests may inject).
	shutdownContext func(parent context.Context) (context.Context, context.CancelFunc)

	authConnections sync.Map
}

var (
	errTemporaryFailure = &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message:      "Temporary failure, try again later",
	}

	errSubmissionRate = &smtp.SMTPError{
		Code:         452,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "Submission rate limit exceeded, try again later",
	}

	errAuthBusy = &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message:      "Authentication busy, try again later",
	}

	errQueueFull = &smtp.SMTPError{
		Code:         452,
		EnhancedCode: smtp.EnhancedCode{4, 3, 1},
		Message:      "Queue full, try again later",
	}

	errTooManyRecipients = &smtp.SMTPError{
		Code:         452,
		EnhancedCode: smtp.EnhancedCode{4, 5, 3},
		Message:      "Too many recipients",
	}

	errDataBusy = &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 3, 2},
		Message:      "Message processing busy; connection closing",
	}
)

func (s *Server) newSMTP(cfg *config.Config, keeper *certs.Keeper) *smtp.Server {
	server := smtp.NewServer(smtp.BackendFunc(s.session))

	server.Domain = cfg.Server.Hostname
	server.TLSConfig = keeper.Config()
	server.MaxMessageBytes = cfg.Server.MaxMessageBytes
	server.ReadTimeout = config.Duration(cfg.Server.ReadTimeout)
	server.WriteTimeout = config.Duration(cfg.Server.WriteTimeout)
	server.AllowInsecureAuth = false
	server.EnableSMTPUTF8 = true
	server.ErrorLog = s.log

	return server
}

func (s *Server) session(c *smtp.Conn) (smtp.Session, error) {
	return &session{server: s, conn: c, authDeadline: s.authDeadline(c.Conn())}, nil
}

// acquireHashSlot admits hashing immediately. SMTP sessions have no cancellation
// context, so they must never remain queued behind expensive password work.
func (s *Server) acquireHashSlot() bool {
	select {
	case s.hashing <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseHashSlot() {
	<-s.hashing
}

func (s *Server) acquireDataSlot() bool {
	select {
	case s.dataWork <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseDataSlot() {
	<-s.dataWork
}

func (s *Server) dataTimeout() time.Duration {
	timeout := config.Duration(s.cfg.Server.ReadTimeout)
	if timeout <= 0 {
		return defaultDataTimeout
	}

	return timeout
}

// New builds the submission server.
func New(cfg *config.Config, keeper *certs.Keeper, signer *sign.Signer, spool *queue.Queue, log Logger) *Server {
	authWorkers := cfg.Server.AuthWorkers
	if authWorkers <= 0 {
		authWorkers = 4
	}

	dataWorkers := dataWorkerCount(cfg.Server.MaxMessageBytes)

	msgBurst := cfg.Server.MessageBurst
	if msgBurst <= 0 {
		msgBurst = burstDefault(cfg.Server.MaxMessagesPerHour)
	}

	rcptBurst := cfg.Server.RecipientBurst
	if rcptBurst <= 0 {
		rcptBurst = burstDefault(cfg.Server.MaxRecipientsPerHour)
	}

	srv := &Server{
		cfg:         cfg,
		queue:       spool,
		signer:      signer,
		log:         log,
		connLimit:   newConnectionLimiter(cfg.Server.MaxConnections, cfg.Server.MaxConnectionsPerIP),
		connections: newConnectionTracker(),
		authLimit:   newAuthLimiter(),
		rates:       newSubmissionLimiter(cfg.Server.MaxMessagesPerHour, cfg.Server.MaxRecipientsPerHour, msgBurst, rcptBurst),
		hashing:     make(chan struct{}, authWorkers),
		dataWork:    make(chan struct{}, dataWorkers),
	}

	srv.queueAdd = func(ctx context.Context, envelope *queue.Envelope, data []byte) error {
		return srv.queue.AddContext(ctx, envelope, data)
	}

	srv.signMessage = func(ctx context.Context, data []byte) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return srv.signer.Signature(data)
	}

	srv.starttls = srv.newSMTP(cfg, keeper)
	srv.implicit = srv.newSMTP(cfg, keeper)

	srv.starttls.Addr = cfg.Server.SubmissionListenAddr()
	srv.implicit.Addr = cfg.Server.ImplicitTLSListenAddr()

	return srv
}

func dataWorkerCount(maxMessageBytes int64) int {
	perWorker, ok := dataWorkerMemory(maxMessageBytes)
	if !ok {
		return 1
	}

	workers := int(config.DataMemoryBudget / perWorker)
	if workers < 1 {
		return 1
	}

	return min(workers, config.MaxDataWorkers)
}

func dataWorkerMemory(maxMessageBytes int64) (int64, bool) {
	if maxMessageBytes <= 0 || maxMessageBytes > (math.MaxInt64-config.DataMemoryOverhead)/config.DataMemoryCopies {
		return 0, false
	}

	return maxMessageBytes*config.DataMemoryCopies + config.DataMemoryOverhead, true
}

func incrementLimit(limit int64) int64 {
	if limit == math.MaxInt64 {
		return math.MaxInt64
	}

	return limit + 1
}

func burstDefault(hourly int) int {
	if hourly <= 0 {
		return 1
	}

	b := max(hourly/60, 1)

	if b > hourly {
		b = hourly
	}

	return b
}

// address normalizes an SMTP mailbox while preserving local-part case.
func address(value string) (string, error) {
	return mailbox.Address(value)
}

func needsUTF8(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}

	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}

	return false
}

func identifier() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strings.ToLower(rand.Text()[:10])
}

func host(c *smtp.Conn) string {
	addr := c.Conn().RemoteAddr()
	if addr == nil {
		return "unknown"
	}

	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return ip
}

func ignoreClosed(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, smtp.ErrServerClosed) {
		return nil
	}

	return err
}

func responseText(value string) string {
	value = strings.Map(func(char rune) rune {
		if char < 32 || char > 126 {
			return ' '
		}

		return char
	}, value)

	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "Invalid message"
	}

	if len(value) > maxResponseLength {
		return value[:maxResponseLength]
	}

	return value
}
