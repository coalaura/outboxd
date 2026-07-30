package smtpd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/emersion/go-smtp"
)

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

	errTooManyConnections = &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 3, 2},
		Message:      "Too many connections, try again later",
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
)

const (
	DefaultSubmissionAddr  = ":587"
	DefaultImplicitTLSAddr = ":465"

	maxResponseLength = 256
)

// shutdownTimeout bounds graceful Shutdown during Run.
// Tests may lower this for deterministic timeout-path coverage.
var shutdownTimeout = 30 * time.Second

// Logger receives operational messages.
type Logger interface {
	Printf(format string, values ...any)
	Println(values ...any)
}

// Server runs both submission listeners against a shared backend.
type Server struct {
	cfg    *config.Config
	queue  *queue.Queue
	signer *sign.Signer
	log    Logger

	connLimit *connectionLimiter
	authLimit *authLimiter
	rates     *submissionLimiter

	// Bound concurrent Argon2id derivations (worker slots).
	hashing chan struct{}
	// Bound waiters that may sit waiting for a hashing slot.
	authWait chan struct{}

	starttls *smtp.Server
	implicit *smtp.Server

	starttlsListener net.Listener
	implicitListener net.Listener

	// shutdownHook is invoked once when shutdown starts (tests).
	shutdownHook func()
}

// New builds the submission server.
func New(cfg *config.Config, keeper *certs.Keeper, signer *sign.Signer, spool *queue.Queue, log Logger) *Server {
	authWorkers := cfg.Server.AuthWorkers
	if authWorkers <= 0 {
		authWorkers = 4
	}
	authQueue := cfg.Server.AuthQueue
	if authQueue <= 0 {
		authQueue = 64
	}

	msgBurst := cfg.Server.MessageBurst
	if msgBurst <= 0 {
		msgBurst = burstDefault(cfg.Server.MaxMessagesPerHour)
	}
	rcptBurst := cfg.Server.RecipientBurst
	if rcptBurst <= 0 {
		rcptBurst = burstDefault(cfg.Server.MaxRecipientsPerHour)
	}

	srv := &Server{
		cfg:       cfg,
		queue:     spool,
		signer:    signer,
		log:       log,
		connLimit: newConnectionLimiter(cfg.Server.MaxConnections, cfg.Server.MaxConnectionsPerIP),
		authLimit: newAuthLimiter(),
		rates:     newSubmissionLimiter(cfg.Server.MaxMessagesPerHour, cfg.Server.MaxRecipientsPerHour, msgBurst, rcptBurst),
		hashing:   make(chan struct{}, authWorkers),
		authWait:  make(chan struct{}, authQueue),
	}

	srv.starttls = srv.newSMTP(cfg, keeper)
	srv.implicit = srv.newSMTP(cfg, keeper)

	srv.starttls.Addr = cfg.Server.SubmissionListenAddr()
	srv.implicit.Addr = cfg.Server.ImplicitTLSListenAddr()

	return srv
}

func burstDefault(hourly int) int {
	if hourly <= 0 {
		return 1
	}
	b := hourly / 60
	if b < 1 {
		b = 1
	}
	if b > hourly {
		b = hourly
	}
	return b
}

func (s *Server) newSMTP(cfg *config.Config, keeper *certs.Keeper) *smtp.Server {
	server := smtp.NewServer(smtp.BackendFunc(s.session))
	server.Domain = cfg.Server.Hostname
	server.TLSConfig = keeper.Config()
	server.MaxMessageBytes = cfg.Server.MaxMessageBytes
	server.MaxRecipients = cfg.Server.MaxRecipients
	server.ReadTimeout = config.Duration(cfg.Server.ReadTimeout)
	server.WriteTimeout = config.Duration(cfg.Server.WriteTimeout)
	server.AllowInsecureAuth = false
	server.EnableSMTPUTF8 = true
	server.ErrorLog = s.log
	return server
}

// Listen opens configured submission listeners without starting accept loops.
func (s *Server) Listen() error {
	if s.starttlsListener != nil || s.implicitListener != nil {
		return errors.New("submission listeners are already open")
	}

	var opened []net.Listener
	cleanup := func() {
		for _, l := range opened {
			_ = l.Close()
		}
		s.starttlsListener = nil
		s.implicitListener = nil
	}

	if addr := s.cfg.Server.SubmissionListenAddr(); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", addr, err)
		}
		s.starttlsListener = ln
		opened = append(opened, ln)
		s.starttls.Addr = ln.Addr().String()
	}

	if addr := s.cfg.Server.ImplicitTLSListenAddr(); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			cleanup()
			return fmt.Errorf("listen on %s: %w", addr, err)
		}
		s.implicitListener = ln
		opened = append(opened, ln)
		s.implicit.Addr = ln.Addr().String()
	}

	if s.starttlsListener == nil && s.implicitListener == nil {
		return errors.New("no submission listeners enabled")
	}

	parts := make([]string, 0, 2)
	if s.starttlsListener != nil {
		parts = append(parts, fmt.Sprintf("%s (STARTTLS)", s.starttls.Addr))
	}
	if s.implicitListener != nil {
		parts = append(parts, fmt.Sprintf("%s (implicit TLS)", s.implicit.Addr))
	}
	s.log.Printf("Listening for submission on %s\n", strings.Join(parts, " and "))
	return nil
}

// Run serves open listeners until ctx is cancelled or a Serve loop fails.
// Parent cancellation and unexpected Serve exits both trigger graceful shutdown.
// Run always returns after both accept loops finish; no waiter blocks solely on
// the parent context after the server has already failed.
func (s *Server) Run(ctx context.Context) error {
	if s.starttlsListener == nil && s.implicitListener == nil {
		return errors.New("submission listeners are not open")
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
		once sync.Once
	)
	active := atomic.Int32{}

	record := func(err error) {
		if err = ignoreClosed(err); err == nil {
			return
		}
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}

	shutdown := func() {
		once.Do(func() {
			if s.shutdownHook != nil {
				s.shutdownHook()
			}
			cancelRun()

			shutdownCtx, done := context.WithTimeout(context.Background(), shutdownTimeout)
			defer done()

			if s.starttls != nil && s.starttlsListener != nil {
				if err := s.starttls.Shutdown(shutdownCtx); err != nil {
					record(fmt.Errorf("starttls shutdown: %w", err))
				}
			}
			if s.implicit != nil && s.implicitListener != nil {
				if err := s.implicit.Shutdown(shutdownCtx); err != nil {
					record(fmt.Errorf("implicit shutdown: %w", err))
				}
			}
			// Ensure accept loops unblock even if Shutdown times out.
			if s.starttlsListener != nil {
				_ = s.starttlsListener.Close()
			}
			if s.implicitListener != nil {
				_ = s.implicitListener.Close()
			}
		})
	}

	serveOne := func(name string, fn func() error) {
		active.Add(1)
		wg.Go(func() {
			defer func() {
				if active.Add(-1) == 0 {
					shutdown()
				}
			}()
			if err := fn(); err != nil {
				record(fmt.Errorf("%s serve: %w", name, err))
			}
			// Unexpected exit of either listener shuts down the other.
			shutdown()
		})
	}

	if s.starttlsListener != nil {
		ln := s.starttlsListener
		srv := s.starttls
		serveOne("starttls", func() error {
			return srv.Serve(newLimitListener(ln, s.connLimit))
		})
	}
	if s.implicitListener != nil {
		ln := s.implicitListener
		srv := s.implicit
		serveOne("implicit", func() error {
			return srv.Serve(tls.NewListener(newLimitListener(ln, s.connLimit), srv.TLSConfig))
		})
	}

	// Parent cancellation. Exits when runCtx ends (parent cancel OR peer
	// failure via cancelRun), so it cannot leak after the server fails.
	wg.Go(func() {
		select {
		case <-ctx.Done():
			shutdown()
		case <-runCtx.Done():
		}
	})

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return errors.Join(errs...)
}

func (s *Server) session(c *smtp.Conn) (smtp.Session, error) {
	return &session{server: s, conn: c}, nil
}

// acquireHashSlot reserves a seat in the auth work queue then a worker slot.
// Returns errAuthBusy if the wait queue is full (never spawns unbounded waiters).
func (s *Server) acquireHashSlot(ctx context.Context) error {
	select {
	case s.authWait <- struct{}{}:
	default:
		return errAuthBusy
	}
	defer func() { <-s.authWait }()

	select {
	case s.hashing <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) releaseHashSlot() {
	<-s.hashing
}

// address normalizes an SMTP mailbox while preserving local-part case.
func address(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty address")
	}

	parsed, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}
	if parsed.Name != "" {
		return "", errors.New("address contains a display name")
	}
	// Reject if the client sent more than a bare addr-spec.
	if parsed.Address != value && value != "<"+parsed.Address+">" {
		return "", errors.New("address contains a display name")
	}
	return parsed.Address, nil
}

func addressDomain(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
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
