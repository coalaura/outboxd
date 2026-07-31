package smtpd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/mailbox"
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

	errDataBusy = &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 3, 2},
		Message:      "Message processing busy; connection closing",
	}
)

const (
	DefaultSubmissionAddr  = ":587"
	DefaultImplicitTLSAddr = ":465"

	maxResponseLength = 256
	// Account conservatively for ReadAll capacity growth, newline normalization
	// up to twice the input size, prepared output, and the signed copy.
	dataMemoryBudget   = int64(512 << 20)
	dataMemoryCopies   = int64(8)
	dataMemoryOverhead = int64(1 << 20)
	maxDataWorkers     = 8
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
		cfg:       cfg,
		queue:     spool,
		signer:    signer,
		log:       log,
		connLimit: newConnectionLimiter(cfg.Server.MaxConnections, cfg.Server.MaxConnectionsPerIP),
		authLimit: newAuthLimiter(),
		rates:     newSubmissionLimiter(cfg.Server.MaxMessagesPerHour, cfg.Server.MaxRecipientsPerHour, msgBurst, rcptBurst),
		hashing:   make(chan struct{}, authWorkers),
		dataWork:  make(chan struct{}, dataWorkers),
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
	workers := int(dataMemoryBudget / perWorker)
	if workers < 1 {
		return 1
	}
	return min(workers, maxDataWorkers)
}

func dataWorkerMemory(maxMessageBytes int64) (int64, bool) {
	if maxMessageBytes <= 0 || maxMessageBytes > (math.MaxInt64-dataMemoryOverhead)/dataMemoryCopies {
		return 0, false
	}
	return maxMessageBytes*dataMemoryCopies + dataMemoryOverhead, true
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
	server.MaxMessageBytes = incrementLimit(cfg.Server.MaxMessageBytes)
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

	var (
		mu              sync.Mutex
		errs            []error
		wg              sync.WaitGroup
		once            sync.Once
		shutdownStarted = make(chan struct{})
	)
	active := atomic.Int32{}
	var startup sync.WaitGroup
	started := make(chan struct{})
	listenerCount := 0
	if s.starttlsListener != nil {
		listenerCount++
	}
	if s.implicitListener != nil {
		listenerCount++
	}
	startup.Add(listenerCount)
	go func() {
		startup.Wait()
		close(started)
		if s.serveEntered != nil {
			s.serveEntered()
		}
	}()

	record := func(err error) {
		if err = ignoreClosed(err); err == nil {
			return
		}
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}

	shutdown := func() {
		// Serve registers its listener before calling Accept. Waiting for every
		// wrapped listener to enter Accept prevents Shutdown from missing one.
		<-started
		once.Do(func() {
			close(shutdownStarted)
			if s.shutdownHook != nil {
				s.shutdownHook()
			}

			var (
				shutdownCtx context.Context
				done        context.CancelFunc
			)
			if s.shutdownContext != nil {
				shutdownCtx, done = s.shutdownContext(context.Background())
			} else {
				shutdownCtx, done = context.WithTimeout(context.Background(), shutdownTimeout)
			}
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

	serveOne := func(name string, listener net.Listener, srv *smtp.Server) {
		active.Add(1)
		wg.Go(func() {
			defer func() {
				if active.Add(-1) == 0 {
					shutdown()
				}
			}()
			if err := srv.Serve(&startListener{Listener: listener, entered: startup.Done}); err != nil {
				record(fmt.Errorf("%s serve: %w", name, err))
			}
			// Unexpected exit of either listener shuts down the other.
			shutdown()
		})
	}

	if s.starttlsListener != nil {
		serveOne("starttls", newLimitListener(s.starttlsListener, s.connLimit), s.starttls)
	}
	if s.implicitListener != nil {
		ln := tls.NewListener(newLimitListener(s.implicitListener, s.connLimit), s.implicit.TLSConfig)
		serveOne("implicit", ln, s.implicit)
	}

	// Parent cancellation initiates shutdown. An unexpected Serve exit closes
	// shutdownStarted so this waiter cannot leak after the server fails.
	wg.Go(func() {
		select {
		case <-ctx.Done():
			shutdown()
		case <-shutdownStarted:
		}
	})

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return errors.Join(errs...)
}

type startListener struct {
	net.Listener
	once    sync.Once
	entered func()
}

func (l *startListener) Accept() (net.Conn, error) {
	l.once.Do(l.entered)
	return l.Listener.Accept()
}

func (s *Server) session(c *smtp.Conn) (smtp.Session, error) {
	return &session{server: s, conn: c}, nil
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
