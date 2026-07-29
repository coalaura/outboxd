package smtpd

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/emersion/go-smtp"
)

var temporaryFailureErr = &smtp.SMTPError{
	Code:         451,
	EnhancedCode: smtp.EnhancedCode{4, 3, 0},
	Message:      "Temporary failure, try again later",
}

const (
	SubmissionPort  = ":587"
	ImplicitTLSPort = ":465"
)

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

	limiter *limiter

	// Bounds concurrent Argon2id derivations so authentication floods cannot
	// exhaust memory.
	hashing chan struct{}

	starttls *smtp.Server
	implicit *smtp.Server
}

// New builds the submission server.
func New(cfg *config.Config, keeper *certs.Keeper, signer *sign.Signer, spool *queue.Queue, log Logger) *Server {
	srv := &Server{
		cfg:     cfg,
		queue:   spool,
		signer:  signer,
		log:     log,
		limiter: newLimiter(),
		hashing: make(chan struct{}, 4),
	}

	srv.starttls = srv.listener(cfg, keeper)
	srv.implicit = srv.listener(cfg, keeper)

	srv.starttls.Addr = SubmissionPort
	srv.implicit.Addr = ImplicitTLSPort

	return srv
}

// Run serves both listeners until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	var (
		wg     sync.WaitGroup
		errs   [2]error
		closer sync.Once
	)

	stop := func() {
		closer.Do(func() {
			shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()

			s.starttls.Shutdown(shutdown)
			s.implicit.Shutdown(shutdown)
		})
	}

	s.log.Printf("Listening for submission on %s (STARTTLS) and %s (implicit TLS)\n", SubmissionPort, ImplicitTLSPort)

	wg.Go(func() {
		errs[0] = ignoreClosed(s.starttls.ListenAndServe())

		stop()
	})

	wg.Go(func() {
		errs[1] = ignoreClosed(s.implicit.ListenAndServeTLS())

		stop()
	})

	wg.Go(func() {
		<-ctx.Done()

		stop()
	})

	wg.Wait()

	return errors.Join(errs[0], errs[1])
}

func (s *Server) listener(cfg *config.Config, keeper *certs.Keeper) *smtp.Server {
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

func (s *Server) session(c *smtp.Conn) (smtp.Session, error) {
	return &session{
		server: s,
		conn:   c,
	}, nil
}

func address(value string) (string, error) {
	value = strings.TrimSpace(value)

	parsed, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}

	if parsed.Address != value {
		return "", errors.New("address contains a display name")
	}

	return strings.ToLower(parsed.Address), nil
}

func identifier() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strings.ToLower(rand.Text()[:10])
}

func remote(c *smtp.Conn) string {
	addr := c.Conn().RemoteAddr()
	if addr == nil {
		return "unknown"
	}

	return addr.String()
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
