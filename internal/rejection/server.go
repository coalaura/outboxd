// Package rejection provides the optional rejection-only public SMTP endpoint.
package rejection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/emersion/go-smtp"
)

const maxMessageBytes = 1024

// Logger receives operational messages.
type Logger interface {
	Printf(format string, values ...any)
	Println(values ...any)
}

// Server rejects recipients for explicitly configured domains without accepting DATA.
type Server struct {
	cfg         config.ReplyRejection
	hostname    string
	log         Logger
	smtp        *smtp.Server
	listener    net.Listener
	limiter     *connectionLimiter
	connections *connectionTracker
	domains     map[string]struct{}
	recipients  map[string]string
}

type session struct {
	server *Server
}

type connectionLimiter struct {
	global int
	perIP  int

	mu     sync.Mutex
	active int
	byIP   map[string]int
}

type limitListener struct {
	net.Listener
	limiter  *connectionLimiter
	lifetime time.Duration
}

type limitedConn struct {
	net.Conn
	limiter *connectionLimiter
	ip      string
	once    sync.Once
}

type deadlineConn struct {
	net.Conn
	expires time.Time
}

type startListener struct {
	net.Listener
	once    sync.Once
	entered func()
}

type connectionTracker struct {
	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	closed bool
}

type trackListener struct {
	net.Listener
	tracker *connectionTracker
}

type trackedConn struct {
	net.Conn
	tracker *connectionTracker
	once    sync.Once
}

// New builds a disabled-until-Listen rejection endpoint.
func New(cfg *config.Config, log Logger) *Server {
	r := cfg.ReplyRejection

	s := &Server{
		cfg:         r,
		hostname:    cfg.Server.Hostname,
		log:         log,
		limiter:     newConnectionLimiter(r.MaxConnections, r.MaxConnectionsPerIP),
		connections: newConnectionTracker(),
		domains:     make(map[string]struct{}, len(r.Domains)),
		recipients:  make(map[string]string, len(r.Recipients)),
	}

	for _, domain := range r.Domains {
		s.domains[strings.ToLower(domain)] = struct{}{}
	}

	for _, recipient := range r.Recipients {
		message := recipient.Message
		if message == "" {
			message = r.DefaultMessage
		}

		s.recipients[strings.ToLower(recipient.Address)] = message
	}

	s.smtp = smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		return &session{server: s}, nil
	}))

	s.smtp.Domain = s.hostname
	s.smtp.MaxRecipients = 1
	s.smtp.MaxMessageBytes = maxMessageBytes
	s.smtp.ReadTimeout = config.Duration(r.ReadTimeout)
	s.smtp.WriteTimeout = config.Duration(r.WriteTimeout)
	s.smtp.ErrorLog = log

	return s
}

// Listen binds the configured public SMTP socket without starting its accept loop.
func (s *Server) Listen() error {
	if s.listener != nil {
		return errors.New("reply rejection listener is already open")
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen for reply rejection on %s: %w", s.cfg.ListenAddr, err)
	}

	s.listener = ln
	s.smtp.Addr = ln.Addr().String()

	s.log.Printf("Listening for reply rejection on %s\n", s.smtp.Addr)

	return nil
}

// CloseListener closes a listener opened before Run starts.
func (s *Server) CloseListener() {
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
}

// Run serves until ctx is cancelled or the listener fails.
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		return errors.New("reply rejection listener is not open")
	}

	serveDone := make(chan error, 1)
	started := make(chan struct{})

	lifetime := max(config.Duration(s.cfg.ReadTimeout), config.Duration(s.cfg.WriteTimeout))
	listener := &startListener{
		Listener: &trackListener{
			Listener: &limitListener{Listener: s.listener, limiter: s.limiter, lifetime: lifetime},
			tracker:  s.connections,
		},
		entered: func() {
			close(started)
		},
	}

	go func() {
		serveDone <- s.smtp.Serve(listener)
	}()

	<-started

	var (
		serveErr      error
		serveFinished bool
	)

	select {
	case <-ctx.Done():
	case serveErr = <-serveDone:
		serveFinished = true
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	shutdownErr := s.smtp.Shutdown(shutdownCtx)

	cancel()

	s.connections.closeAll()

	if !serveFinished {
		serveErr = <-serveDone
	}

	if errors.Is(serveErr, net.ErrClosed) || errors.Is(serveErr, smtp.ErrServerClosed) {
		serveErr = nil
	}

	if serveErr != nil {
		serveErr = fmt.Errorf("reply rejection serve: %w", serveErr)
	}

	if shutdownErr != nil && !errors.Is(shutdownErr, context.Canceled) {
		shutdownErr = fmt.Errorf("reply rejection shutdown: %w", shutdownErr)
	} else {
		shutdownErr = nil
	}

	return errors.Join(serveErr, shutdownErr)
}

func (l *startListener) Accept() (net.Conn, error) {
	l.once.Do(l.entered)

	return l.Listener.Accept()
}

func (s *session) Mail(string, *smtp.MailOptions) error {
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	address, err := mailbox.Address(to)
	if err != nil {
		return smtpError(550, smtp.EnhancedCode{5, 1, 3}, "Invalid recipient address")
	}

	domain, err := mailbox.DomainOf(address)
	if err != nil {
		return smtpError(550, smtp.EnhancedCode{5, 1, 3}, "Invalid recipient address")
	}

	if _, ok := s.server.domains[domain]; !ok {
		return smtpError(550, smtp.EnhancedCode{5, 7, 1}, "Relaying denied")
	}

	if message, ok := s.server.recipients[strings.ToLower(address)]; ok {
		return smtpError(550, smtp.EnhancedCode{5, 1, 1}, message)
	}

	if s.server.cfg.UnknownRecipients == "all" {
		return smtpError(550, smtp.EnhancedCode{5, 1, 1}, s.server.cfg.DefaultMessage)
	}

	return smtpError(550, smtp.EnhancedCode{5, 1, 1}, "Recipient does not exist")
}

func (*session) Data(r io.Reader) error {
	return smtpError(554, smtp.EnhancedCode{5, 5, 1}, "Message data is not accepted")
}

func (*session) Reset() {}

func (*session) Logout() error {
	return nil
}

func smtpError(code int, enhanced smtp.EnhancedCode, message string) error {
	return &smtp.SMTPError{Code: code, EnhancedCode: enhanced, Message: message}
}

func newConnectionLimiter(global, perIP int) *connectionLimiter {
	return &connectionLimiter{global: global, perIP: perIP, byIP: make(map[string]int)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		ip := connectionIP(conn.RemoteAddr())

		if l.limiter.acquire(ip) {
			bounded := &deadlineConn{Conn: conn, expires: time.Now().Add(l.lifetime)}

			_ = bounded.SetDeadline(bounded.expires)

			return &limitedConn{Conn: bounded, limiter: l.limiter, ip: ip}, nil
		}

		_ = conn.Close()
	}
}

func (c *deadlineConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(c.bounded(deadline))
}

func (c *deadlineConn) SetReadDeadline(deadline time.Time) error {
	return c.Conn.SetReadDeadline(c.bounded(deadline))
}

func (c *deadlineConn) SetWriteDeadline(deadline time.Time) error {
	return c.Conn.SetWriteDeadline(c.bounded(deadline))
}

func (c *deadlineConn) bounded(deadline time.Time) time.Time {
	if deadline.IsZero() || deadline.After(c.expires) {
		return c.expires
	}

	return deadline
}

func (c *limitedConn) Close() error {
	var err error

	c.once.Do(func() {
		c.limiter.release(c.ip)

		err = c.Conn.Close()
	})

	return err
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{conns: make(map[*trackedConn]struct{})}
}

func (l *trackListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tracked := &trackedConn{Conn: conn, tracker: l.tracker}

	if !l.tracker.add(tracked) {
		_ = tracked.Close()

		return nil, net.ErrClosed
	}

	return tracked, nil
}

func (c *trackedConn) Close() error {
	var err error

	c.once.Do(func() {
		c.tracker.remove(c)

		err = c.Conn.Close()
	})

	return err
}

func (t *connectionTracker) add(conn *trackedConn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return false
	}

	t.conns[conn] = struct{}{}

	return true
}

func (t *connectionTracker) remove(conn *trackedConn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
}

func (t *connectionTracker) closeAll() {
	t.mu.Lock()
	t.closed = true

	conns := make([]*trackedConn, 0, len(t.conns))

	for conn := range t.conns {
		conns = append(conns, conn)
	}

	t.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *connectionLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.active >= l.global || l.byIP[ip] >= l.perIP {
		return false
	}

	l.active++
	l.byIP[ip]++

	return true
}

func (l *connectionLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.active--
	l.byIP[ip]--

	if l.byIP[ip] == 0 {
		delete(l.byIP, ip)
	}
}

func connectionIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return host
}
