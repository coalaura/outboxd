package smtpd

import (
	"net"
	"sync"
	"time"
)

type connectionKey struct {
	local  string
	remote string
}

type authDeadlineListener struct {
	net.Listener
	server   *Server
	lifetime time.Duration
}

type authDeadlineConn struct {
	net.Conn
	server *Server
	key    connectionKey

	mu       sync.Mutex
	deadline time.Time
	active   bool
	once     sync.Once
}

func newAuthDeadlineListener(listener net.Listener, server *Server, lifetime time.Duration) net.Listener {
	return &authDeadlineListener{Listener: listener, server: server, lifetime: lifetime}
}

func (l *authDeadlineListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	bounded := &authDeadlineConn{
		Conn:     conn,
		server:   l.server,
		key:      keyForConn(conn),
		deadline: time.Now().Add(l.lifetime),
		active:   true,
	}

	l.server.authConnections.Store(bounded.key, bounded)

	_ = bounded.SetDeadline(bounded.deadline)

	return bounded, nil
}

func keyForConn(conn net.Conn) connectionKey {
	key := connectionKey{}

	if conn.LocalAddr() != nil {
		key.local = conn.LocalAddr().String()
	}

	if conn.RemoteAddr() != nil {
		key.remote = conn.RemoteAddr().String()
	}

	return key
}

func (c *authDeadlineConn) clamp(deadline time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.active && (deadline.IsZero() || deadline.After(c.deadline)) {
		return c.deadline
	}

	return deadline
}

func (c *authDeadlineConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(c.clamp(deadline))
}

func (c *authDeadlineConn) SetReadDeadline(deadline time.Time) error {
	return c.Conn.SetReadDeadline(c.clamp(deadline))
}

func (c *authDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	return c.Conn.SetWriteDeadline(c.clamp(deadline))
}

func (c *authDeadlineConn) clear() {
	c.mu.Lock()
	c.active = false
	c.mu.Unlock()

	_ = c.Conn.SetDeadline(time.Time{})
}

func (c *authDeadlineConn) Close() error {
	var err error

	c.once.Do(func() {
		c.server.authConnections.Delete(c.key)
		err = c.Conn.Close()
	})

	return err
}

func (s *Server) authDeadline(conn net.Conn) *authDeadlineConn {
	bounded, _ := s.authConnections.Load(keyForConn(conn))

	deadline, _ := bounded.(*authDeadlineConn)

	return deadline
}
