package smtpd

import (
	"net"
	"sync"
)

// connectionLimiter enforces global and per-IP concurrent connection caps.
type connectionLimiter struct {
	global int
	perIP  int

	mu      sync.Mutex
	active  int
	byIP    map[string]int
	waiting int
}

func newConnectionLimiter(global, perIP int) *connectionLimiter {
	if global <= 0 {
		global = 256
	}
	if perIP <= 0 {
		perIP = 16
	}
	return &connectionLimiter{
		global: global,
		perIP:  perIP,
		byIP:   make(map[string]int),
	}
}

func (l *connectionLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.active >= l.global {
		return false
	}
	if l.byIP[ip] >= l.perIP {
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
	if l.active < 0 {
		l.active = 0
	}
	n := l.byIP[ip] - 1
	if n <= 0 {
		delete(l.byIP, ip)
	} else {
		l.byIP[ip] = n
	}
}

// limitListener rejects accepts that would exceed connection caps.
type limitListener struct {
	net.Listener
	limiter *connectionLimiter
}

func newLimitListener(ln net.Listener, limiter *connectionLimiter) net.Listener {
	if limiter == nil {
		return ln
	}
	return &limitListener{Listener: ln, limiter: limiter}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := connIP(c.RemoteAddr())
		if l.limiter.acquire(ip) {
			return &limitedConn{Conn: c, ip: ip, limiter: l.limiter}, nil
		}
		// Close with a short 421 if possible is handled at SMTP layer for
		// established sessions; for hard over-limit we drop the TCP connection.
		_ = c.Close()
	}
}

type limitedConn struct {
	net.Conn
	ip      string
	limiter *connectionLimiter
	once    sync.Once
}

func (c *limitedConn) Close() error {
	var err error
	c.once.Do(func() {
		c.limiter.release(c.ip)
		err = c.Conn.Close()
	})
	return err
}

func connIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
