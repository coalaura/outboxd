package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/emersion/go-smtp"
)

type startListener struct {
	net.Listener
	once    sync.Once
	entered func()
}

// shutdownTimeout bounds graceful Shutdown during Run.
// Tests may lower this for deterministic timeout-path coverage.
var shutdownTimeout = 30 * time.Second

func (l *startListener) Accept() (net.Conn, error) {
	l.once.Do(l.entered)

	return l.Listener.Accept()
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

	addr := s.cfg.Server.SubmissionListenAddr()
	if addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", addr, err)
		}

		s.starttlsListener = ln

		opened = append(opened, ln)

		s.starttls.Addr = ln.Addr().String()
	}

	addr = s.cfg.Server.ImplicitTLSListenAddr()
	if addr != "" {
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

// CloseListeners closes listeners opened by Listen before Run starts.
func (s *Server) CloseListeners() {
	if s.starttlsListener != nil {
		_ = s.starttlsListener.Close()
		s.starttlsListener = nil
	}

	if s.implicitListener != nil {
		_ = s.implicitListener.Close()
		s.implicitListener = nil
	}
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
		active          atomic.Int32
		startup         sync.WaitGroup
	)

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
		err = ignoreClosed(err)
		if err == nil {
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

			// Stop both accept paths before either server begins draining sessions.
			if s.starttlsListener != nil {
				_ = s.starttlsListener.Close()
			}

			if s.implicitListener != nil {
				_ = s.implicitListener.Close()
			}

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
				err := s.starttls.Shutdown(shutdownCtx)
				if err != nil {
					record(fmt.Errorf("starttls shutdown: %w", err))
				}
			}

			if s.implicit != nil && s.implicitListener != nil {
				err := s.implicit.Shutdown(shutdownCtx)
				if err != nil {
					record(fmt.Errorf("implicit shutdown: %w", err))
				}
			}

			s.connections.closeAll()

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

			err := srv.Serve(&startListener{Listener: listener, entered: startup.Done})
			if err != nil {
				record(fmt.Errorf("%s serve: %w", name, err))
			}

			// Unexpected exit of either listener shuts down the other.
			shutdown()
		})
	}

	if s.starttlsListener != nil {
		tracked := newTrackListener(newLimitListener(s.starttlsListener, s.connLimit), s.connections)

		ln := newAuthDeadlineListener(tracked, s, config.Duration(s.cfg.Server.ReadTimeout))

		serveOne("starttls", ln, s.starttls)
	}

	if s.implicitListener != nil {
		tracked := newTrackListener(newLimitListener(s.implicitListener, s.connLimit), s.connections)

		bounded := newAuthDeadlineListener(tracked, s, config.Duration(s.cfg.Server.ReadTimeout))

		ln := tls.NewListener(bounded, s.implicit.TLSConfig)

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
