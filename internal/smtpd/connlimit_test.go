package smtpd

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type oneConnListener struct {
	conn net.Conn
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, net.ErrClosed
	}

	conn := l.conn
	l.conn = nil

	return conn, nil
}

func (*oneConnListener) Close() error {
	return nil
}

func (*oneConnListener) Addr() net.Addr {
	return testAddr("listener")
}

type testAddr string

func (a testAddr) Network() string {
	return string(a)
}

func (a testAddr) String() string {
	return string(a)
}

func TestTrackListenerRejectsAcceptBetweenAcceptAndTrack(t *testing.T) {
	accepted, peer := net.Pipe()
	defer peer.Close()

	tracker := newConnectionTracker()

	between := make(chan struct{})
	resume := make(chan struct{})

	listener := &trackListener{
		Listener: &oneConnListener{conn: accepted},
		tracker:  tracker,
		beforeTrack: func() {
			close(between)
			<-resume
		},
	}

	type acceptResult struct {
		conn net.Conn
		err  error
	}

	result := make(chan acceptResult, 1)

	go func() {
		conn, err := listener.Accept()
		result <- acceptResult{conn: conn, err: err}
	}()

	<-between

	tracker.closeAll()

	close(resume)

	got := <-result
	if got.conn != nil || !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("Accept() = (%v, %v), want (nil, net.ErrClosed)", got.conn, got.err)
	}

	assertPeerClosed(t, peer)

	tracker.closeAll()
}

func TestConnectionTrackerCloseAllRace(t *testing.T) {
	const attempts = 500

	for i := range attempts {
		accepted, peer := net.Pipe()

		tracker := newConnectionTracker()

		listener := newTrackListener(&oneConnListener{conn: accepted}, tracker)

		start := make(chan struct{})

		var (
			conn net.Conn
			err  error
			wg   sync.WaitGroup
		)

		wg.Add(2)

		go func() {
			defer wg.Done()

			<-start

			conn, err = listener.Accept()
		}()

		go func() {
			defer wg.Done()

			<-start

			tracker.closeAll()
		}()

		close(start)

		wg.Wait()

		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("attempt %d: Accept error = %v", i, err)
		}

		if err != nil && conn != nil {
			t.Fatalf("attempt %d: rejected Accept returned connection", i)
		}

		if conn != nil {
			_ = conn.Close()
			_ = conn.Close()
		}

		assertPeerClosed(t, peer)

		_ = peer.Close()

		tracker.closeAll()
	}
}

func assertPeerClosed(t *testing.T, conn net.Conn) {
	t.Helper()

	err := conn.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		return
	}

	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("peer remained usable after tracker shutdown")
	}
}
