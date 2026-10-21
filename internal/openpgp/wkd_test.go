package openpgp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type wkdLookupCase struct {
	name          string
	advancedError error
	ips           []net.IP
	status        int
	body          []byte
	untrusted     bool
	wantError     string
	wantQueries   int
}

type wkdKeyCase struct {
	name      string
	data      []byte
	recipient string
	wantError bool
}

func TestWKDLookupPolicy(t *testing.T) {
	_, keyData := newWKDTestKey(t, "Bob+tag@example.com", nil)

	missing := &net.DNSError{Err: "no such host", IsNotFound: true}
	temporary := &net.DNSError{Err: "temporary", IsTemporary: true}

	publicIPs := []net.IP{net.ParseIP("8.8.8.8")}
	mixedIPs := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}

	tests := []wkdLookupCase{
		{name: "advanced", status: http.StatusOK, body: keyData, wantQueries: 1},
		{name: "direct", advancedError: missing, status: http.StatusOK, body: keyData, wantQueries: 2},
		{name: "temporary DNS failure", advancedError: temporary, wantError: "advanced WKD", wantQueries: 1},
		{name: "private address", ips: mixedIPs, wantError: "restricted", wantQueries: 1},
		{name: "redirect", status: http.StatusFound, wantError: "HTTP 302", wantQueries: 1},
		{name: "absent key", status: http.StatusNotFound, wantError: "HTTP 404", wantQueries: 1},
		{name: "oversized key", status: http.StatusOK, body: bytes.Repeat([]byte("x"), wkdMaxKeyBytes+1), wantError: "size limit", wantQueries: 1},
		{name: "untrusted TLS", untrusted: true, status: http.StatusOK, body: keyData, wantError: "certificate", wantQueries: 1},
	}

	// A configured proxy must not become an alternate, unchecked dial target.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan *http.Request, 2)

			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests <- request

				writer.Header().Set("Location", "https://example.com/redirected")
				writer.WriteHeader(test.status)

				_, _ = writer.Write(test.body)
			}))

			defer server.Close()

			client := newWKDTestClient(server)

			queries := make([]string, 0, 2)

			dials := 0
			dial := client.dial

			client.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
				queries = append(queries, host)

				if strings.HasPrefix(host, "openpgpkey.") && test.advancedError != nil {
					return nil, test.advancedError
				}

				if test.ips != nil {
					return test.ips, nil
				}

				return publicIPs, nil
			}

			client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials++

				if address != "8.8.8.8:443" {
					return nil, errors.New("unvalidated dial target: " + address)
				}

				return dial(ctx, network, address)
			}

			if test.untrusted {
				client.tlsConfig.RootCAs = x509.NewCertPool()
			}

			result, err := client.lookup(context.Background(), "Bob+tag@example.com")

			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("lookup() error = %v, want %q", err, test.wantError)
				}
			} else if err != nil || !bytes.Equal(result, keyData) {
				t.Fatalf("lookup() = %d bytes, %v", len(result), err)
			}

			if len(queries) != test.wantQueries || queries[0] != "openpgpkey.example.com." {
				t.Fatalf("DNS queries = %v", queries)
			}

			if test.wantQueries == 2 && queries[1] != "example.com." {
				t.Fatalf("direct DNS query = %q", queries[1])
			}

			if test.ips != nil || errors.Is(test.advancedError, temporary) {
				if dials != 0 {
					t.Fatalf("blocked lookup made %d connections", dials)
				}

				return
			}

			if test.untrusted {
				return
			}

			if len(requests) != 1 {
				t.Fatalf("request count = %d, want 1", len(requests))
			}

			request := <-requests

			wantHost := "openpgpkey.example.com"
			wantPath := "/.well-known/openpgpkey/example.com/hu/"

			if test.wantQueries == 2 {
				wantHost = "example.com"
				wantPath = "/.well-known/openpgpkey/hu/"
			}

			wantPath += wkdHash("bob+tag")
			if request.Host != wantHost || request.URL.Path != wantPath || request.URL.RawQuery != "l=Bob%2Btag" {
				t.Fatalf("unexpected WKD request: host=%s URL=%s", request.Host, request.URL)
			}
		})
	}
}

func TestWKDLookupCancellationAndAddressBudget(t *testing.T) {
	client := newWKDClient()

	client.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		ips := make([]net.IP, wkdMaxIPs+10)

		for index := range ips {
			ips[index] = net.ParseIP("8.8.8.8")
		}

		return ips, nil
	}

	attempts := 0

	client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts++

		return nil, errors.New("connection failed")
	}

	_, err := client.lookup(context.Background(), "bob@example.com")
	if err == nil || attempts != wkdMaxIPs {
		t.Fatalf("lookup() = %v, dial attempts = %d", err, attempts)
	}

	client.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		<-ctx.Done()

		return nil, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = client.lookup(ctx, "bob@example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled lookup() = %v", err)
	}
}

func TestWKDLookupBoundsStreamingResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()

		_, _ = io.CopyN(writer, strings.NewReader(strings.Repeat("x", wkdMaxKeyBytes+1)), wkdMaxKeyBytes+1)
	}))

	defer server.Close()

	client := newWKDTestClient(server)

	_, err := client.lookup(context.Background(), "bob@example.com")
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("streaming lookup() = %v", err)
	}
}

func TestParseWKDRecipient(t *testing.T) {
	entity, public := newWKDTestKey(t, "bob@example.com", nil)
	_, other := newWKDTestKey(t, "other@example.com", nil)
	_, version6 := newWKDTestKey(t, "bob@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEd25519, V6Keys: true})

	_, expired := newWKDTestKey(t, "bob@example.com", &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		KeyLifetimeSecs: 1,
		Time: func() time.Time {
			return time.Now().Add(-time.Hour)
		},
	})

	var private bytes.Buffer

	err := entity.SerializePrivate(&private, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []wkdKeyCase{
		{name: "valid", data: public, recipient: "bob@example.com"},
		{name: "version 6", data: version6, recipient: "bob@example.com"},
		{name: "different local case", data: public, recipient: "Bob@example.com", wantError: true},
		{name: "wrong mailbox", data: other, recipient: "bob@example.com", wantError: true},
		{name: "private key", data: private.Bytes(), recipient: "bob@example.com", wantError: true},
		{name: "hidden private key", data: bytes.Join([][]byte{public, private.Bytes()}, nil), recipient: "bob@example.com", wantError: true},
		{name: "multiple entities", data: bytes.Join([][]byte{public, other}, nil), recipient: "bob@example.com", wantError: true},
		{name: "trailing garbage", data: bytes.Join([][]byte{public, []byte("garbage")}, nil), recipient: "bob@example.com", wantError: true},
		{name: "truncated packet header", data: bytes.Join([][]byte{public, {0xc6}}, nil), recipient: "bob@example.com", wantError: true},
		{name: "expired", data: expired, recipient: "bob@example.com", wantError: true},
		{name: "empty", recipient: "bob@example.com", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseWKDRecipient(test.data, test.recipient)
			if (err != nil) != test.wantError {
				t.Fatalf("parseWKDRecipient() = %v", err)
			}
		})
	}
}

func TestWKDRejectsPacketResourceAbuse(t *testing.T) {
	_, public := newWKDTestKey(t, "bob@example.com", nil)

	tests := []string{"forged hashed length", "forged unhashed length", "nested signatures", "packet count"}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			var response bytes.Buffer

			response.Write(public)
			contents := []byte{6, 0x13, 1, 8, 0xff, 0xff, 0xff, 0xff}

			switch name {
			case "forged unhashed length":
				contents = []byte{6, 0x13, 1, 8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
			case "nested signatures":
				contents = []byte{4, 0x13, 1, 8, 0, 0, 0, 0}

				for range 2 {
					length := byte(len(contents))
					header := []byte{4, 0x13, 1, 8, 0, length + 2, length + 1, wkdEmbeddedSignature}

					contents = bytes.Join([][]byte{header, contents, {0, 0}}, nil)
				}
			case "packet count":
				for range wkdMaxPackets {
					value := packet.OpaquePacket{Tag: wkdUserIDPacket, Contents: []byte("extra@example.com")}

					err := value.Serialize(&response)
					if err != nil {
						t.Fatal(err)
					}
				}
			}

			value := packet.OpaquePacket{Tag: wkdSignaturePacket, Contents: contents}

			err := value.Serialize(&response)
			if err != nil {
				t.Fatal(err)
			}

			_, err = parseWKDRecipient(response.Bytes(), "bob@example.com")
			if err == nil {
				t.Fatal("unbounded packet accepted")
			}
		})
	}
}

func newWKDTestClient(server *httptest.Server) *wkdClient {
	client := newWKDClient()

	client.lookupIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}

	client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{}

		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}

	client.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: "example.com",
	}

	return client
}

func newWKDTestKey(t *testing.T, recipient string, cfg *packet.Config) (*pgp.Entity, []byte) {
	t.Helper()

	if cfg == nil {
		cfg = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	}

	entity, err := pgp.NewEntity("Recipient", "", recipient, cfg)
	if err != nil {
		t.Fatal(err)
	}

	var public bytes.Buffer

	err = entity.Serialize(&public)
	if err != nil {
		t.Fatal(err)
	}

	return entity, public.Bytes()
}
