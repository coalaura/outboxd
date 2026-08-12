// Package check runs offline deployment readiness checks for outboxd.
//
// Checks never touch the public internet unless the injected Resolver does.
// Tests supply a fake Resolver; production uses net.Resolver.
package check

import (
	"context"
	"net"
	"time"

	"github.com/coalaura/outboxd/internal/config"
)

const (
	Pass Level = "PASS"
	Warn Level = "WARN"
	Fail Level = "FAIL"
)

// Level is the result severity of a single check.
type Level string

// Result is one named check outcome.
type Result struct {
	Name    string
	Level   Level
	Message string
}

// Resolver is the DNS seam used by checks. Tests inject fakes; production
// uses DefaultResolver.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// DKIMKey is the local DKIM public key material used to verify the published record.
type DKIMKey struct {
	// Selector is the DNS selector label.
	Selector string

	// PublicKey is base64 SubjectPublicKeyInfo (same form as sign.Signer.PublicKey).
	PublicKey string
}

// Options configures a Check run.
type Options struct {
	Config *config.Config

	// Resolver defaults to DefaultResolver when nil.
	Resolver Resolver

	// DKIM is optional; when set, the selector TXT is compared to the key.
	DKIM *DKIMKey

	// Now overrides time for expiry-adjacent checks (unused now; reserved).
	Now func() time.Time
}

// DefaultResolver uses the process-wide resolver.
type DefaultResolver struct{}

func (DefaultResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func (DefaultResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (DefaultResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (DefaultResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, name)
}

// Run executes deployment checks and returns every result.
func Run(ctx context.Context, opts Options) []Result {
	if opts.Resolver == nil {
		opts.Resolver = DefaultResolver{}
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	cfg := opts.Config

	r := opts.Resolver

	var out []Result

	out = append(out, checkHostnameAddrs(ctx, r, cfg)...)
	out = append(out, checkFCrDNS(ctx, r, cfg)...)
	out = append(out, checkSPF(ctx, r, cfg)...)
	out = append(out, checkDKIM(ctx, r, cfg, opts.DKIM)...)
	out = append(out, checkDMARC(ctx, r, cfg)...)
	out = append(out, checkEnvelopeMX(ctx, r, cfg)...)

	return out
}

// Failed reports whether any result is FAIL.
func Failed(results []Result) bool {
	for _, r := range results {
		if r.Level == Fail {
			return true
		}
	}

	return false
}
