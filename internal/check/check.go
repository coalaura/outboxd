// Package check runs offline deployment readiness checks for outboxd.
//
// Checks never touch the public internet unless the injected Resolver does.
// Tests supply a fake Resolver; production uses net.Resolver.
package check

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/config"
)

// Level is the result severity of a single check.
type Level string

const (
	Pass Level = "PASS"
	Warn Level = "WARN"
	Fail Level = "FAIL"
)

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

func checkHostnameAddrs(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	host := strings.TrimSuffix(cfg.Server.Hostname, ".")
	name := "hostname_address"

	if cfg.DNS.PublicIPv4 == "" && cfg.DNS.PublicIPv6 == "" {
		return []Result{{Name: name, Level: Fail, Message: "no public_ipv4/public_ipv6 configured"}}
	}

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return []Result{{Name: name, Level: Fail, Message: fmt.Sprintf("A/AAAA lookup for %s: %v", host, err)}}
	}

	have4 := map[string]bool{}
	have6 := map[string]bool{}

	for _, a := range addrs {
		v4 := a.IP.To4()
		if v4 != nil {
			have4[v4.String()] = true
		} else {
			v6 := a.IP.To16()
			if v6 != nil {
				have6[a.IP.String()] = true
			}
		}
	}

	var rs []Result

	if cfg.DNS.PublicIPv4 != "" {
		if !have4[cfg.DNS.PublicIPv4] {
			rs = append(rs, Result{
				Name:    name + "_a",
				Level:   Fail,
				Message: fmt.Sprintf("%s A records do not include configured public_ipv4 %s (have %v)", host, cfg.DNS.PublicIPv4, keys(have4)),
			})
		} else {
			rs = append(rs, Result{
				Name:    name + "_a",
				Level:   Pass,
				Message: fmt.Sprintf("%s A includes %s", host, cfg.DNS.PublicIPv4),
			})
		}
	}

	if cfg.DNS.PublicIPv6 != "" {
		var found bool

		want := net.ParseIP(cfg.DNS.PublicIPv6)
		if want != nil {
			for ip := range have6 {
				if net.ParseIP(ip).Equal(want) {
					found = true

					break
				}
			}
		}

		if !found {
			rs = append(rs, Result{
				Name:    name + "_aaaa",
				Level:   Fail,
				Message: fmt.Sprintf("%s AAAA records do not include configured public_ipv6 %s", host, cfg.DNS.PublicIPv6),
			})
		} else {
			rs = append(rs, Result{
				Name:    name + "_aaaa",
				Level:   Pass,
				Message: fmt.Sprintf("%s AAAA includes %s", host, cfg.DNS.PublicIPv6),
			})
		}
	}

	return rs
}

func checkFCrDNS(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	host := strings.ToLower(strings.TrimSuffix(cfg.Server.Hostname, "."))

	var rs []Result

	checkIP := func(ip string, label string) {
		name := "fcrdns_" + label
		if ip == "" {
			return
		}

		names, err := r.LookupAddr(ctx, ip)
		if err != nil {
			rs = append(rs, Result{Name: name, Level: Fail, Message: fmt.Sprintf("PTR for %s: %v", ip, err)})
			return
		}

		var matched bool

		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			if n == host {
				matched = true

				break
			}
		}

		if !matched {
			rs = append(rs, Result{
				Name:    name,
				Level:   Fail,
				Message: fmt.Sprintf("PTR for %s is %v, want %s", ip, names, host),
			})

			return
		}

		// Confirm forward match again from PTR target.
		addrs, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			rs = append(rs, Result{
				Name:    name,
				Level:   Fail,
				Message: fmt.Sprintf("forward lookup after PTR: %v", err),
			})

			return
		}

		want := net.ParseIP(ip)

		var ok bool

		for _, a := range addrs {
			if a.IP.Equal(want) {
				ok = true

				break
			}
		}

		if !ok {
			rs = append(rs, Result{
				Name:    name,
				Level:   Fail,
				Message: fmt.Sprintf("FCrDNS broken: PTR is %s but A/AAAA does not include %s", host, ip),
			})

			return
		}

		rs = append(rs, Result{
			Name:    name,
			Level:   Pass,
			Message: fmt.Sprintf("FCrDNS ok for %s ↔ %s", ip, host),
		})
	}

	checkIP(cfg.DNS.PublicIPv4, "v4")
	checkIP(cfg.DNS.PublicIPv6, "v6")

	if len(rs) == 0 {
		rs = append(rs, Result{
			Name:    "fcrdns",
			Level:   Fail,
			Message: "no public IPs configured",
		})
	}

	return rs
}

func checkSPF(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	var rs []Result

	owners := requiredSPFOwners(cfg)

	for _, owner := range owners {
		name := "spf_" + strings.TrimSuffix(owner, ".")

		txts, err := r.LookupTXT(ctx, strings.TrimSuffix(owner, "."))
		if err != nil {
			rs = append(rs, Result{
				Name:    name,
				Level:   Fail,
				Message: fmt.Sprintf("TXT lookup %s: %v", owner, err),
			})

			continue
		}

		var spf []string

		for _, t := range txts {
			tt := strings.TrimSpace(t)

			fields := strings.Fields(tt)
			if len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1") {
				spf = append(spf, tt)
			}
		}

		switch len(spf) {
		case 0:
			rs = append(rs, Result{
				Name:    name,
				Level:   Fail,
				Message: fmt.Sprintf("no SPF TXT at %s", owner),
			})
		case 1:
			want := normalizeSPF(cfg.ExpectedSPF())
			if normalizeSPF(spf[0]) != want {
				rs = append(rs, Result{Name: name,
					Level:   Fail,
					Message: fmt.Sprintf("SPF at %s does not match configured policy: got %q, want %q", owner, spf[0], cfg.ExpectedSPF()),
				})
			} else {
				rs = append(rs, Result{Name: name,
					Level:   Pass,
					Message: fmt.Sprintf("SPF at %s matches configured policy", owner),
				})
			}
		default:
			rs = append(rs, Result{Name: name,
				Level:   Fail,
				Message: fmt.Sprintf("%d SPF TXT records at %s (must be exactly one)", len(spf), owner),
			})
		}
	}

	return rs
}

func requiredSPFOwners(cfg *config.Config) []string {
	domain := strings.ToLower(strings.TrimSuffix(cfg.Server.Domain, "."))
	hostname := strings.ToLower(strings.TrimSuffix(cfg.Server.Hostname, "."))

	set := map[string]struct{}{domain: {}}

	for i := range cfg.Users {
		for _, sender := range cfg.Users[i].AllowedSenders {
			sender = strings.TrimSpace(sender)
			if strings.HasPrefix(sender, "*@") {
				set[strings.ToLower(sender[2:])] = struct{}{}

				continue
			}

			at := strings.LastIndexByte(sender, '@')
			if at > 0 {
				set[strings.ToLower(sender[at+1:])] = struct{}{}
			}
		}
	}

	if hostname != domain {
		set[hostname] = struct{}{}
	}

	owners := make([]string, 0, len(set))

	for o := range set {
		if o != "" {
			owners = append(owners, o)
		}
	}

	sort.Strings(owners)

	return owners
}

func checkDKIM(ctx context.Context, r Resolver, cfg *config.Config, key *DKIMKey) []Result {
	selector := cfg.DKIM.Selector
	if key != nil && key.Selector != "" {
		selector = key.Selector
	}

	name := fmt.Sprintf("%s._domainkey.%s", selector, strings.TrimSuffix(cfg.Server.Domain, "."))
	checkName := "dkim"

	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("TXT lookup %s: %v", name, err),
		}}
	}

	var dkim []string

	for _, t := range txts {
		tt := strings.TrimSpace(collapseSpaces(t))
		if strings.HasPrefix(strings.ToLower(tt), "v=dkim1") {
			dkim = append(dkim, tt)
		}
	}

	if len(dkim) == 0 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("no DKIM TXT at %s", name),
		}}
	}

	if len(dkim) > 1 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("multiple DKIM TXT at %s", name),
		}}
	}

	if key == nil || key.PublicKey == "" {
		return []Result{{
			Name:    checkName,
			Level:   Warn,
			Message: fmt.Sprintf("DKIM TXT present at %s (local key not provided for comparison)", name),
		}}
	}

	pub, ok := dkimP(dkim[0])
	if !ok {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DKIM TXT at %s missing p=", name),
		}}
	}

	// Compare base64 payloads (ignore padding differences).
	if normalizeB64(pub) != normalizeB64(key.PublicKey) {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DKIM p= at %s does not match the loaded private key", name),
		}}
	}

	return []Result{{
		Name:    checkName,
		Level:   Pass,
		Message: fmt.Sprintf("DKIM selector %s matches loaded key", selector),
	}}
}

func checkDMARC(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	name := "_dmarc." + strings.TrimSuffix(cfg.Server.Domain, ".")
	checkName := "dmarc"

	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("TXT lookup %s: %v", name, err),
		}}
	}

	var found []string

	for _, t := range txts {
		tt := strings.TrimSpace(t)

		first, _, _ := strings.Cut(tt, ";")
		if strings.EqualFold(strings.TrimSpace(first), "v=DMARC1") {
			found = append(found, tt)
		}
	}

	if len(found) == 0 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("no DMARC TXT at %s", name),
		}}
	}

	if len(found) > 1 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("multiple DMARC TXT at %s", name),
		}}
	}

	tags, err := parseDMARCTags(found[0])
	if err != nil {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DMARC record invalid: %v", err),
		}}
	}

	p := strings.ToLower(tags["p"])

	switch p {
	case "none", "quarantine", "reject":
	case "":
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: "DMARC record missing p=",
		}}
	default:
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DMARC p=%q is not none/quarantine/reject", p),
		}}
	}

	want := strings.ToLower(cfg.DNS.DMARC)
	if want == "" {
		want = "none"
	}

	level := Pass
	msg := fmt.Sprintf("DMARC p=%s", p)

	if p != want {
		level = Fail
		msg = fmt.Sprintf("DMARC p=%s does not match config dmarc_policy=%s", p, want)
	} else if p == "none" {
		level = Warn
		msg = "DMARC p=none (monitor only); stage to quarantine/reject after verifying alignment"
	}

	rua := tags["rua"]
	if rua == "" {
		if level == Pass {
			level = Warn
		}

		msg += "; no rua= (no aggregate reports)"
	} else {
		err = config.ValidateDMARCReportURIList(rua)
		if err != nil {
			return []Result{{
				Name:    checkName,
				Level:   Fail,
				Message: fmt.Sprintf("DMARC rua invalid: %v", err),
			}}
		}
	}

	return []Result{{
		Name:    checkName,
		Level:   level,
		Message: msg,
	}}
}

func parseDMARCTags(record string) (map[string]string, error) {
	parts := strings.Split(record, ";")
	tags := make(map[string]string, len(parts))

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			if i == len(parts)-1 {
				continue
			}

			return nil, errors.New("empty tag")
		}

		key, value, ok := strings.Cut(part, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)

		if !ok || key == "" || value == "" || !asciiLetters(key) {
			return nil, fmt.Errorf("malformed tag %q", part)
		}

		_, duplicate := tags[key]
		if duplicate {
			return nil, fmt.Errorf("duplicate %s tag", key)
		}

		tags[key] = value
	}

	if !strings.EqualFold(tags["v"], "DMARC1") {
		return nil, errors.New("first tag must be exactly v=DMARC1")
	}

	return tags, nil
}

func asciiLetters(value string) bool {
	for _, char := range value {
		if char < 'a' || char > 'z' {
			return false
		}
	}

	return value != ""
}

func checkEnvelopeMX(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	var rs []Result

	domains := envelopeDomains(cfg)

	for _, d := range domains {
		name := "envelope_mx_" + d

		mxs, err := r.LookupMX(ctx, d)
		if err == nil && len(mxs) > 0 {
			var null int

			for _, mx := range mxs {
				if mx != nil && strings.TrimSpace(mx.Host) == "." {
					null++
				}
			}

			if null > 0 {
				message := fmt.Sprintf("%s publishes a null MX and does not accept bounces", d)
				if len(mxs) > 1 || null > 1 {
					message = fmt.Sprintf("%s publishes an invalid null MX mixed with other MX records", d)
				}

				rs = append(rs, Result{
					Name:    name,
					Level:   Fail,
					Message: message,
				})

				continue
			}

			rs = append(rs, Result{
				Name:    name,
				Level:   Pass,
				Message: fmt.Sprintf("%s has MX", d),
			})

			continue
		}

		// Implicit MX: A/AAAA on the domain apex (RFC 5321).
		addrs, aerr := r.LookupIPAddr(ctx, d)
		if aerr == nil && len(addrs) > 0 {
			rs = append(rs, Result{
				Name:    name,
				Level:   Warn,
				Message: fmt.Sprintf("%s has no MX; using A/AAAA implicit MX (ensure a mailbox accepts bounces)", d),
			})

			continue
		}

		msg := fmt.Sprintf("%s has no MX and no A/AAAA (bounces cannot be delivered)", d)
		if err != nil {
			msg = fmt.Sprintf("%s MX lookup failed (%v) and no A/AAAA", d, err)
		}

		rs = append(rs, Result{
			Name:    name,
			Level:   Fail,
			Message: msg,
		})
	}

	return rs
}

func envelopeDomains(cfg *config.Config) []string {
	set := map[string]struct{}{
		strings.ToLower(strings.TrimSuffix(cfg.Server.Domain, ".")): {},
	}

	for i := range cfg.Users {
		for _, sender := range cfg.Users[i].AllowedSenders {
			sender = strings.TrimSpace(sender)
			if strings.HasPrefix(sender, "*@") {
				set[strings.ToLower(strings.TrimSuffix(sender[2:], "."))] = struct{}{}

				continue
			}

			at := strings.LastIndexByte(sender, '@')
			if at > 0 {
				set[strings.ToLower(strings.TrimSuffix(sender[at+1:], "."))] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(set))

	for d := range set {
		if d != "" {
			out = append(out, d)
		}
	}

	sort.Strings(out)

	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))

	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func dkimP(record string) (string, bool) {
	tags := parseTags(record)

	p, ok := tags["p"]
	return p, ok
}

func parseTags(record string) map[string]string {
	out := make(map[string]string)

	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}

		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}

	return out
}

func normalizeB64(s string) string {
	s = collapseSpaces(s)

	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return s
		}
	}

	return base64.StdEncoding.EncodeToString(raw)
}

func normalizeSPF(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
