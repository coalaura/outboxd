package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
)

func checkEnvelopeMX(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	var rs []Result

	domains := envelopeDomains(cfg)

	for _, d := range domains {
		name := "envelope_mx_" + d

		mxs, err := r.LookupMX(ctx, d)
		if err == nil && len(mxs) > 0 {
			var (
				null             int
				hasRejectionHost bool
			)

			for _, mx := range mxs {
				if mx != nil && strings.TrimSpace(mx.Host) == "." {
					null++
				}

				if mx != nil && strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(mx.Host), "."), strings.TrimSuffix(cfg.Server.Hostname, ".")) {
					hasRejectionHost = true
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

			if rejectionDomain(cfg, d) && (!hasRejectionHost || len(mxs) != 1) {
				rs = append(rs, Result{
					Name:    name,
					Level:   Fail,
					Message: fmt.Sprintf("%s MX must route exclusively to rejection host %s", d, cfg.Server.Hostname),
				})

				continue
			}

			rs = append(rs, Result{
				Name:    name,
				Level:   Pass,
				Message: mxSuccessMessage(cfg, d),
			})

			continue
		}

		if rejectionDomain(cfg, d) {
			rs = append(rs, Result{
				Name:    name,
				Level:   Fail,
				Message: fmt.Sprintf("%s must publish one explicit MX routing exclusively to rejection host %s", d, cfg.Server.Hostname),
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

	if cfg.ReplyRejection.Enabled {
		for _, domain := range cfg.ReplyRejection.Domains {
			set[strings.ToLower(strings.TrimSuffix(domain, "."))] = struct{}{}
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

func rejectionDomain(cfg *config.Config, domain string) bool {
	if !cfg.ReplyRejection.Enabled {
		return false
	}

	for _, configured := range cfg.ReplyRejection.Domains {
		if strings.EqualFold(strings.TrimSuffix(configured, "."), strings.TrimSuffix(domain, ".")) {
			return true
		}
	}

	return false
}

func mxSuccessMessage(cfg *config.Config, domain string) string {
	if rejectionDomain(cfg, domain) {
		return fmt.Sprintf("%s routes attempted replies to rejection host %s", domain, cfg.Server.Hostname)
	}

	return fmt.Sprintf("%s has MX", domain)
}
