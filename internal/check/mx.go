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
