package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
)

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

func normalizeSPF(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
