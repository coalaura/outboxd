package check

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
)

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
