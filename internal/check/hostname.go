package check

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
)

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

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))

	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
