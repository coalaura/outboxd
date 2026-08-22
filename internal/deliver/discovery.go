package deliver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
)

var restrictedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func (d *Deliverer) lookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	network := d.lookupNetwork()

	lookupCtx, cancel := context.WithTimeout(ctx, d.dnsTO)

	addrs, err := d.resolver.LookupNetIP(lookupCtx, network, host)

	cancel()
	if err != nil {
		return nil, err
	}

	unique := make(map[netip.Addr]struct{}, len(addrs))
	ordered := make([]netip.Addr, 0, len(addrs))

	var disallowed error

	for _, ip := range addrs {
		err = d.checkDestination(ip)
		if err != nil {
			disallowed = err

			continue
		}

		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}

		addr = addr.Unmap()

		if _, exists := unique[addr]; exists {
			continue
		}

		unique[addr] = struct{}{}
		ordered = append(ordered, addr)
	}

	if len(ordered) == 0 && disallowed != nil {
		return nil, disallowed
	}

	slices.SortFunc(ordered, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	addrs = make([]net.IP, len(ordered))

	for i, addr := range ordered {
		addrs[i] = net.IP(addr.AsSlice())
	}

	if d.orderIPs != nil {
		d.orderIPs(addrs)
	}

	if len(addrs) > d.maxIP {
		addrs = addrs[:d.maxIP]
	}

	return addrs, nil
}

func (d *Deliverer) lookupNetwork() string {
	has4 := d.cfg.Delivery.BindIPv4 != "" || d.cfg.Delivery.BindIPv6 == ""
	has6 := d.cfg.Delivery.BindIPv6 != ""

	switch {
	case has4 && has6:
		return "ip"
	case has6 && !has4:
		return "ip6"
	default:
		return "ip4"
	}
}

func (d *Deliverer) checkDestination(ip net.IP) error {
	if d.cfg.Delivery.AllowPrivateDestinations {
		return nil
	}

	if d.allowlisted(ip) {
		return nil
	}

	if isRestricted(ip) {
		return fmt.Errorf("%w: %s", errPrivateDestination, ip)
	}

	return nil
}

func (d *Deliverer) allowlisted(ip net.IP) bool {
	_, ok := d.allowlist[ip.String()]
	if ok {
		return true
	}

	// Also match canonical IPv4 forms.
	ip4 := ip.To4()
	if ip4 != nil {
		_, ok := d.allowlist[ip4.String()]
		if ok {
			return true
		}
	}

	return false
}

func (d *Deliverer) hosts(ctx context.Context, domain string) ([]mxCandidate, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, d.dnsTO)

	records, err := d.resolver.LookupMX(lookupCtx, domain)

	cancel()

	var mxNotFound bool

	if err != nil {
		dnsErr, ok := errors.AsType[*net.DNSError](err)
		if !ok || !dnsErr.IsNotFound {
			return nil, err
		}

		mxNotFound = true
		records = nil
	}

	if len(records) == 0 {
		ips, lookupErr := d.lookupHostIPs(ctx, domain)
		if lookupErr != nil {
			dnsErr, ok := errors.AsType[*net.DNSError](lookupErr)
			if mxNotFound && ok && dnsErr.IsNotFound {
				return nil, errNoSuchDomain
			}

			return nil, lookupErr
		}

		return []mxCandidate{{host: domain, ips: ips}}, nil
	}

	valid := make([]*net.MX, 0, len(records))

	for _, record := range records {
		if record != nil {
			if record.Host == "." {
				return nil, errNullMX
			}

			valid = append(valid, record)
		}
	}

	// Establish deterministic groups, then rotate only within equal preference.
	// Processing groups in order keeps the lowest-preference occurrence of a
	// duplicate host before the candidate cap is applied.
	slices.SortFunc(valid, func(a, b *net.MX) int {
		if a.Pref != b.Pref {
			return int(a.Pref) - int(b.Pref)
		}

		return strings.Compare(strings.ToLower(a.Host), strings.ToLower(b.Host))
	})

	if d.orderMX != nil {
		for start := 0; start < len(valid); {
			end := start + 1

			for end < len(valid) && valid[end].Pref == valid[start].Pref {
				end++
			}

			d.orderMX(valid[start:end])
			start = end
		}
	}

	hosts := make([]mxCandidate, 0, min(len(valid), d.maxMX))
	seen := make(map[string]struct{}, len(valid))

	for _, record := range valid {
		host := strings.ToLower(strings.TrimSuffix(record.Host, "."))
		if host != "" && host != "." {
			if _, exists := seen[host]; exists {
				continue
			}

			seen[host] = struct{}{}
			hosts = append(hosts, mxCandidate{host: host})

			if len(hosts) == d.maxMX {
				break
			}
		}
	}

	if len(hosts) == 0 {
		return nil, errNullMX
	}

	return hosts, nil
}

// shuffleIPs is the production candidate-IP ordering: light shuffle for multi-A.
func shuffleIPs(addrs []net.IP) {
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
}

func shuffleMX(records []*net.MX) {
	rand.Shuffle(len(records), func(i, j int) {
		records[i], records[j] = records[j], records[i]
	})
}

func isRestricted(ip net.IP) bool {
	if ip == nil {
		return true
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}

	addr = addr.Unmap()

	for _, prefix := range restrictedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
