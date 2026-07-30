// Package mailbox provides shared SMTP mailbox and routing-domain helpers.
package mailbox

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Lookup-oriented IDNA profile for DNS routing (A-labels).
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
)

var (
	ErrEmptyDomain   = errors.New("empty domain")
	ErrInvalidUTF8   = errors.New("invalid utf-8 domain")
	ErrInvalidDomain = errors.New("invalid domain")
	ErrDomainLabel   = errors.New("invalid DNS label")
	ErrDomainLength  = errors.New("domain too long")
)

// DomainOf extracts the domain after the final '@' and returns its ASCII
// routing A-label (lowercased). The local part is not inspected beyond the split.
func DomainOf(addr string) (string, error) {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return "", ErrEmptyDomain
	}
	return RoutingDomain(addr[at+1:])
}

// RoutingDomain converts a mailbox domain to a lowercased ASCII A-label suitable
// for MX/A lookup and concurrency keys. Unicode U-labels are not returned.
func RoutingDomain(domain string) (string, error) {
	if domain == "" {
		return "", ErrEmptyDomain
	}
	if !utf8.ValidString(domain) {
		return "", ErrInvalidUTF8
	}
	// Reject empty labels before IDNA (including trailing dots).
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", ErrDomainLabel
	}

	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDomain, err)
	}
	ascii = strings.ToLower(strings.TrimSpace(ascii))
	if ascii == "" {
		return "", ErrEmptyDomain
	}
	if len(ascii) > 253 {
		return "", ErrDomainLength
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		// Delivery still requires a multi-label FQDN for ordinary recipients.
		return "", ErrDomainLabel
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", ErrDomainLabel
		}
	}
	return ascii, nil
}
