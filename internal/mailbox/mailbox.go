// Package mailbox provides shared SMTP mailbox and routing-domain helpers.
package mailbox

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var (

	// Strict lookup-oriented IDNA profile for SMTP recipient-domain DNS routing.
	// Options match the pinned golang.org/x/net/idna API for lookup validation plus
	// DNS length and Bidi checks required for safe A-label conversion.
	idnaProfile = idna.New(
		idna.MapForLookup(),
		idna.StrictDomainName(true),
		idna.ValidateLabels(true),
		idna.VerifyDNSLength(true),
		idna.BidiRule(),
	)

	ErrEmptyDomain   = errors.New("empty domain")
	ErrInvalidUTF8   = errors.New("invalid utf-8 domain")
	ErrInvalidDomain = errors.New("invalid domain")
	ErrDomainLabel   = errors.New("invalid DNS label")
	ErrDomainLength  = errors.New("domain too long")
	ErrLocalLength   = errors.New("local part too long")
	ErrMailboxLength = errors.New("mailbox too long")
)

const (
	maxLocalOctets   = 64
	maxMailboxOctets = 254
)

// Address parses a bare SMTP mailbox, preserving local-part case, and enforces
// RFC mailbox limits in octets. Angle brackets are accepted; display names are not.
func Address(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty address")
	}

	parsed, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}

	if parsed.Name != "" || (parsed.Address != value && value != "<"+parsed.Address+">") {
		return "", errors.New("address contains a display name")
	}

	err = ValidateAddress(parsed.Address)
	if err != nil {
		return "", err
	}

	return parsed.Address, nil
}

// CanonicalAddress parses a bare SMTP mailbox and converts its domain to the
// ASCII routing form while preserving the local part exactly.
func CanonicalAddress(value string) (string, error) {
	address, err := Address(value)
	if err != nil {
		return "", err
	}

	domain, err := DomainOf(address)
	if err != nil {
		return "", err
	}

	at := strings.LastIndexByte(address, '@')
	return address[:at+1] + domain, nil
}

// ValidateAddress enforces SMTP mailbox and DNS-representation octet limits.
// It intentionally accepts single-label and address-literal domains; routing
// callers can apply RoutingDomain's stricter DNS requirements afterwards.
func ValidateAddress(addr string) error {
	if !utf8.ValidString(addr) {
		return ErrInvalidUTF8
	}

	if len(addr) > maxMailboxOctets {
		return ErrMailboxLength
	}

	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return ErrEmptyDomain
	}

	if at > maxLocalOctets {
		return ErrLocalLength
	}

	domain := addr[at+1:]
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		if len(domain) > 255 {
			return ErrDomainLength
		}

		return nil
	}

	_, err := asciiDomain(domain, false)
	return err
}

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
// Leading or trailing whitespace is rejected; input is never silently trimmed.
func RoutingDomain(domain string) (string, error) {
	return asciiDomain(domain, true)
}

func asciiDomain(domain string, requireFQDN bool) (string, error) {
	if domain == "" {
		return "", ErrEmptyDomain
	}

	if !utf8.ValidString(domain) {
		return "", ErrInvalidUTF8
	}

	// Whitespace is never accepted or stripped for routing.
	if strings.TrimSpace(domain) != domain {
		return "", ErrInvalidDomain
	}

	// Reject empty labels before IDNA (including trailing dots).
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", ErrDomainLabel
	}

	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDomain, err)
	}

	// Profile already lowercases; enforce lowercase ASCII A-labels explicitly.
	ascii = strings.ToLower(ascii)
	if ascii == "" {
		return "", ErrEmptyDomain
	}

	if len(ascii) > 253 {
		return "", ErrDomainLength
	}

	labels := strings.Split(ascii, ".")
	if requireFQDN && len(labels) < 2 {
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
