package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var reportSizeRE = regexp.MustCompile(`(?i)![0-9]+[kmgt]?$`)

// ValidateDMARCReportURIList validates DMARC rua syntax, including its optional
// terminal !digits[unit] report-size suffix.
func ValidateDMARCReportURIList(value string) error {
	return validateReportURIList(value, true)
}

// ValidateTLSReportURIList validates TLS-RPT rua syntax. TLS-RPT does not
// define DMARC's report-size suffix.
func ValidateTLSReportURIList(value string) error {
	return validateReportURIList(value, false)
}

func validateReportURIList(value string, dmarc bool) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	for uri := range strings.SplitSeq(value, ",") {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			return errors.New("empty report URI entry")
		}

		err := validateReportURI(uri, dmarc)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateReportURI(uri string, dmarc bool) error {
	base := strings.TrimSpace(uri)
	if dmarc {
		suffix := reportSizeRE.FindStringIndex(base)
		if suffix != nil {
			base = base[:suffix[0]]
		}
	}

	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid report URI %q: %w", uri, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "mailto":
		if u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid mailto URI %q", uri)
		}

		addr, err := mail.ParseAddress(u.Opaque)
		if err != nil || addr.Name != "" || addr.Address != u.Opaque || strings.Count(addr.Address, "@") != 1 {
			return fmt.Errorf("invalid mailto URI %q", uri)
		}

		domain := addr.Address[strings.LastIndexByte(addr.Address, '@')+1:]

		err = validateDomain("report mailbox domain", strings.ToLower(domain))
		if err != nil {
			return fmt.Errorf("invalid mailto URI %q", uri)
		}
	case "https":
		if u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
			return fmt.Errorf("invalid HTTPS report URI %q", uri)
		}

		host := strings.ToLower(u.Hostname())
		if net.ParseIP(host) == nil {
			err = validateDomain("HTTPS report host", host)
			if err != nil {
				return fmt.Errorf("invalid HTTPS report URI %q", uri)
			}
		}

		port := u.Port()
		if port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("invalid HTTPS report URI port in %q", uri)
			}
		}
	default:
		return fmt.Errorf("unsupported report URI scheme in %q (use mailto: or https:)", uri)
	}

	return nil
}
