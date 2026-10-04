package config

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

const MaxDomains = 128

// DomainFor returns the most specific configured domain covering a sender domain.
// Subdomains inherit their parent's signing identity unless configured separately.
func (cfg *Config) DomainFor(name string) *Domain {
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	var matched *Domain

	for i := range cfg.Domains {
		domain := &cfg.Domains[i]

		if name != domain.Name && !strings.HasSuffix(name, "."+domain.Name) {
			continue
		}

		if matched == nil || len(domain.Name) > len(matched.Name) {
			matched = domain
		}
	}

	return matched
}

func (cfg *Config) validateDomains() error {
	if len(cfg.Domains) == 0 || len(cfg.Domains) > MaxDomains {
		return fmt.Errorf("domains must contain between 1 and %d entries", MaxDomains)
	}

	names := make(map[string]struct{}, len(cfg.Domains))
	paths := make(map[string]struct{}, len(cfg.Domains))

	for i := range cfg.Domains {
		domain := &cfg.Domains[i]

		field := fmt.Sprintf("domains[%d]", i)

		err := validateDomain(field+".name", domain.Name)
		if err != nil {
			return err
		}

		if _, exists := names[domain.Name]; exists {
			return fmt.Errorf("%s: duplicate domain %q", field, domain.Name)
		}

		names[domain.Name] = struct{}{}

		err = validateDNSLabel(field+".dkim.selector", domain.DKIM.Selector)
		if err != nil {
			return err
		}

		if domain.DKIM.PrivateKeyFile == "" {
			return fmt.Errorf("%s.dkim.private_key_file must not be empty", field)
		}

		path, err := cfg.ResolveGeneratedPath(domain.DKIM.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("%s.dkim.private_key_file: %w", field, err)
		}

		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			path = strings.ToLower(path)
		}

		if _, exists := paths[path]; exists {
			return fmt.Errorf("%s.dkim.private_key_file: domains must use distinct key paths", field)
		}

		paths[path] = struct{}{}

		err = validateDKIMHeaders(domain.DKIM.Headers)
		if err != nil {
			return fmt.Errorf("%s.dkim.headers: %w", field, err)
		}
	}

	return nil
}

func validateDKIMHeaders(headers []string) error {
	seen := make(map[string]struct{}, len(headers))

	for _, header := range headers {
		err := validateHeaderName(header)
		if err != nil {
			return err
		}

		canonical := strings.ToLower(header)
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("duplicate %q", header)
		}

		seen[canonical] = struct{}{}
	}

	if _, exists := seen["from"]; !exists {
		return errors.New("must contain From")
	}

	if _, exists := seen["sender"]; !exists {
		return errors.New("must contain Sender")
	}

	return nil
}
