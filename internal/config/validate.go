package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
)

// Validate validates all config options.
func (cfg *Config) Validate() error {
	switch cfg.LogLevel {
	case "debug", "print", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, print, warn or error, got %q", cfg.LogLevel)
	}

	err := validateDomain("server.hostname", cfg.Server.Hostname)
	if err != nil {
		return err
	}

	err = validateDomain("server.domain", cfg.Server.Domain)
	if err != nil {
		return err
	}

	if cfg.Server.MaxMessageBytes <= 0 || cfg.Server.MaxMessageBytes > MaxMessageBytes {
		return fmt.Errorf("server.max_message_bytes must be between 1 and %d", MaxMessageBytes)
	}

	if cfg.Server.MaxRecipients <= 0 || cfg.Server.MaxRecipients > MaxRecipients {
		return fmt.Errorf("server.max_recipients must be between 1 and %d", MaxRecipients)
	}

	if cfg.Server.MaxMessagesPerHour <= 0 || cfg.Server.MaxMessagesPerHour > MaxMessagesPerHour {
		return fmt.Errorf("server.max_messages_per_hour must be between 1 and %d", MaxMessagesPerHour)
	}

	if cfg.Server.MaxRecipientsPerHour <= 0 || cfg.Server.MaxRecipientsPerHour > MaxRecipientsPerHour {
		return fmt.Errorf("server.max_recipients_per_hour must be between 1 and %d", MaxRecipientsPerHour)
	}

	if cfg.Server.MessageBurst < 0 || cfg.Server.MessageBurst > MaxMessageBurst || cfg.Server.MessageBurst > cfg.Server.MaxMessagesPerHour {
		return fmt.Errorf("server.message_burst must be 0 (default) or between 1 and max_messages_per_hour, up to %d", MaxMessageBurst)
	}

	if cfg.Server.RecipientBurst < 0 || cfg.Server.RecipientBurst > MaxRecipientBurst || cfg.Server.RecipientBurst > cfg.Server.MaxRecipientsPerHour {
		return fmt.Errorf("server.recipient_burst must be 0 (default) or between 1 and max_recipients_per_hour, up to %d", MaxRecipientBurst)
	}

	if cfg.Server.DataDirectory == "" {
		return errors.New("server.data_directory must not be empty")
	}

	if cfg.Server.SubmissionListenAddr() == "" && cfg.Server.ImplicitTLSListenAddr() == "" {
		return errors.New("at least one submission listener must be enabled")
	}

	if cfg.Server.MaxConnections <= 0 || cfg.Server.MaxConnections > MaxConnections || cfg.Server.MaxConnectionsPerIP <= 0 || cfg.Server.MaxConnectionsPerIP > MaxConnectionsPerIP || cfg.Server.MaxConnectionsPerIP > cfg.Server.MaxConnections {
		return errors.New("connection limits are invalid or exceed supported bounds")
	}

	if cfg.Server.AuthWorkers <= 0 || cfg.Server.AuthWorkers > MaxAuthWorkers {
		return errors.New("auth worker limit is invalid or exceeds supported bounds")
	}

	err = cfg.validateReplyRejection()
	if err != nil {
		return err
	}

	if cfg.Server.MaxQueueMessages < 0 || cfg.Server.MaxQueueBytes < 0 || cfg.Server.MaxQueueMessagesPerUser < 0 || cfg.Server.MaxQueueBytesPerUser < 0 || cfg.Server.MinFreeDiskBytes < 0 {
		return errors.New("queue caps and minimum free disk must not be negative")
	}
	if cfg.Server.MaxSpoolBytes <= 0 {
		return errors.New("server.max_spool_bytes must be positive")
	}

	if cfg.Server.SpoolEmergencyBytes < queue.MinimumSpoolEmergencyBytes || cfg.Server.SpoolEmergencyBytes >= cfg.Server.MaxSpoolBytes {
		return fmt.Errorf("server.spool_emergency_bytes must be at least %d bytes and smaller than max_spool_bytes", queue.MinimumSpoolEmergencyBytes)
	}

	durations := []durationEntry{
		{"server.read_timeout", cfg.Server.ReadTimeout, MaxSMTPReadTimeout},
		{"server.write_timeout", cfg.Server.WriteTimeout, MaxSMTPWriteTimeout},
		{"server.dead_retention", cfg.Server.DeadRetention, MaxDeadRetention},
		{"server.corrupt_retention", cfg.Server.CorruptRetention, MaxCorruptRetention},
		{"delivery.maximum_lifetime", cfg.Delivery.MaximumLifetime, MaxDeliveryLifetime},
		{"delivery.initial_retry_delay", cfg.Delivery.InitialRetryDelay, MaxInitialRetryDelay},
		{"delivery.maximum_retry_delay", cfg.Delivery.MaximumRetryDelay, MaxRetryDelay},
		{"delivery.dns_timeout", cfg.Delivery.DNSTimeout, MaxDeliveryDNSTimeout},
		{"delivery.attempt_timeout", cfg.Delivery.AttemptTimeout, MaxDeliveryAttemptTimeout},
		{"delivery.connection_timeout", cfg.Delivery.ConnectionTimeout, MaxDeliveryConnectionTimeout},
		{"delivery.command_timeout", cfg.Delivery.CommandTimeout, MaxDeliveryCommandTimeout},
		{"delivery.submission_timeout", cfg.Delivery.SubmissionTimeout, MaxDeliverySubmissionTimeout},
	}

	for _, duration := range durations {
		err = validateDuration(duration.name, duration.value, duration.max)
		if err != nil {
			return err
		}
	}

	initial := Duration(cfg.Delivery.InitialRetryDelay)
	maximum := Duration(cfg.Delivery.MaximumRetryDelay)
	lifetime := Duration(cfg.Delivery.MaximumLifetime)

	if initial > maximum {
		return errors.New("delivery.initial_retry_delay must be <= maximum_retry_delay")
	}

	if maximum > lifetime {
		return errors.New("delivery.maximum_retry_delay must be <= maximum_lifetime")
	}

	connection := Duration(cfg.Delivery.ConnectionTimeout)
	command := Duration(cfg.Delivery.CommandTimeout)
	submission := Duration(cfg.Delivery.SubmissionTimeout)
	dnsTimeout := Duration(cfg.Delivery.DNSTimeout)
	attemptTimeout := Duration(cfg.Delivery.AttemptTimeout)

	if connection > command {
		return errors.New("delivery.connection_timeout must be <= command_timeout")
	}

	if submission < command {
		return errors.New("delivery.submission_timeout must be >= command_timeout")
	}

	if connection > lifetime || command > lifetime || submission > lifetime {
		return errors.New("delivery connection, command, and submission timeouts must be <= maximum_lifetime")
	}
	if dnsTimeout > attemptTimeout || submission > attemptTimeout {
		return errors.New("delivery dns and SMTP timeouts must be <= attempt_timeout")
	}

	switch cfg.TLS.Mode {
	case "self_signed", "files":
	default:
		return fmt.Errorf("unsupported tls.mode %q", cfg.TLS.Mode)
	}

	if cfg.TLS.CertificateFile == "" || cfg.TLS.PrivateKeyFile == "" {
		return errors.New("TLS certificate and private-key paths are required")
	}

	switch cfg.TLS.MinimumVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("tls.minimum_version must be 1.2 or 1.3, got %q", cfg.TLS.MinimumVersion)
	}

	err = validateDNSLabel("dkim.selector", cfg.DKIM.Selector)
	if err != nil {
		return err
	}

	if cfg.DKIM.PrivateKeyFile == "" {
		return errors.New("dkim.private_key_file must not be empty")
	}

	_, err = cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("dkim.private_key_file: %w", err)
	}

	var (
		hasFromHeader   bool
		hasSenderHeader bool
		seenDKIMHeaders = make(map[string]struct{}, len(cfg.DKIM.Headers))
	)

	for _, header := range cfg.DKIM.Headers {
		err = validateHeaderName(header)
		if err != nil {
			return fmt.Errorf("dkim.headers: %w", err)
		}

		canon := strings.ToLower(header)

		_, ok := seenDKIMHeaders[canon]
		if ok {
			return fmt.Errorf("dkim.headers: duplicate %q", header)
		}

		seenDKIMHeaders[canon] = struct{}{}

		switch canon {
		case "from":
			hasFromHeader = true
		case "sender":
			hasSenderHeader = true
		}
	}

	if !hasFromHeader {
		return errors.New("dkim.headers must contain From")
	}

	if !hasSenderHeader {
		return errors.New("dkim.headers must contain Sender")
	}

	openPGPSenders := make(map[string]struct{}, len(cfg.OpenPGP.Identities))

	_, signsAutocrypt := seenDKIMHeaders["autocrypt"]

	if len(cfg.OpenPGP.Identities) > MaxOpenPGPIdentities {
		return fmt.Errorf("openpgp.identities must contain at most %d entries", MaxOpenPGPIdentities)
	}

	for i := range cfg.OpenPGP.Identities {
		identity := &cfg.OpenPGP.Identities[i]

		sender, err := mailbox.Address(identity.Sender)
		if err != nil {
			return fmt.Errorf("openpgp.identities[%d].sender: %w", i, err)
		}

		at := strings.LastIndexByte(sender, '@')
		sender = sender[:at] + "@" + strings.ToLower(sender[at+1:])

		if _, exists := openPGPSenders[sender]; exists {
			return fmt.Errorf("openpgp.identities[%d]: duplicate sender %q", i, sender)
		}

		openPGPSenders[sender] = struct{}{}

		identity.Sender = sender

		if identity.SigningKey == "" {
			return fmt.Errorf("openpgp.identities[%d].signing_key must not be empty", i)
		}

		if identity.Signing != "required" {
			return fmt.Errorf("openpgp.identities[%d].signing must be required", i)
		}

		if identity.Autocrypt && !signsAutocrypt {
			return fmt.Errorf("openpgp.identities[%d].autocrypt requires Autocrypt in dkim.headers", i)
		}
	}

	switch cfg.Delivery.TLSMode {
	case "opportunistic", "required", "opportunistic_insecure":
	default:
		return fmt.Errorf("delivery.tls_mode must be opportunistic, required, or opportunistic_insecure, got %q", cfg.Delivery.TLSMode)
	}

	if cfg.Delivery.TLSMode == "required" && cfg.Delivery.AllowPlaintext != nil && *cfg.Delivery.AllowPlaintext {
		return errors.New("delivery.tls_mode=required cannot be combined with allow_plaintext=true")
	}

	if cfg.Delivery.TLSMode == "opportunistic_insecure" && cfg.Delivery.RequireValidMXTLSCert {
		return errors.New("delivery.tls_mode=opportunistic_insecure contradicts require_valid_mx_tls_certificate=true")
	}

	if cfg.Delivery.MaxAttempts <= 0 || cfg.Delivery.MaxAttempts > MaxDeliveryAttempts {
		return fmt.Errorf("delivery.max_attempts must be between 1 and %d", MaxDeliveryAttempts)
	}

	if cfg.Delivery.DomainConcurrency <= 0 || cfg.Delivery.DomainConcurrency > MaxDomainConcurrency || cfg.Delivery.GlobalConcurrency <= 0 || cfg.Delivery.GlobalConcurrency > MaxGlobalConcurrency || cfg.Delivery.UserConcurrency <= 0 || cfg.Delivery.UserConcurrency > MaxUserConcurrency || cfg.Delivery.DomainConcurrency > cfg.Delivery.GlobalConcurrency {
		return errors.New("delivery concurrency limits are invalid or exceed supported bounds")
	}

	if cfg.Delivery.MaxMXCandidates <= 0 || cfg.Delivery.MaxMXCandidates > MaxMXCandidates || cfg.Delivery.MaxIPCandidatesPerMX <= 0 || cfg.Delivery.MaxIPCandidatesPerMX > MaxIPCandidatesPerMX {
		return errors.New("delivery candidate limits are invalid or exceed supported bounds")
	}

	if cfg.Delivery.BindIPv4 != "" {
		ip, err := netip.ParseAddr(cfg.Delivery.BindIPv4)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("invalid delivery.bind_ipv4 %q", cfg.Delivery.BindIPv4)
		}

		cfg.Delivery.BindIPv4 = ip.String()
	}

	if cfg.Delivery.BindIPv6 != "" {
		ip := net.ParseIP(cfg.Delivery.BindIPv6)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid delivery.bind_ipv6 %q", cfg.Delivery.BindIPv6)
		}
	}

	for i, a := range cfg.Delivery.DestinationAllowlist {
		if net.ParseIP(a) == nil {
			return fmt.Errorf("delivery.destination_allowlist[%d] invalid", i)
		}
	}

	switch cfg.DNS.DMARC {
	case "none", "quarantine", "reject":
	default:
		return fmt.Errorf("invalid DMARC policy %q", cfg.DNS.DMARC)
	}

	if cfg.DNS.OutputFile == "" {
		return errors.New("dns.output_file must not be empty")
	}

	_, err = cfg.ResolveGeneratedPath(cfg.DNS.OutputFile)
	if err != nil {
		return fmt.Errorf("dns.output_file: %w", err)
	}

	if cfg.DNS.PublicIPv4 != "" {
		ip, err := netip.ParseAddr(cfg.DNS.PublicIPv4)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("invalid public IPv4 address %q", cfg.DNS.PublicIPv4)
		}

		cfg.DNS.PublicIPv4 = ip.String()
	}

	if cfg.DNS.PublicIPv6 != "" {
		ip := net.ParseIP(cfg.DNS.PublicIPv6)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid public IPv6 address %q", cfg.DNS.PublicIPv6)
		}
	}

	if cfg.DNS.ReportURI != "" {
		err = ValidateDMARCReportURIList(cfg.DNS.ReportURI)
		if err != nil {
			return fmt.Errorf("dns.dmarc_report_uri: %w", err)
		}
	}

	if cfg.DNS.TLSRPTURI != "" {
		err = ValidateTLSReportURIList(cfg.DNS.TLSRPTURI)
		if err != nil {
			return fmt.Errorf("dns.tlsrpt_uri: %w", err)
		}
	}

	for i, inc := range cfg.DNS.SPFIncludes {
		err = validateDomain(fmt.Sprintf("dns.spf_includes[%d]", i), inc)
		if err != nil {
			return err
		}
	}

	if len(cfg.DNS.SPFIncludes) > SPFDNSLookupLimit {
		return fmt.Errorf("dns.spf_includes exceeds SPF DNS lookup limit of %d", SPFDNSLookupLimit)
	}

	usernames := make(map[string]struct{}, len(cfg.Users))

	for i := range cfg.Users {
		user := &cfg.Users[i]

		err = user.Validate()
		if err != nil {
			return fmt.Errorf("users[%d]: %w", i, err)
		}

		err = passwd.ValidatePHC(user.PasswordHash)
		if err != nil {
			return fmt.Errorf("users[%d]: %w", i, err)
		}

		// Sender outside the DKIM domain can never produce an aligned DMARC pass.
		for _, sender := range user.AllowedSenders {
			domain := strings.ToLower(sender[strings.LastIndexByte(sender, '@')+1:])

			if domain != cfg.Server.Domain && !strings.HasSuffix(domain, "."+cfg.Server.Domain) {
				return fmt.Errorf("users[%d]: sender %q is outside server.domain %q; DKIM signs with d=%s so this mail cannot pass DMARC", i, sender, cfg.Server.Domain, cfg.Server.Domain)
			}
		}

		username := canonicalUsername(user.Username)

		_, exists := usernames[username]
		if exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}

		usernames[username] = struct{}{}
	}

	return nil
}

func (cfg *Config) validateReplyRejection() error {
	r := &cfg.ReplyRejection

	if r.ListenAddr == "" {
		return errors.New("reply_rejection.listen_addr must not be empty")
	}

	switch r.UnknownRecipients {
	case "listed_only", "all":
	default:
		return errors.New("reply_rejection.unknown_recipients must be listed_only or all")
	}

	err := validateResponseMessage("reply_rejection.default_message", r.DefaultMessage)
	if err != nil {
		return err
	}

	if r.MaxConnections <= 0 || r.MaxConnections > MaxReplyConnections || r.MaxConnectionsPerIP <= 0 || r.MaxConnectionsPerIP > MaxReplyConnectionsPerIP || r.MaxConnectionsPerIP > r.MaxConnections {
		return errors.New("reply rejection connection limits are invalid or exceed supported bounds")
	}

	err = validateDuration("reply_rejection.read_timeout", r.ReadTimeout, MaxReplyReadTimeout)
	if err != nil {
		return err
	}

	err = validateDuration("reply_rejection.write_timeout", r.WriteTimeout, MaxReplyWriteTimeout)
	if err != nil {
		return err
	}

	domains := make(map[string]struct{}, len(r.Domains))

	for i, domain := range r.Domains {
		err = validateDomain(fmt.Sprintf("reply_rejection.domains[%d]", i), domain)
		if err != nil {
			return err
		}

		canonical := strings.ToLower(domain)

		if _, exists := domains[canonical]; exists {
			return fmt.Errorf("duplicate reply rejection domain %q", domain)
		}

		domains[canonical] = struct{}{}
		r.Domains[i] = canonical
	}

	if r.Enabled && len(domains) == 0 {
		return errors.New("reply_rejection.domains must contain at least one domain when enabled")
	}

	recipients := make(map[string]struct{}, len(r.Recipients))

	for i := range r.Recipients {
		recipient := &r.Recipients[i]

		address, err := mailbox.Address(recipient.Address)
		if err != nil {
			return fmt.Errorf("reply_rejection.recipients[%d].address: %w", i, err)
		}

		domain, err := mailbox.DomainOf(address)
		if err != nil {
			return fmt.Errorf("reply_rejection.recipients[%d].address: %w", i, err)
		}

		if _, ok := domains[domain]; !ok {
			return fmt.Errorf("reply_rejection recipient %q is outside configured domains", address)
		}

		if recipient.Message != "" {
			err = validateResponseMessage(fmt.Sprintf("reply_rejection.recipients[%d].message", i), recipient.Message)
			if err != nil {
				return err
			}
		}

		canonical := strings.ToLower(address)

		if _, exists := recipients[canonical]; exists {
			return fmt.Errorf("duplicate reply rejection recipient %q", address)
		}

		recipients[canonical] = struct{}{}
		recipient.Address = address
	}

	return nil
}

func validateResponseMessage(name, message string) error {
	if message == "" || len(message) > 256 {
		return fmt.Errorf("%s must contain 1 to 256 ASCII characters", name)
	}

	for _, char := range message {
		if char < 32 || char > 126 {
			return fmt.Errorf("%s must contain only printable ASCII characters", name)
		}
	}

	return nil
}

func validateDuration(name, value string, maximum time.Duration) error {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if duration <= 0 {
		return fmt.Errorf("%s must be positive", name)
	}

	if duration > maximum {
		return fmt.Errorf("%s must not exceed %s", name, maximum)
	}

	return nil
}

func validateDomain(name, domain string) error {
	if len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("invalid %s %q", name, domain)
	}

	for label := range strings.SplitSeq(domain, ".") {
		err := validateDNSLabel(name, label)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateDNSLabel(name, label string) error {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("invalid %s %q", name, label)
	}

	for _, char := range label {
		if char != '-' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return fmt.Errorf("invalid %s %q", name, label)
		}
	}

	return nil
}

func validateHeaderName(name string) error {
	if name == "" {
		return errors.New("empty header name")
	}

	for _, r := range name {
		if r <= 32 || r >= 127 || r == ':' {
			return fmt.Errorf("invalid header name %q", name)
		}

		if unicode.IsControl(r) {
			return fmt.Errorf("invalid header name %q", name)
		}
	}

	return nil
}
