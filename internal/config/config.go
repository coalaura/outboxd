package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/goccy/go-yaml"
)

type Config struct {
	dataMu *sync.RWMutex
	fileMu *sync.Mutex

	userLookup map[string]*User

	Server   Server   `yaml:"server"`
	TLS      TLS      `yaml:"tls"`
	DKIM     DKIM     `yaml:"dkim"`
	Delivery Delivery `yaml:"delivery"`
	DNS      DNS      `yaml:"dns"`
	Users    []User   `yaml:"users"`
}

type Server struct {
	Hostname        string `yaml:"hostname"`
	Domain          string `yaml:"domain"`
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	MaxRecipients   int    `yaml:"max_recipients"`
	ReadTimeout     string `yaml:"read_timeout"`
	WriteTimeout    string `yaml:"write_timeout"`
	DataDirectory   string `yaml:"data_directory"`
}

type TLS struct {
	Mode            string `yaml:"mode"`
	CertificateFile string `yaml:"certificate_file"`
	PrivateKeyFile  string `yaml:"private_key_file"`
	MinimumVersion  string `yaml:"minimum_version"`
}

type DKIM struct {
	Selector       string   `yaml:"selector"`
	PrivateKeyFile string   `yaml:"private_key_file"`
	Headers        []string `yaml:"headers"`
}

type Delivery struct {
	TLSMode               string `yaml:"tls_mode"`
	MaxAttempts           int    `yaml:"max_attempts"`
	InitialRetryDelay     string `yaml:"initial_retry_delay"`
	MaximumRetryDelay     string `yaml:"maximum_retry_delay"`
	DomainConcurrency     int    `yaml:"domain_concurrency"`
	GlobalConcurrency     int    `yaml:"global_concurrency"`
	ConnectionTimeout     string `yaml:"connection_timeout"`
	CommandTimeout        string `yaml:"command_timeout"`
	SubmissionTimeout     string `yaml:"submission_timeout"`
	RequireValidMXTLSCert bool   `yaml:"require_valid_mx_tls_certificate"`
}

type DNS struct {
	PublicIPv4 string `yaml:"public_ipv4"`
	PublicIPv6 string `yaml:"public_ipv6"`
	DMARC      string `yaml:"dmarc_policy"`
	ReportURI  string `yaml:"dmarc_report_uri"`
	OutputFile string `yaml:"output_file"`
}

type User struct {
	Username       string   `yaml:"username"`
	PasswordHash   string   `yaml:"password_hash"`
	AllowedSenders []string `yaml:"allowed_senders"`
	Enabled        bool     `yaml:"enabled"`
}

const configPath = "config.yml"

// Default returns the default config
func Default() *Config {
	return &Config{
		Server: Server{
			Hostname:        "mail.example.invalid",
			Domain:          "example.invalid",
			MaxMessageBytes: 25 << 20,
			MaxRecipients:   100,
			ReadTimeout:     "5m",
			WriteTimeout:    "5m",
			DataDirectory:   "./data",
		},
		TLS: TLS{
			Mode:            "self_signed",
			CertificateFile: "tls/server.crt",
			PrivateKeyFile:  "tls/server.key",
			MinimumVersion:  "1.2",
		},
		DKIM: DKIM{
			Selector:       "mail",
			PrivateKeyFile: "dkim/mail.key",
			Headers: []string{
				"From",
				"To",
				"Cc",
				"Subject",
				"Date",
				"Message-ID",
				"MIME-Version",
				"Content-Type",
				"Content-Transfer-Encoding",
				"Reply-To",
			},
		},
		Delivery: Delivery{
			TLSMode:               "opportunistic",
			MaxAttempts:           15,
			InitialRetryDelay:     "5m",
			MaximumRetryDelay:     "8h",
			DomainConcurrency:     2,
			GlobalConcurrency:     16,
			ConnectionTimeout:     "30s",
			CommandTimeout:        "5m",
			SubmissionTimeout:     "12m",
			RequireValidMXTLSCert: true,
		},
		DNS: DNS{
			DMARC:      "quarantine",
			OutputFile: "dns-records.txt",
		},
		Users: []User{
			{
				Username:     "example",
				PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dmgLPdAEgsPfBznUbnX0jA$3jpi3X+lrcemQBB4cL5OwOcyaB3hFPBvwoNYpxbTxjs",
				AllowedSenders: []string{
					"example@example.invalid",
				},
				Enabled: false,
			},
		},
	}
}

// Load loads the config
func Load() (*Config, error) {
	cfg := Default()

	cfg.initializeRuntime()

	file, err := os.OpenFile(configPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	err = yaml.NewDecoder(file, yaml.DisallowUnknownField()).Decode(cfg)
	if err != nil {
		return nil, err
	}

	err = cfg.Init()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// Ensure loads the config or atomically creates it with secure defaults.
func Ensure() (*Config, bool, error) {
	cfg, err := Load()
	if err == nil {
		return cfg, false, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	cfg = Default()

	cfg.initializeRuntime()

	err = cfg.Init()
	if err != nil {
		return nil, false, err
	}

	err = cfg.storeExclusive()
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			cfg, err = Load()

			return cfg, false, err
		}

		return nil, false, err
	}

	return cfg, true, nil
}

// Init validates the configuration and builds its runtime indexes.
func (cfg *Config) Init() error {
	cfg.initializeRuntime()

	err := cfg.Validate()
	if err != nil {
		return err
	}

	cfg.dataMu.Lock()
	defer cfg.dataMu.Unlock()

	cfg.userLookup = make(map[string]*User, len(cfg.Users))

	for i := range cfg.Users {
		user := &cfg.Users[i]

		username := canonicalUsername(user.Username)

		cfg.userLookup[username] = user
	}

	return nil
}

// User returns a snapshot of the configured user.
func (cfg *Config) User(username string) (User, bool) {
	cfg.dataMu.RLock()
	defer cfg.dataMu.RUnlock()

	user, ok := cfg.userLookup[canonicalUsername(username)]
	if !ok {
		return User{}, false
	}

	return User{
		Username:       user.Username,
		PasswordHash:   user.PasswordHash,
		Enabled:        user.Enabled,
		AllowedSenders: slices.Clone(user.AllowedSenders),
	}, true
}

// Store atomically writes the current configuration.
func (cfg *Config) Store() error {
	cfg.initializeRuntime()

	body, err := cfg.marshal()
	if err != nil {
		return err
	}

	cfg.fileMu.Lock()
	defer cfg.fileMu.Unlock()

	return disk.Write(configPath, body, 0600)
}

// Validate validates all config options.
func (cfg Config) Validate() error {
	err := validateDomain("server.hostname", cfg.Server.Hostname)
	if err != nil {
		return err
	}

	err = validateDomain("server.domain", cfg.Server.Domain)
	if err != nil {
		return err
	}

	if cfg.Server.MaxMessageBytes <= 0 {
		return errors.New("server.max_message_bytes must be positive")
	}

	if cfg.Server.MaxRecipients <= 0 {
		return errors.New("server.max_recipients must be positive")
	}

	if cfg.Server.DataDirectory == "" {
		return errors.New("server.data_directory must not be empty")
	}

	durations := map[string]string{
		"server.read_timeout":          cfg.Server.ReadTimeout,
		"server.write_timeout":         cfg.Server.WriteTimeout,
		"delivery.initial_retry_delay": cfg.Delivery.InitialRetryDelay,
		"delivery.maximum_retry_delay": cfg.Delivery.MaximumRetryDelay,
		"delivery.connection_timeout":  cfg.Delivery.ConnectionTimeout,
		"delivery.command_timeout":     cfg.Delivery.CommandTimeout,
		"delivery.submission_timeout":  cfg.Delivery.SubmissionTimeout,
	}

	for name, value := range durations {
		err = validateDuration(name, value)
		if err != nil {
			return err
		}
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

	hasFromHeader := slices.ContainsFunc(cfg.DKIM.Headers, func(header string) bool {
		return strings.EqualFold(header, "From")
	})

	if !hasFromHeader {
		return errors.New("dkim.headers must contain From")
	}

	switch cfg.Delivery.TLSMode {
	case "opportunistic", "required":
	default:
		return fmt.Errorf("delivery.tls_mode must be opportunistic or required, got %q", cfg.Delivery.TLSMode)
	}

	if cfg.Delivery.MaxAttempts <= 0 {
		return errors.New("delivery.max_attempts must be positive")
	}

	if cfg.Delivery.DomainConcurrency <= 0 || cfg.Delivery.GlobalConcurrency <= 0 {
		return errors.New("delivery concurrency limits must be positive")
	}

	switch cfg.DNS.DMARC {
	case "none", "quarantine", "reject":
	default:
		return fmt.Errorf("invalid DMARC policy %q", cfg.DNS.DMARC)
	}

	if cfg.DNS.PublicIPv4 != "" && net.ParseIP(cfg.DNS.PublicIPv4).To4() == nil {
		return fmt.Errorf("invalid public IPv4 address %q", cfg.DNS.PublicIPv4)
	}

	if cfg.DNS.PublicIPv6 != "" {
		ip := net.ParseIP(cfg.DNS.PublicIPv6)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid public IPv6 address %q", cfg.DNS.PublicIPv6)
		}
	}

	usernames := make(map[string]struct{}, len(cfg.Users))

	for i := range cfg.Users {
		user := &cfg.Users[i]

		err = user.Validate()
		if err != nil {
			return fmt.Errorf("users[%d]: %w", i, err)
		}

		username := canonicalUsername(user.Username)
		if _, exists := usernames[username]; exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}

		usernames[username] = struct{}{}
	}

	return nil
}

// Validate normalizes a single user in place and reports why it is unusable.
func (u *User) Validate() error {
	u.Username = strings.TrimSpace(u.Username)

	if u.Username == "" {
		return errors.New("username must not be empty")
	}

	if strings.ContainsAny(u.Username, "\x00\r\n") {
		return fmt.Errorf("invalid username %q", u.Username)
	}

	if !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		return fmt.Errorf("user %q must have an Argon2id password hash", u.Username)
	}

	if len(u.AllowedSenders) == 0 {
		return fmt.Errorf("user %q has no allowed senders", u.Username)
	}

	senders := make(map[string]struct{}, len(u.AllowedSenders))

	for i, sender := range u.AllowedSenders {
		sender = strings.TrimSpace(sender)

		address, err := mail.ParseAddress(sender)
		if err != nil || address.Address != sender {
			return fmt.Errorf("user %q has invalid sender %q", u.Username, sender)
		}

		canonicalSender := strings.ToLower(address.Address)
		if _, exists := senders[canonicalSender]; exists {
			return fmt.Errorf("user %q has duplicate sender %q", u.Username, sender)
		}

		senders[canonicalSender] = struct{}{}
		u.AllowedSenders[i] = address.Address
	}

	return nil
}

// IsReady reports configuration options that must be corrected before serving.
func (cfg Config) IsReady() error {
	var problems []error

	if strings.HasSuffix(cfg.Server.Domain, ".invalid") {
		problems = append(problems, errors.New("replace server.domain with the sending domain"))
	}

	if strings.HasSuffix(cfg.Server.Hostname, ".invalid") {
		problems = append(problems, errors.New("replace server.hostname with the public SMTP hostname"))
	}

	if cfg.DNS.PublicIPv4 == "" && cfg.DNS.PublicIPv6 == "" {
		problems = append(problems, errors.New("configure at least one public sending IP"))
	}

	if len(cfg.Users) == 0 {
		problems = append(problems, errors.New("configure at least one SMTP user"))
	}

	return errors.Join(problems...)
}

// Warnings reports non-fatal deliverability problems.
func (cfg Config) Warnings() []string {
	var warnings []string

	if cfg.TLS.Mode == "self_signed" {
		warnings = append(warnings, "tls.mode is self_signed; submission clients must trust the generated certificate")
	}

	if cfg.DNS.DMARC == "none" {
		warnings = append(warnings, `dmarc_policy is "none"; move to quarantine or reject once alignment is verified`)
	}

	if cfg.DNS.ReportURI == "" {
		warnings = append(warnings, "dns.dmarc_report_uri is empty; you will receive no DMARC reports and have no view of failures")
	}

	if cfg.Delivery.TLSMode == "opportunistic" {
		warnings = append(warnings, "delivery.tls_mode is opportunistic; destinations without STARTTLS receive plaintext")
	}

	return warnings
}

// ResolvePath resolves a path relative to the configured data directory.
func (cfg Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	return filepath.Join(cfg.Server.DataDirectory, path)
}

func (cfg *Config) initializeRuntime() {
	if cfg.dataMu == nil {
		cfg.dataMu = new(sync.RWMutex)
	}

	if cfg.fileMu == nil {
		cfg.fileMu = new(sync.Mutex)
	}
}

func (cfg *Config) storeExclusive() error {
	body, err := cfg.marshal()
	if err != nil {
		return err
	}

	cfg.fileMu.Lock()
	defer cfg.fileMu.Unlock()

	return disk.WriteExclusive(configPath, body, 0600)
}

func (cfg *Config) marshal() ([]byte, error) {
	var buffer bytes.Buffer

	comments := yaml.CommentMap{
		"$.server":                   {yaml.HeadComment(" SMTP submission server")},
		"$.server.hostname":          {yaml.HeadComment(" public SMTP hostname used for EHLO, TLS, MX, and reverse DNS")},
		"$.server.domain":            {yaml.HeadComment(" sending domain used for DKIM, SPF, and DMARC")},
		"$.server.max_message_bytes": {yaml.HeadComment(" maximum accepted message size in bytes")},
		"$.server.max_recipients":    {yaml.HeadComment(" maximum recipients accepted for one message")},
		"$.server.read_timeout":      {yaml.HeadComment(" maximum time spent waiting for an SMTP command")},
		"$.server.write_timeout":     {yaml.HeadComment(" maximum time spent writing an SMTP response")},
		"$.server.data_directory":    {yaml.HeadComment(" generated keys, certificates, DNS instructions and queue data")},

		"$.tls":                  {yaml.HeadComment("\n# TLS used by the submission listeners")},
		"$.tls.mode":             {yaml.HeadComment(` "self_signed" generates a development certificate; use "files" in production`)},
		"$.tls.certificate_file": {yaml.HeadComment(" certificate chain; relative paths are resolved below data_directory")},
		"$.tls.private_key_file": {yaml.HeadComment(" TLS private key; relative paths are resolved below data_directory")},
		"$.tls.minimum_version":  {yaml.HeadComment(` minimum accepted TLS version: "1.2" or "1.3"`)},

		"$.dkim":                  {yaml.HeadComment("\n# DKIM signing configuration")},
		"$.dkim.selector":         {yaml.HeadComment(" DNS selector placed before _domainkey")},
		"$.dkim.private_key_file": {yaml.HeadComment(" automatically generated when absent")},
		"$.dkim.headers":          {yaml.HeadComment(" message headers included in the DKIM signature; From is mandatory")},

		"$.delivery":                                  {yaml.HeadComment("\n# outbound SMTP delivery and retry policy")},
		"$.delivery.tls_mode":                         {yaml.HeadComment(` destination TLS policy: "opportunistic" or "required"`)},
		"$.delivery.max_attempts":                     {yaml.HeadComment(" maximum delivery attempts before moving a message to dead-letter state")},
		"$.delivery.initial_retry_delay":              {yaml.HeadComment(" delay after the first temporary delivery failure")},
		"$.delivery.maximum_retry_delay":              {yaml.HeadComment(" upper bound for exponential retry delays")},
		"$.delivery.domain_concurrency":               {yaml.HeadComment(" maximum simultaneous deliveries to one recipient domain")},
		"$.delivery.global_concurrency":               {yaml.HeadComment(" maximum simultaneous outbound deliveries")},
		"$.delivery.connection_timeout":               {yaml.HeadComment(" timeout while connecting to a destination MX")},
		"$.delivery.command_timeout":                  {yaml.HeadComment(" timeout while waiting for normal SMTP responses")},
		"$.delivery.submission_timeout":               {yaml.HeadComment(" timeout while waiting for the response after message data")},
		"$.delivery.require_valid_mx_tls_certificate": {yaml.HeadComment(" verify destination certificates whenever TLS is negotiated")},

		"$.dns":                  {yaml.HeadComment("\n# values used to generate dns-records.txt")},
		"$.dns.public_ipv4":      {yaml.HeadComment(" static public IPv4 address used for outbound delivery")},
		"$.dns.public_ipv6":      {yaml.HeadComment(" static public IPv6 address; omit until forward and reverse DNS are ready")},
		"$.dns.dmarc_policy":     {yaml.HeadComment(` "quarantine" is a safe default; move to "reject" once reports look clean`)},
		"$.dns.dmarc_report_uri": {yaml.HeadComment(" optional external aggregate-report URI, for example mailto:dmarc@example.com")},
		"$.dns.output_file":      {yaml.HeadComment(" generated DNS instructions; relative paths are below data_directory")},

		"$.users": {yaml.HeadComment("\n# SMTP users; password_hash must contain an Argon2id hash, never plaintext")},
	}

	cfg.dataMu.RLock()
	err := yaml.NewEncoder(&buffer, yaml.WithComment(comments), yaml.Indent(2)).Encode(cfg)
	cfg.dataMu.RUnlock()

	if err != nil {
		return nil, err
	}

	body := bytes.ReplaceAll(buffer.Bytes(), []byte("#\n"), []byte("\n"))

	return body, nil
}

func canonicalUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func validateDuration(name, value string) error {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return err
	}

	if duration <= 0 {
		return fmt.Errorf("%s must be positive", name)
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
