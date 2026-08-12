package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/goccy/go-yaml"
)

const maxConfigFileBytes = 1 << 20

type Config struct {
	dataMu *sync.RWMutex
	fileMu *sync.Mutex

	path    string
	baseDir string

	userLookup map[string]*User

	Server   Server   `yaml:"server"`
	TLS      TLS      `yaml:"tls"`
	DKIM     DKIM     `yaml:"dkim"`
	Delivery Delivery `yaml:"delivery"`
	DNS      DNS      `yaml:"dns"`
	Users    []User   `yaml:"users"`
}

// gost:preserve-layout
type Server struct {
	Hostname                  string `yaml:"hostname"`
	Domain                    string `yaml:"domain"`
	MaxMessageBytes           int64  `yaml:"max_message_bytes"`
	MaxRecipients             int    `yaml:"max_recipients"`
	MaxMessagesPerHour        int    `yaml:"max_messages_per_hour"`
	MaxRecipientsPerHour      int    `yaml:"max_recipients_per_hour"`
	MessageBurst              int    `yaml:"message_burst"`
	RecipientBurst            int    `yaml:"recipient_burst"`
	IncludeClientIPInReceived bool   `yaml:"include_client_ip_in_received"`
	ReadTimeout               string `yaml:"read_timeout"`
	WriteTimeout              string `yaml:"write_timeout"`
	DataDirectory             string `yaml:"data_directory"`
	SubmissionAddr            string `yaml:"submission_addr"`
	ImplicitTLSAddr           string `yaml:"implicit_tls_addr"`
	DisableSubmission         bool   `yaml:"disable_submission,omitempty"`
	DisableImplicitTLS        bool   `yaml:"disable_implicit_tls,omitempty"`
	MaxConnections            int    `yaml:"max_connections"`
	MaxConnectionsPerIP       int    `yaml:"max_connections_per_ip"`
	AuthWorkers               int    `yaml:"auth_workers"`
	MaxQueueMessages          int    `yaml:"max_queue_messages"`
	MaxQueueBytes             int64  `yaml:"max_queue_bytes"`
	MaxQueueMessagesPerUser   int    `yaml:"max_queue_messages_per_user"`
	MaxQueueBytesPerUser      int64  `yaml:"max_queue_bytes_per_user"`
	MaxSpoolBytes             int64  `yaml:"max_spool_bytes"`
	SpoolEmergencyBytes       int64  `yaml:"spool_emergency_bytes"`
	MinFreeDiskBytes          int64  `yaml:"min_free_disk_bytes"`
	DeadRetention             string `yaml:"dead_retention"`
	CorruptRetention          string `yaml:"corrupt_retention"`
}

type TLS struct {
	Mode                   string `yaml:"mode"`
	AllowSelfSignedServing bool   `yaml:"allow_self_signed_serving"`
	CertificateFile        string `yaml:"certificate_file"`
	PrivateKeyFile         string `yaml:"private_key_file"`
	MinimumVersion         string `yaml:"minimum_version"`
}

type DKIM struct {
	Selector       string   `yaml:"selector"`
	PrivateKeyFile string   `yaml:"private_key_file"`
	Headers        []string `yaml:"headers"`
}

// gost:preserve-layout
type Delivery struct {
	// TLSMode: opportunistic | required | opportunistic_insecure
	TLSMode        string `yaml:"tls_mode"`
	AllowPlaintext *bool  `yaml:"allow_plaintext,omitempty"`

	MaxAttempts          int    `yaml:"max_attempts"`
	MaximumLifetime      string `yaml:"maximum_lifetime"`
	InitialRetryDelay    string `yaml:"initial_retry_delay"`
	MaximumRetryDelay    string `yaml:"maximum_retry_delay"`
	DomainConcurrency    int    `yaml:"domain_concurrency"`
	GlobalConcurrency    int    `yaml:"global_concurrency"`
	UserConcurrency      int    `yaml:"user_concurrency"`
	DNSTimeout           string `yaml:"dns_timeout"`
	AttemptTimeout       string `yaml:"attempt_timeout"`
	MaxMXCandidates      int    `yaml:"max_mx_candidates"`
	MaxIPCandidatesPerMX int    `yaml:"max_ip_candidates_per_mx"`
	ConnectionTimeout    string `yaml:"connection_timeout"`
	CommandTimeout       string `yaml:"command_timeout"`
	SubmissionTimeout    string `yaml:"submission_timeout"`

	RequireValidMXTLSCert bool `yaml:"require_valid_mx_tls_certificate"`

	// BindIPv4/BindIPv6 are local outbound bind addresses (not DNS public IPs).
	BindIPv4 string `yaml:"bind_ipv4"`
	BindIPv6 string `yaml:"bind_ipv6"`

	AllowPrivateDestinations bool     `yaml:"allow_private_destinations"`
	DestinationAllowlist     []string `yaml:"destination_allowlist"`
}

type DNS struct {
	PublicIPv4  string   `yaml:"public_ipv4"`
	PublicIPv6  string   `yaml:"public_ipv6"`
	DMARC       string   `yaml:"dmarc_policy"`
	ReportURI   string   `yaml:"dmarc_report_uri"`
	TLSRPTURI   string   `yaml:"tlsrpt_uri"`
	SPFIncludes []string `yaml:"spf_includes"`
	OutputFile  string   `yaml:"output_file"`
}

type User struct {
	Username       string   `yaml:"username"`
	PasswordHash   string   `yaml:"password_hash"`
	AllowedSenders []string `yaml:"allowed_senders"`
	Enabled        bool     `yaml:"enabled"`
}

type durationEntry struct {
	name  string
	value string
	max   time.Duration
}

const (
	defaultConfigName    = "config.yml"
	DataMemoryBudget     = int64(512 << 20)
	DataMemoryCopies     = int64(8)
	DataMemoryOverhead   = int64(1<<20) + 1000*128
	MaxDataWorkers       = 8
	MaxMessageBytes      = (DataMemoryBudget - DataMemoryOverhead) / DataMemoryCopies
	MaxRecipients        = 1000
	MaxMessagesPerHour   = 1_000_000
	MaxRecipientsPerHour = 10_000_000
	MaxMessageBurst      = MaxMessagesPerHour
	MaxRecipientBurst    = MaxRecipientsPerHour
	MaxDeliveryAttempts  = 100
	MaxDomainConcurrency = 64
	MaxGlobalConcurrency = 256
	MaxUserConcurrency   = 64
	MaxMXCandidates      = 100
	MaxIPCandidatesPerMX = 64
	MaxConnections       = 3840
	MaxConnectionsPerIP  = 256
	MaxAuthWorkers       = 8
	SPFDNSLookupLimit    = 10

	MaxSMTPReadTimeout           = 30 * time.Minute
	MaxSMTPWriteTimeout          = 30 * time.Minute
	MaxDeadRetention             = 365 * 24 * time.Hour
	MaxCorruptRetention          = 365 * 24 * time.Hour
	MaxDeliveryLifetime          = 30 * 24 * time.Hour
	MaxInitialRetryDelay         = 24 * time.Hour
	MaxRetryDelay                = 7 * 24 * time.Hour
	MaxDeliveryDNSTimeout        = 2 * time.Minute
	MaxDeliveryAttemptTimeout    = time.Hour
	MaxDeliveryConnectionTimeout = 2 * time.Minute
	MaxDeliveryCommandTimeout    = 10 * time.Minute
	MaxDeliverySubmissionTimeout = 30 * time.Minute

	// EnvConfigPath overrides the config file path.
	EnvConfigPath = "OUTBOXD_CONFIG"
)

// Default returns the default config without an example password hash.
func Default() *Config {
	var allowPlain bool

	return &Config{
		Server: Server{
			Hostname:                "mail.example.invalid",
			Domain:                  "example.invalid",
			MaxMessageBytes:         25 << 20,
			MaxRecipients:           100,
			MaxMessagesPerHour:      1000,
			MaxRecipientsPerHour:    10000,
			ReadTimeout:             "5m",
			WriteTimeout:            "5m",
			DataDirectory:           "./data",
			SubmissionAddr:          ":587",
			ImplicitTLSAddr:         ":465",
			MaxConnections:          256,
			MaxConnectionsPerIP:     16,
			AuthWorkers:             4,
			MaxQueueMessages:        10000,
			MaxQueueBytes:           10 << 30,
			MaxQueueMessagesPerUser: 1000,
			MaxQueueBytesPerUser:    1 << 30,
			MaxSpoolBytes:           16 << 30,
			SpoolEmergencyBytes:     512 << 20,
			MinFreeDiskBytes:        1 << 30,
			DeadRetention:           "720h",
			CorruptRetention:        "336h",
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
				"Sender",
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
			TLSMode:               "required",
			AllowPlaintext:        &allowPlain,
			MaxAttempts:           15,
			MaximumLifetime:       "120h",
			InitialRetryDelay:     "5m",
			MaximumRetryDelay:     "8h",
			DomainConcurrency:     2,
			GlobalConcurrency:     16,
			UserConcurrency:       2,
			DNSTimeout:            "30s",
			AttemptTimeout:        "30m",
			MaxMXCandidates:       10,
			MaxIPCandidatesPerMX:  8,
			ConnectionTimeout:     "30s",
			CommandTimeout:        "5m",
			SubmissionTimeout:     "12m",
			RequireValidMXTLSCert: true,
		},
		DNS: DNS{
			DMARC:      "none",
			OutputFile: "dns-records.txt",
		},
		Users: nil,
	}
}

// ResolveConfigPath picks the config path from flag/env/default.
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}

	v := os.Getenv(EnvConfigPath)
	if v != "" {
		return v
	}

	return defaultConfigName
}

// LoadFile loads configuration from path.
func LoadFile(path string) (*Config, error) {
	cfg := Default()

	cfg.initializeRuntime()

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	cfg.path = abs
	cfg.baseDir = filepath.Dir(abs)

	raw, err := ReadCheckedFile(abs, true, false, maxConfigFileBytes)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}

	err = rejectMultiDoc(raw)
	if err != nil {
		return nil, err
	}

	cfg.Users = nil

	dec := yaml.NewDecoder(bytes.NewReader(raw), yaml.DisallowUnknownField())

	err = dec.Decode(cfg)
	if err != nil {
		return nil, err
	}

	var extra any

	err = dec.Decode(&extra)
	if err == nil {
		return nil, errors.New("config contains trailing YAML content")
	} else if err != io.EOF && !isYAMLEOF(err) {
		return nil, fmt.Errorf("trailing YAML content: %w", err)
	}

	cfg.applyDefaults()

	err = cfg.Init()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func isYAMLEOF(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) || strings.Contains(err.Error(), "EOF"))
}

func rejectMultiDoc(raw []byte) error {
	var count int

	for line := range bytes.SplitSeq(raw, []byte("\n")) {
		if bytes.Equal(bytes.TrimSpace(line), []byte("---")) {
			count++

			if count > 1 {
				return errors.New("config contains multiple YAML documents")
			}
		}
	}

	return nil
}

// Load loads from the default path resolution.
func Load() (*Config, error) {
	return LoadFile(ResolveConfigPath(""))
}

// Ensure loads the config or atomically creates it with secure defaults.
func Ensure() (*Config, bool, error) {
	return EnsurePath(ResolveConfigPath(""))
}

// EnsurePath loads or creates config at path.
func EnsurePath(path string) (*Config, bool, error) {
	cfg, err := LoadFile(path)
	if err == nil {
		return cfg, false, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	cfg = Default()

	cfg.initializeRuntime()

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, false, err
	}

	cfg.path = abs
	cfg.baseDir = filepath.Dir(abs)

	cfg.applyDefaults()

	err = cfg.Init()
	if err != nil {
		return nil, false, err
	}

	err = cfg.storeExclusive()
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			cfg, err = LoadFile(path)

			return cfg, false, err
		}

		return nil, false, err
	}

	return cfg, true, nil
}

func (cfg *Config) applyDefaults() {
	if !slices.ContainsFunc(cfg.DKIM.Headers, func(header string) bool {
		return strings.EqualFold(strings.TrimSpace(header), "Sender")
	}) {
		cfg.DKIM.Headers = append(cfg.DKIM.Headers, "Sender")
	}

	if cfg.Server.DisableSubmission {
		cfg.Server.SubmissionAddr = ""
	}

	if cfg.Server.DisableImplicitTLS {
		cfg.Server.ImplicitTLSAddr = ""
	}

	if cfg.Delivery.TLSMode == "" {
		cfg.Delivery.TLSMode = "required"
	}

	if cfg.DNS.DMARC == "" {
		cfg.DNS.DMARC = "none"
	}

	if cfg.DNS.OutputFile == "" {
		cfg.DNS.OutputFile = "dns-records.txt"
	}
}

// SubmissionListenAddr returns the STARTTLS listen address or "" if disabled.
func (s Server) SubmissionListenAddr() string {
	if s.DisableSubmission {
		return ""
	}

	return s.SubmissionAddr
}

// ImplicitTLSListenAddr returns the implicit TLS listen address or "" if disabled.
func (s Server) ImplicitTLSListenAddr() string {
	if s.DisableImplicitTLS {
		return ""
	}

	return s.ImplicitTLSAddr
}

// PlaintextAllowed reports whether opportunistic plaintext delivery is allowed.
func (d Delivery) PlaintextAllowed() bool {
	if d.TLSMode == "required" {
		return false
	}

	if d.AllowPlaintext != nil {
		return *d.AllowPlaintext
	}

	return false
}

// InsecureTLSAllowed reports whether STARTTLS without certificate verification is allowed.
func (d Delivery) InsecureTLSAllowed() bool {
	if d.TLSMode == "opportunistic_insecure" {
		return true
	}

	return d.TLSMode == "opportunistic" && !d.RequireValidMXTLSCert
}

// Init validates the configuration and builds its runtime indexes.
func (cfg *Config) Init() error {
	cfg.initializeRuntime()
	cfg.canonicalize()

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

func (cfg *Config) canonicalize() {
	cfg.Server.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.Server.Hostname), "."))
	cfg.Server.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.Server.Domain), "."))
	cfg.DKIM.Selector = strings.ToLower(strings.TrimSpace(cfg.DKIM.Selector))

	for i, inc := range cfg.DNS.SPFIncludes {
		cfg.DNS.SPFIncludes[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(inc), "."))
	}
}

// Path returns the absolute config file path.
func (cfg *Config) Path() string {
	return cfg.path
}

// BaseDir returns the directory containing the config file.
func (cfg *Config) BaseDir() string {
	return cfg.baseDir
}

// AddUser appends a user and atomically rewrites the config after Validate.
func (cfg *Config) AddUser(user User) error {
	err := user.Validate()
	if err != nil {
		return err
	}

	err = passwd.ValidatePHC(user.PasswordHash)
	if err != nil {
		return err
	}

	path := cfg.path
	if path == "" {
		path = defaultConfigName
	}

	lock, err := lockConfig(path + ".lock")
	if err != nil {
		return err
	}

	defer lock.Close()

	latest, err := LoadFile(path)
	if err != nil {
		return fmt.Errorf("reload config under mutation lock: %w", err)
	}

	for i := range latest.Users {
		if canonicalUsername(latest.Users[i].Username) == canonicalUsername(user.Username) {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
	}

	latest.Users = append(latest.Users, user)

	err = latest.Init()
	if err != nil {
		return err
	}

	err = latest.Save()
	if err != nil {
		return err
	}

	cfg.adopt(latest)

	return nil
}

func lockConfig(path string) (*disk.FileLock, error) {
	deadline := time.Now().Add(10 * time.Second)

	for {
		lock, err := disk.Lock(path)
		if err == nil {
			return lock, nil
		}

		if !errors.Is(err, disk.ErrLocked) || time.Now().After(deadline) {
			return nil, fmt.Errorf("lock config for mutation: %w", err)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (cfg *Config) adopt(other *Config) {
	cfg.dataMu.Lock()
	defer cfg.dataMu.Unlock()

	cfg.Server, cfg.TLS, cfg.DKIM, cfg.Delivery, cfg.DNS = other.Server, other.TLS, other.DKIM, other.Delivery, other.DNS
	cfg.Users = slices.Clone(other.Users)
	cfg.userLookup = make(map[string]*User, len(cfg.Users))

	for i := range cfg.Users {
		cfg.userLookup[canonicalUsername(cfg.Users[i].Username)] = &cfg.Users[i]
	}
}

// Save atomically replaces the config file.
func (cfg *Config) Save() error {
	body, err := cfg.marshal()
	if err != nil {
		return err
	}

	path := cfg.path
	if path == "" {
		path = defaultConfigName
	}

	cfg.fileMu.Lock()
	defer cfg.fileMu.Unlock()

	return disk.Write(path, body, 0600)
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

// Validate validates all config options.
func (cfg *Config) Validate() error {
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

		// Wildcard domain policy: *@example.com
		if strings.HasPrefix(sender, "*@") {
			domain := strings.TrimSpace(sender[2:])
			if domain == "" || strings.Contains(domain, "@") {
				return fmt.Errorf("user %q has invalid sender %q", u.Username, sender)
			}

			err := validateDomain("allowed_senders", strings.ToLower(domain))
			if err != nil {
				return fmt.Errorf("user %q has invalid sender %q", u.Username, sender)
			}

			canonicalSender := "*@" + strings.ToLower(domain)

			_, exists := senders[canonicalSender]
			if exists {
				return fmt.Errorf("user %q has duplicate sender %q", u.Username, sender)
			}

			senders[canonicalSender] = struct{}{}
			u.AllowedSenders[i] = canonicalSender

			continue
		}

		address, err := mailbox.Address(sender)
		if err != nil {
			return fmt.Errorf("user %q has invalid sender %q", u.Username, sender)
		}

		at := strings.LastIndexByte(address, '@')
		canonicalSender := address[:at] + "@" + strings.ToLower(address[at+1:])

		_, exists := senders[canonicalSender]
		if exists {
			return fmt.Errorf("user %q has duplicate sender %q", u.Username, sender)
		}

		senders[canonicalSender] = struct{}{}

		// Preserve local-part case while normalizing the case-insensitive domain.
		u.AllowedSenders[i] = canonicalSender
	}

	return nil
}

// IsReady reports configuration options that must be corrected before serving.
func (cfg *Config) IsReady() error {
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

	enabled := 0

	for i := range cfg.Users {
		if cfg.Users[i].Enabled {
			enabled++
		}
	}

	if enabled == 0 {
		problems = append(problems, errors.New("configure at least one enabled SMTP user"))
	}

	if cfg.TLS.Mode == "self_signed" && !cfg.TLS.AllowSelfSignedServing {
		problems = append(problems, errors.New("tls.mode=self_signed requires tls.allow_self_signed_serving=true before serving"))
	}

	return errors.Join(problems...)
}

// Warnings reports non-fatal deliverability problems.
func (cfg *Config) Warnings() []string {
	var warnings []string

	if cfg.TLS.Mode == "self_signed" {
		warnings = append(warnings, "tls.mode is self_signed (development only); ordinary SMTP clients will not trust the certificate — use tls.mode=files with a publicly trusted certificate in production")
	}

	if cfg.DNS.DMARC == "none" {
		warnings = append(warnings, `dmarc_policy is "none"; stage to quarantine then reject after verifying SPF/DKIM alignment via aggregate reports`)
	}

	if cfg.DNS.ReportURI == "" {
		warnings = append(warnings, "dns.dmarc_report_uri is empty; you will receive no DMARC reports and have no view of failures")
	}

	if cfg.Delivery.TLSMode == "opportunistic" {
		warnings = append(warnings, "delivery.tls_mode is opportunistic; destinations without STARTTLS may receive plaintext when allow_plaintext is true")
	}

	if cfg.Delivery.TLSMode == "opportunistic_insecure" {
		warnings = append(warnings, "delivery.tls_mode is opportunistic_insecure; certificate verification is disabled for STARTTLS — development/legacy only")
	}

	if cfg.Server.Domain == cfg.Server.Hostname {
		warnings = append(warnings, "server.hostname equals server.domain; prefer a dedicated sending subdomain when the parent domain has other senders")
	}

	return warnings
}

// ResolvePath resolves a path relative to the configured data directory.
// Relative data_directory values are resolved against the config file directory.
func (cfg Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	data := cfg.Server.DataDirectory
	if !filepath.IsAbs(data) && cfg.baseDir != "" {
		data = filepath.Join(cfg.baseDir, data)
	}

	return filepath.Join(data, path)
}

// ResolveGeneratedPath confines generated DKIM and DNS files beneath data_directory.
func (cfg Config) ResolveGeneratedPath(path string) (string, error) {
	data, err := filepath.Abs(filepath.Clean(cfg.ResolvedDataDir()))
	if err != nil {
		return "", err
	}

	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(data, target)
	}

	target, err = filepath.Abs(filepath.Clean(target))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(data, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path must resolve to a file beneath server.data_directory")
	}

	return target, nil
}

// ResolvedDataDir returns the absolute data directory.
func (cfg Config) ResolvedDataDir() string {
	data := cfg.Server.DataDirectory
	if filepath.IsAbs(data) {
		return data
	}

	if cfg.baseDir != "" {
		return filepath.Join(cfg.baseDir, data)
	}

	abs, err := filepath.Abs(data)
	if err != nil {
		return data
	}

	return abs
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

	path := cfg.path
	if path == "" {
		path = defaultConfigName
	}

	cfg.fileMu.Lock()
	defer cfg.fileMu.Unlock()

	return disk.WriteExclusive(path, body, 0600)
}

func (cfg *Config) marshal() ([]byte, error) {
	var buffer bytes.Buffer

	comments := yaml.CommentMap{
		"$.server":                               {yaml.HeadComment(" SMTP submission server (send-only; no inbound MX)")},
		"$.server.hostname":                      {yaml.HeadComment(" public SMTP hostname used for EHLO, TLS, and reverse DNS")},
		"$.server.domain":                        {yaml.HeadComment(" sending domain used for DKIM, SPF, and DMARC; prefer a dedicated subdomain")},
		"$.server.max_message_bytes":             {yaml.HeadComment(" maximum accepted message size in bytes (bounded so one DATA worker fits the 512 MiB processing budget)")},
		"$.server.max_recipients":                {yaml.HeadComment(" maximum recipients accepted for one message")},
		"$.server.max_messages_per_hour":         {yaml.HeadComment(" per-user hourly message rate (maximum 1000000)")},
		"$.server.max_recipients_per_hour":       {yaml.HeadComment(" per-user hourly recipient rate (maximum 10000000)")},
		"$.server.message_burst":                 {yaml.HeadComment(" token-bucket burst for messages (0 = hourly/60; otherwise no greater than hourly rate)")},
		"$.server.recipient_burst":               {yaml.HeadComment(" token-bucket burst for recipients (0 = hourly/60; otherwise no greater than hourly rate)")},
		"$.server.submission_addr":               {yaml.HeadComment(` STARTTLS submission listen address; default ":587"; empty disables`)},
		"$.server.implicit_tls_addr":             {yaml.HeadComment(` implicit TLS submission listen address; default ":465"; empty disables`)},
		"$.server.max_connections":               {yaml.HeadComment(" global concurrent submission connections (maximum 3840; leaves room for bounded DATA, auth, and delivery workers)")},
		"$.server.max_connections_per_ip":        {yaml.HeadComment(" per-IP concurrent submission connections (maximum 256 and no greater than global)")},
		"$.server.auth_workers":                  {yaml.HeadComment(" concurrent Argon2id authentications (19 MiB each; maximum 8)")},
		"$.server.max_queue_messages":            {yaml.HeadComment(" maximum ready queue message count (0 = unlimited)")},
		"$.server.max_queue_bytes":               {yaml.HeadComment(" logical quota for ready message bodies only (0 = unlimited)")},
		"$.server.max_queue_messages_per_user":   {yaml.HeadComment(" per-user ready queue message cap (0 = unlimited; generated DSNs are exempt)")},
		"$.server.max_queue_bytes_per_user":      {yaml.HeadComment(" per-user ready message-body quota (0 = unlimited; generated DSNs are exempt)")},
		"$.server.max_spool_bytes":               {yaml.HeadComment(" conservative admission estimate across ready, tmp, dsn, dead, corrupt, and trash; use a dedicated quota-controlled volume for a hard limit")},
		"$.server.spool_emergency_bytes":         {yaml.HeadComment(" estimated spool headroom reserved from submissions for DSNs and state transitions")},
		"$.server.min_free_disk_bytes":           {yaml.HeadComment(" refuse submissions when free disk is below this threshold")},
		"$.server.dead_retention":                {yaml.HeadComment(" positive retention for dead letters before automatic pruning (maximum 365d)")},
		"$.server.corrupt_retention":             {yaml.HeadComment(" positive retention for quarantined entries before automatic pruning (maximum 365d)")},
		"$.server.include_client_ip_in_received": {yaml.HeadComment(" include the submitting client's IP address in Received headers")},
		"$.server.read_timeout":                  {yaml.HeadComment(" SMTP command-idle, TLS-read, and DATA-read timeout (maximum 30m)")},
		"$.server.write_timeout":                 {yaml.HeadComment(" SMTP response and TLS-write timeout (maximum 30m)")},
		"$.server.data_directory":                {yaml.HeadComment(" generated keys, certificates, DNS instructions and queue data; relative to the config file directory")},

		"$.tls":                           {yaml.HeadComment("\n# TLS used by the submission listeners")},
		"$.tls.mode":                      {yaml.HeadComment(` "self_signed" is development-only; use "files" with a publicly trusted certificate in production`)},
		"$.tls.allow_self_signed_serving": {yaml.HeadComment(" explicit development-only opt-in required to serve with a self-signed certificate")},
		"$.tls.certificate_file":          {yaml.HeadComment(" certificate chain; relative paths are resolved below data_directory")},
		"$.tls.private_key_file":          {yaml.HeadComment(" TLS private key; relative paths are resolved below data_directory")},
		"$.tls.minimum_version":           {yaml.HeadComment(` minimum accepted TLS version: "1.2" or "1.3"`)},

		"$.dkim":                  {yaml.HeadComment("\n# DKIM signing configuration")},
		"$.dkim.selector":         {yaml.HeadComment(" DNS selector placed before _domainkey")},
		"$.dkim.private_key_file": {yaml.HeadComment(" create-once signing key provisioned explicitly with 'outboxd provision'")},
		"$.dkim.headers":          {yaml.HeadComment(" message headers included in the DKIM signature; From is mandatory")},

		"$.delivery":                                  {yaml.HeadComment("\n# outbound SMTP delivery and retry policy")},
		"$.delivery.tls_mode":                         {yaml.HeadComment(` destination TLS policy (chosen before connect; never verified-then-insecure fallback): "opportunistic" (verify STARTTLS when offered; plaintext only if allow_plaintext), "required" (STARTTLS required, verified), "opportunistic_insecure" (STARTTLS without cert verification — legacy/dev only)`)},
		"$.delivery.allow_plaintext":                  {yaml.HeadComment(" when true with opportunistic modes, allow destinations that do not advertise STARTTLS; advertised STARTTLS failures never fall back to plaintext")},
		"$.delivery.bind_ipv4":                        {yaml.HeadComment(" optional local IPv4 bind for outbound MX connections (independent of dns.public_ipv4)")},
		"$.delivery.bind_ipv6":                        {yaml.HeadComment(" optional local IPv6 bind for outbound MX connections")},
		"$.delivery.max_attempts":                     {yaml.HeadComment(" maximum delivery attempts before moving a message to dead-letter state")},
		"$.delivery.maximum_lifetime":                 {yaml.HeadComment(" absolute time a message may remain queued before dead-lettering (maximum 30d)")},
		"$.delivery.initial_retry_delay":              {yaml.HeadComment(" delay after the first temporary delivery failure (maximum 24h)")},
		"$.delivery.maximum_retry_delay":              {yaml.HeadComment(" upper bound for exponential retry delays (maximum 7d and no greater than lifetime)")},
		"$.delivery.domain_concurrency":               {yaml.HeadComment(" maximum simultaneous deliveries to one recipient domain")},
		"$.delivery.global_concurrency":               {yaml.HeadComment(" maximum simultaneous outbound deliveries")},
		"$.delivery.user_concurrency":                 {yaml.HeadComment(" maximum active deliveries owned by one SMTP user; generated DSNs use an isolated internal owner")},
		"$.delivery.dns_timeout":                      {yaml.HeadComment(" timeout for each outbound DNS lookup (maximum 2m and no greater than attempt_timeout)")},
		"$.delivery.attempt_timeout":                  {yaml.HeadComment(" aggregate deadline for one queue delivery attempt across domains, DNS, candidates, and SMTP (maximum 1h)")},
		"$.delivery.max_mx_candidates":                {yaml.HeadComment(" maximum sorted unique MX hosts tried per recipient domain (maximum 100)")},
		"$.delivery.max_ip_candidates_per_mx":         {yaml.HeadComment(" maximum sorted unique addresses tried per MX host (maximum 64)")},
		"$.delivery.connection_timeout":               {yaml.HeadComment(" timeout while dialing a destination MX (maximum 2m; no greater than command_timeout)")},
		"$.delivery.command_timeout":                  {yaml.HeadComment(" timeout while waiting for normal SMTP responses (maximum 10m)")},
		"$.delivery.submission_timeout":               {yaml.HeadComment(" timeout while waiting for the response after message data (maximum 30m; at least command_timeout)")},
		"$.delivery.require_valid_mx_tls_certificate": {yaml.HeadComment(" legacy: when false with tls_mode=opportunistic, STARTTLS uses insecure verification on the first (only) attempt; prefer tls_mode=opportunistic_insecure. Never enables verified-then-insecure reconnect")},
		"$.delivery.allow_private_destinations":       {yaml.HeadComment(" permit delivery to private/loopback MX addresses (default false)")},

		"$.dns":                  {yaml.HeadComment("\n# values used to generate dns-records.txt (not outbound bind addresses)")},
		"$.dns.public_ipv4":      {yaml.HeadComment(" static public IPv4 for A/SPF DNS generation")},
		"$.dns.public_ipv6":      {yaml.HeadComment(" static public IPv6 for AAAA/SPF DNS generation; omit until forward and reverse DNS are ready")},
		"$.dns.dmarc_policy":     {yaml.HeadComment(` start with "none"; stage to "quarantine" then "reject" after verifying alignment`)},
		"$.dns.dmarc_report_uri": {yaml.HeadComment(" DMARC aggregate-report URI (rua), for example mailto:dmarc@example.com")},
		"$.dns.tlsrpt_uri":       {yaml.HeadComment(" SMTP TLS reporting URI (separate from DMARC); not proof of outbound TLS quality")},
		"$.dns.spf_includes":     {yaml.HeadComment(" additional SPF include: domains for other legitimate senders")},
		"$.dns.output_file":      {yaml.HeadComment(" generated DNS instructions; relative paths are below data_directory")},

		"$.users": {yaml.HeadComment("\n# SMTP users; password_hash must contain an Argon2id hash, never plaintext")},
	}

	cfg.dataMu.RLock()
	err := yaml.NewEncoder(&buffer, yaml.WithComment(comments), yaml.Indent(2)).Encode(cfg)
	cfg.dataMu.RUnlock()

	if err != nil {
		return nil, err
	}

	body := bytes.ReplaceAll(buffer.Bytes(), []byte("\n#\n"), []byte("\n\n"))

	return body, nil
}

func canonicalUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
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

var reportSizeRE = regexp.MustCompile(`(?i)![0-9]+[kmgt]?$`)

// ExpectedSPF returns the effective policy emitted by DNS generation.
func (cfg *Config) ExpectedSPF() string {
	var b strings.Builder

	b.WriteString("v=spf1")

	if cfg.DNS.PublicIPv4 != "" {
		ip, err := netip.ParseAddr(cfg.DNS.PublicIPv4)
		if err == nil && ip.Is4() {
			fmt.Fprintf(&b, " ip4:%s", ip.String())
		}
	}

	if cfg.DNS.PublicIPv6 != "" {
		fmt.Fprintf(&b, " ip6:%s", cfg.DNS.PublicIPv6)
	}

	for _, include := range cfg.DNS.SPFIncludes {
		fmt.Fprintf(&b, " include:%s", strings.ToLower(strings.TrimSuffix(strings.TrimSpace(include), ".")))
	}

	b.WriteString(" -all")

	return b.String()
}
