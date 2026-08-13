package config

import "time"

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

type ReplyRejection struct {
	Enabled             bool                      `yaml:"enabled"`
	ListenAddr          string                    `yaml:"listen_addr"`
	UnknownRecipients   string                    `yaml:"unknown_recipients"`
	DefaultMessage      string                    `yaml:"default_message"`
	Domains             []string                  `yaml:"domains"`
	Recipients          []ReplyRejectionRecipient `yaml:"recipients"`
	MaxConnections      int                       `yaml:"max_connections"`
	MaxConnectionsPerIP int                       `yaml:"max_connections_per_ip"`
	ReadTimeout         string                    `yaml:"read_timeout"`
	WriteTimeout        string                    `yaml:"write_timeout"`
}

type ReplyRejectionRecipient struct {
	Address string `yaml:"address"`
	Message string `yaml:"message"`
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

type OpenPGP struct {
	Identities []OpenPGPIdentity `yaml:"identities,omitempty"`
}

type OpenPGPIdentity struct {
	Sender         string `yaml:"sender"`
	SigningKey     string `yaml:"signing_key"`
	PassphraseFile string `yaml:"passphrase_file,omitempty"`
	Signing        string `yaml:"signing"`
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
