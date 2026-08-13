package config

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
)

type resourceBoundaryCase struct {
	name string
	set  func(*Config)
}

type rateBoundaryCase struct {
	name string
	max  int
	set  func(*Config, int)
	zero bool
}

type intBoundaryCase struct {
	name  string
	value int
	valid bool
}

type durationSettingCase struct {
	name string
	max  time.Duration
	set  func(*Config, string)
}

type stringBoundaryCase struct {
	name  string
	value string
	valid bool
}

func writeYAML(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)

	err := os.WriteFile(path, []byte(body), 0600)
	if err != nil {
		t.Fatal(err)
	}

	return path
}

func validUserPHC(t *testing.T) string {
	t.Helper()

	h, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	return h
}

func minimalYAML(dataDir, hash string) string {
	return fmt.Sprintf(`
server:
  hostname: mail.example.com
  domain: example.com
  data_directory: %s
  max_message_bytes: 1048576
  max_recipients: 10
  max_messages_per_hour: 100
  max_recipients_per_hour: 1000
  read_timeout: 5m
  write_timeout: 5m
tls:
  mode: self_signed
  certificate_file: tls/server.crt
  private_key_file: tls/server.key
  minimum_version: "1.2"
dkim:
  selector: mail
  private_key_file: dkim/mail.key
  headers: [From, Sender]
delivery:
  tls_mode: opportunistic
  max_attempts: 5
  maximum_lifetime: 24h
  initial_retry_delay: 1m
  maximum_retry_delay: 1h
  domain_concurrency: 2
  global_concurrency: 4
  connection_timeout: 30s
  command_timeout: 2m
  submission_timeout: 5m
dns:
  dmarc_policy: none
  public_ipv4: 203.0.113.10
  output_file: dns-records.txt
users:
  - username: alice
    password_hash: %q
    allowed_senders: ["alice@example.com"]
    enabled: true
`, filepath.ToSlash(dataDir), hash)
}

func TestOldConfigsGetDefaults(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")

	hash := validUserPHC(t)

	// Omit new fields: max_queue_*, auth_workers, message_burst, disable_*, etc.
	body := fmt.Sprintf(`
server:
  hostname: mail.example.com
  domain: example.com
  data_directory: %s
  max_message_bytes: 1048576
  max_recipients: 10
  max_messages_per_hour: 100
  max_recipients_per_hour: 1000
  read_timeout: 5m
  write_timeout: 5m
tls:
  mode: self_signed
  certificate_file: tls/server.crt
  private_key_file: tls/server.key
  minimum_version: "1.2"
dkim:
  selector: mail
  private_key_file: dkim/mail.key
  headers: [From, Sender]
delivery:
  max_attempts: 5
  maximum_lifetime: 24h
  initial_retry_delay: 1m
  maximum_retry_delay: 1h
  domain_concurrency: 2
  global_concurrency: 4
  connection_timeout: 30s
  command_timeout: 2m
  submission_timeout: 5m
dns:
  dmarc_policy: none
  public_ipv4: 203.0.113.10
users:
  - username: alice
    password_hash: %q
    allowed_senders: ["alice@example.com"]
    enabled: true
`, filepath.ToSlash(data), hash)

	path := writeYAML(t, dir, "config.yml", body)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.MaxConnections != 256 {
		t.Fatalf("MaxConnections default %d", cfg.Server.MaxConnections)
	}

	if cfg.Server.AuthWorkers != 4 {
		t.Fatalf("AuthWorkers %d", cfg.Server.AuthWorkers)
	}

	if cfg.Server.SubmissionAddr != ":587" {
		t.Fatalf("SubmissionAddr %q", cfg.Server.SubmissionAddr)
	}

	if cfg.Server.ImplicitTLSAddr != ":465" {
		t.Fatalf("ImplicitTLSAddr %q", cfg.Server.ImplicitTLSAddr)
	}

	if cfg.Delivery.TLSMode != "required" {
		t.Fatalf("TLSMode %q", cfg.Delivery.TLSMode)
	}

	if cfg.ReplyRejection.Enabled || cfg.ReplyRejection.ListenAddr != ":25" || cfg.ReplyRejection.UnknownRecipients != "listed_only" {
		t.Fatalf("reply rejection defaults: %+v", cfg.ReplyRejection)
	}

	// Defaults from Default() survive for MaxQueue*
	if cfg.Server.MaxQueueMessages != 10000 {
		t.Fatalf("MaxQueueMessages %d", cfg.Server.MaxQueueMessages)
	}

	if cfg.Server.MaxQueueMessagesPerUser != 1000 || cfg.Server.MaxQueueBytesPerUser != 1<<30 {
		t.Fatalf("per-user queue defaults: messages=%d bytes=%d", cfg.Server.MaxQueueMessagesPerUser, cfg.Server.MaxQueueBytesPerUser)
	}

	if cfg.Delivery.UserConcurrency != 2 || cfg.Delivery.DNSTimeout != "30s" || cfg.Delivery.AttemptTimeout != "30m" || cfg.Delivery.MaxMXCandidates != 10 || cfg.Delivery.MaxIPCandidatesPerMX != 8 {
		t.Fatalf("delivery work defaults: %+v", cfg.Delivery)
	}
}

func TestOpenPGPIdentityValidation(t *testing.T) {
	cfg := Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.Users = []User{{Username: "alice", PasswordHash: validUserPHC(t), AllowedSenders: []string{"alice@example.com"}, Enabled: true}}
	cfg.OpenPGP.Identities = []OpenPGPIdentity{{Sender: "Alice@EXAMPLE.com", SigningKey: "openpgp/alice.asc", Signing: "required"}}

	err := cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	if got := cfg.OpenPGP.Identities[0].Sender; got != "Alice@example.com" {
		t.Fatalf("canonical sender = %q", got)
	}

	cfg.OpenPGP.Identities = append(cfg.OpenPGP.Identities, cfg.OpenPGP.Identities[0])

	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate sender") {
		t.Fatalf("duplicate Validate() error = %v", err)
	}

	cfg.OpenPGP.Identities = cfg.OpenPGP.Identities[:1]
	cfg.OpenPGP.Identities[0].Signing = "optional"

	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be required") {
		t.Fatalf("optional Validate() error = %v", err)
	}
}

func TestReplyRejectionValidation(t *testing.T) {
	cfg := Default()

	cfg.ReplyRejection.Enabled = true
	cfg.ReplyRejection.Domains = []string{"Example.COM"}
	cfg.ReplyRejection.Recipients = []ReplyRejectionRecipient{{Address: "noreply@example.com"}}

	cfg.initializeRuntime()

	err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ReplyRejection.Domains[0] != "example.com" {
		t.Fatalf("domain not canonicalized: %q", cfg.ReplyRejection.Domains[0])
	}

	tests := []struct {
		name string
		set  func(*Config)
	}{
		{"no domains", func(c *Config) {
			c.ReplyRejection.Domains = nil
		}},
		{"bad mode", func(c *Config) {
			c.ReplyRejection.UnknownRecipients = "drop"
		}},
		{"outside recipient", func(c *Config) {
			c.ReplyRejection.Recipients[0].Address = "noreply@elsewhere.com"
		}},
		{"response injection", func(c *Config) {
			c.ReplyRejection.DefaultMessage = "No\r\n250 accepted"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := *cfg

			candidate.ReplyRejection = cfg.ReplyRejection
			candidate.ReplyRejection.Domains = append([]string(nil), cfg.ReplyRejection.Domains...)
			candidate.ReplyRejection.Recipients = append([]ReplyRejectionRecipient(nil), cfg.ReplyRejection.Recipients...)

			test.set(&candidate)

			err := candidate.Validate()
			if err == nil {
				t.Fatal("invalid reply rejection configuration accepted")
			}
		})
	}
}

func TestInvalidDurationRelationships(t *testing.T) {
	dir := t.TempDir()

	hash := validUserPHC(t)

	// initial > maximum
	body := minimalYAML(filepath.Join(dir, "d"), hash)

	body = strings.Replace(body, "initial_retry_delay: 1m", "initial_retry_delay: 2h", 1)
	body = strings.Replace(body, "maximum_retry_delay: 1h", "maximum_retry_delay: 30m", 1)

	path := writeYAML(t, dir, "bad1.yml", body)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "initial_retry_delay") {
		t.Fatalf("want initial>max error, got %v", err)
	}

	body2 := minimalYAML(filepath.Join(dir, "d2"), hash)
	body2 = strings.Replace(body2, "maximum_retry_delay: 1h", "maximum_retry_delay: 48h", 1)
	body2 = strings.Replace(body2, "maximum_lifetime: 24h", "maximum_lifetime: 24h", 1)

	path2 := writeYAML(t, dir, "bad2.yml", body2)

	_, err = LoadFile(path2)
	if err == nil || !strings.Contains(err.Error(), "maximum_retry_delay") {
		t.Fatalf("want max>lifetime error, got %v", err)
	}
}

func TestHostilePHCRejected(t *testing.T) {
	dir := t.TempDir()

	good, err := passwd.Hash("x")
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(good, "$")

	// $ argon2id v= m=,t=,p= salt key — inflate memory cost
	hostile := "$" + parts[1] + "$" + parts[2] + "$m=2147483648,t=2,p=1$" + parts[4] + "$" + parts[5]

	body := minimalYAML(filepath.Join(dir, "d"), hostile)
	path := writeYAML(t, dir, "hostile.yml", body)

	_, err = LoadFile(path)
	if err == nil {
		t.Fatal("hostile PHC must fail Validate")
	}
}

func TestIsReadyRequiresEnabledUser(t *testing.T) {
	cfg := Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.1"
	cfg.TLS.AllowSelfSignedServing = true
	cfg.Users = []User{{
		Username:       "alice",
		PasswordHash:   validUserPHC(t),
		AllowedSenders: []string{"alice@example.com"},
		Enabled:        false,
	}}

	err := cfg.IsReady()
	if err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Fatalf("want enabled user error, got %v", err)
	}

	cfg.Users[0].Enabled = true

	err = cfg.IsReady()
	if err != nil {
		t.Fatal(err)
	}
}

func TestExplicitEmptyListenerRemainsDisabled(t *testing.T) {
	dir := t.TempDir()

	body := strings.Replace(minimalYAML(filepath.Join(dir, "data"), validUserPHC(t)), "  data_directory:", "  submission_addr: \"\"\n  implicit_tls_addr: \"127.0.0.1:465\"\n  data_directory:", 1)

	cfg, err := LoadFile(writeYAML(t, dir, "config.yml", body))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.SubmissionAddr != "" || cfg.Server.SubmissionListenAddr() != "" {
		t.Fatalf("explicit empty submission address was defaulted to %q", cfg.Server.SubmissionAddr)
	}
}

func TestDefaultOutboundPolicyFailsClosed(t *testing.T) {
	cfg := Default()

	if cfg.Delivery.TLSMode != "required" || cfg.Delivery.PlaintextAllowed() || cfg.Delivery.InsecureTLSAllowed() || !cfg.Delivery.RequireValidMXTLSCert {
		t.Fatalf("insecure default delivery policy: %+v", cfg.Delivery)
	}
}

func TestSelfSignedServingRequiresExplicitOptIn(t *testing.T) {
	cfg := Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.1"
	cfg.Users = []User{{Enabled: true}}

	err := cfg.IsReady()
	if err == nil || !strings.Contains(err.Error(), "allow_self_signed_serving") {
		t.Fatalf("expected self-signed serving gate, got %v", err)
	}

	cfg.TLS.AllowSelfSignedServing = true

	err = cfg.IsReady()
	if err != nil {
		t.Fatal(err)
	}
}

func TestResourceBoundaries(t *testing.T) {
	if MaxMessageBytes != (DataMemoryBudget-DataMemoryOverhead)/DataMemoryCopies || Default().Server.MaxMessageBytes != 25<<20 {
		t.Fatalf("message limits: maximum=%d default=%d", MaxMessageBytes, Default().Server.MaxMessageBytes)
	}

	tests := []resourceBoundaryCase{
		{"message too large", func(c *Config) { c.Server.MaxMessageBytes = MaxMessageBytes + 1 }},
		{"recipients hard limit", func(c *Config) { c.Server.MaxRecipients = MaxRecipients + 1 }},
		{"attempts", func(c *Config) { c.Delivery.MaxAttempts = MaxDeliveryAttempts + 1 }},
		{"domain concurrency", func(c *Config) { c.Delivery.DomainConcurrency = MaxDomainConcurrency + 1 }},
		{"global concurrency", func(c *Config) { c.Delivery.GlobalConcurrency = MaxGlobalConcurrency + 1 }},
		{"user concurrency", func(c *Config) { c.Delivery.UserConcurrency = MaxUserConcurrency + 1 }},
		{"MX candidates", func(c *Config) { c.Delivery.MaxMXCandidates = MaxMXCandidates + 1 }},
		{"IP candidates", func(c *Config) { c.Delivery.MaxIPCandidatesPerMX = MaxIPCandidatesPerMX + 1 }},
		{"connections", func(c *Config) { c.Server.MaxConnections = MaxConnections + 1 }},
		{"connections per IP", func(c *Config) { c.Server.MaxConnectionsPerIP = MaxConnectionsPerIP + 1 }},
		{"auth workers", func(c *Config) { c.Server.AuthWorkers = MaxAuthWorkers + 1 }},
		{"negative queue messages", func(c *Config) { c.Server.MaxQueueMessages = -1 }},
		{"negative queue bytes", func(c *Config) { c.Server.MaxQueueBytes = -1 }},
		{"missing spool cap", func(c *Config) { c.Server.MaxSpoolBytes = 0 }},
		{"missing emergency reserve", func(c *Config) { c.Server.SpoolEmergencyBytes = 0 }},
		{"undersized emergency reserve", func(c *Config) { c.Server.SpoolEmergencyBytes = queue.MinimumSpoolEmergencyBytes - 1 }},
		{"emergency consumes spool", func(c *Config) { c.Server.SpoolEmergencyBytes = c.Server.MaxSpoolBytes }},
		{"zero dead retention", func(c *Config) { c.Server.DeadRetention = "0s" }},
		{"zero corrupt retention", func(c *Config) { c.Server.CorruptRetention = "0s" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()

			tt.set(cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}

	err := Default().Validate()
	if err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}

	max := Default()

	max.Server.MaxMessageBytes = MaxMessageBytes
	max.Server.MaxRecipients = MaxRecipients
	max.Server.MaxConnections = MaxConnections
	max.Server.MaxConnectionsPerIP = MaxConnectionsPerIP
	max.Server.AuthWorkers = MaxAuthWorkers
	max.Delivery.MaxAttempts = MaxDeliveryAttempts
	max.Delivery.DomainConcurrency = MaxDomainConcurrency
	max.Delivery.GlobalConcurrency = MaxGlobalConcurrency
	max.Delivery.UserConcurrency = MaxUserConcurrency
	max.Delivery.MaxMXCandidates = MaxMXCandidates
	max.Delivery.MaxIPCandidatesPerMX = MaxIPCandidatesPerMX

	err = max.Validate()
	if err != nil {
		t.Fatalf("inclusive maximum boundaries invalid: %v", err)
	}
}

func TestRateAndBurstBoundaries(t *testing.T) {
	maxInt := int(^uint(0) >> 1)

	tests := []rateBoundaryCase{
		{"message rate", MaxMessagesPerHour, func(c *Config, value int) {
			c.Server.MaxMessagesPerHour = value
		}, false},
		{"recipient rate", MaxRecipientsPerHour, func(c *Config, value int) {
			c.Server.MaxRecipientsPerHour = value
		}, false},
		{"message burst", MaxMessageBurst, func(c *Config, value int) {
			c.Server.MaxMessagesPerHour = MaxMessagesPerHour
			c.Server.MessageBurst = value
		}, true},
		{"recipient burst", MaxRecipientBurst, func(c *Config, value int) {
			c.Server.MaxRecipientsPerHour = MaxRecipientsPerHour
			c.Server.RecipientBurst = value
		}, true},
	}

	for _, tt := range tests {
		for _, boundary := range []intBoundaryCase{
			{"negative", -1, false},
			{"zero", 0, tt.zero},
			{"maximum", tt.max, true},
			{"maximum plus one", tt.max + 1, false},
			{"integer maximum", maxInt, false},
		} {
			t.Run(tt.name+"/"+boundary.name, func(t *testing.T) {
				cfg := Default()

				tt.set(cfg, boundary.value)

				err := cfg.Validate()
				if (err == nil) != boundary.valid {
					t.Fatalf("value=%d valid=%v err=%v", boundary.value, boundary.valid, err)
				}
			})
		}
	}
}

func TestDeliveryAttemptBoundaries(t *testing.T) {
	for _, tt := range []intBoundaryCase{
		{"negative", -1, false},
		{"zero", 0, false},
		{"maximum", MaxDeliveryAttempts, true},
		{"maximum plus one", MaxDeliveryAttempts + 1, false},
		{"integer maximum", int(^uint(0) >> 1), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()

			cfg.Delivery.MaxAttempts = tt.value

			err := cfg.Validate()
			if (err == nil) != tt.valid {
				t.Fatalf("value=%d valid=%v err=%v", tt.value, tt.valid, err)
			}
		})
	}
}

func TestDurationBoundaries(t *testing.T) {
	tests := []durationSettingCase{
		{"server read", MaxSMTPReadTimeout, func(c *Config, value string) {
			c.Server.ReadTimeout = value
		}},
		{"server write", MaxSMTPWriteTimeout, func(c *Config, value string) {
			c.Server.WriteTimeout = value
		}},
		{"dead retention", MaxDeadRetention, func(c *Config, value string) {
			c.Server.DeadRetention = value
		}},
		{"corrupt retention", MaxCorruptRetention, func(c *Config, value string) {
			c.Server.CorruptRetention = value
		}},
		{"delivery lifetime", MaxDeliveryLifetime, func(c *Config, value string) {
			c.Delivery.MaximumLifetime = value
		}},
		{"initial retry", MaxInitialRetryDelay, func(c *Config, value string) {
			c.Delivery.InitialRetryDelay = value
			c.Delivery.MaximumRetryDelay = MaxInitialRetryDelay.String()
		}},
		{"maximum retry", MaxRetryDelay, func(c *Config, value string) {
			c.Delivery.MaximumRetryDelay = value
			c.Delivery.MaximumLifetime = MaxRetryDelay.String()
		}},
		{"delivery DNS", MaxDeliveryDNSTimeout, func(c *Config, value string) {
			c.Delivery.DNSTimeout = value
		}},
		{"delivery attempt", MaxDeliveryAttemptTimeout, func(c *Config, value string) {
			c.Delivery.AttemptTimeout = value
		}},
		{"delivery connection", MaxDeliveryConnectionTimeout, func(c *Config, value string) {
			c.Delivery.ConnectionTimeout = value
		}},
		{"delivery command", MaxDeliveryCommandTimeout, func(c *Config, value string) {
			c.Delivery.CommandTimeout = value
		}},
		{"delivery submission", MaxDeliverySubmissionTimeout, func(c *Config, value string) {
			c.Delivery.SubmissionTimeout = value
			c.Delivery.AttemptTimeout = MaxDeliverySubmissionTimeout.String()
		}},
	}

	for _, tt := range tests {
		for _, boundary := range []stringBoundaryCase{
			{"negative", "-1ns", false},
			{"zero", "0s", false},
			{"maximum", tt.max.String(), true},
			{"maximum plus one", (tt.max + time.Nanosecond).String(), false},
			{"overflow adjacent", "2562048h", false},
		} {
			t.Run(tt.name+"/"+boundary.name, func(t *testing.T) {
				cfg := Default()

				tt.set(cfg, boundary.value)

				err := cfg.Validate()
				if (err == nil) != boundary.valid {
					t.Fatalf("value=%q valid=%v err=%v", boundary.value, boundary.valid, err)
				}
			})
		}
	}
}

func TestResourceRelationships(t *testing.T) {
	tests := []resourceBoundaryCase{
		{"message burst exceeds rate", func(c *Config) {
			c.Server.MaxMessagesPerHour = 10
			c.Server.MessageBurst = 11
		}},
		{"recipient burst exceeds rate", func(c *Config) {
			c.Server.MaxRecipientsPerHour = 10
			c.Server.RecipientBurst = 11
		}},
		{"submission shorter than command", func(c *Config) {
			c.Delivery.CommandTimeout = "2m"
			c.Delivery.SubmissionTimeout = "1m"
		}},
		{"DNS exceeds attempt", func(c *Config) {
			c.Delivery.DNSTimeout = "2m"
			c.Delivery.AttemptTimeout = "1m"
		}},
		{"submission exceeds attempt", func(c *Config) {
			c.Delivery.SubmissionTimeout = "10m"
			c.Delivery.AttemptTimeout = "5m"
		}},
		{"connection longer than command", func(c *Config) {
			c.Delivery.ConnectionTimeout = "2m"
			c.Delivery.CommandTimeout = "1m"
		}},
		{"connection exceeds lifetime", func(c *Config) {
			c.Delivery.MaximumLifetime = "1m"
			c.Delivery.InitialRetryDelay = "1s"
			c.Delivery.MaximumRetryDelay = "1s"
			c.Delivery.ConnectionTimeout = "2m"
			c.Delivery.CommandTimeout = "1m"
			c.Delivery.SubmissionTimeout = "1m"
		}},
		{"command exceeds lifetime", func(c *Config) {
			c.Delivery.MaximumLifetime = "1m"
			c.Delivery.InitialRetryDelay = "1s"
			c.Delivery.MaximumRetryDelay = "1s"
			c.Delivery.CommandTimeout = "2m"
			c.Delivery.SubmissionTimeout = "2m"
		}},
		{"submission exceeds lifetime", func(c *Config) {
			c.Delivery.MaximumLifetime = "1m"
			c.Delivery.InitialRetryDelay = "1s"
			c.Delivery.MaximumRetryDelay = "1s"
			c.Delivery.CommandTimeout = "1m"
			c.Delivery.SubmissionTimeout = "2m"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()

			tt.set(cfg)

			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestIPv4FieldsRejectMappedIPv6(t *testing.T) {
	for _, set := range []func(*Config){
		func(cfg *Config) { cfg.DNS.PublicIPv4 = "::ffff:192.0.2.1" },
		func(cfg *Config) { cfg.Delivery.BindIPv4 = "::ffff:192.0.2.1" },
	} {
		cfg := Default()

		set(cfg)

		err := cfg.Validate()
		if err == nil {
			t.Fatal("IPv4-mapped IPv6 accepted as IPv4")
		}
	}
}

func TestConfigReadLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")

	err := os.WriteFile(path, make([]byte, maxConfigFileBytes+1), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("oversized config error=%v", err)
	}
}

func TestAuthWorkerMemoryBound(t *testing.T) {
	if MaxAuthWorkers != 8 {
		t.Fatalf("MaxAuthWorkers=%d want 8", MaxAuthWorkers)
	}

	got := int64(MaxAuthWorkers) * 19 << 20
	if got > 152<<20 {
		t.Fatalf("maximum Argon2 worker memory=%d", got)
	}
}

func TestGeneratedAuthCommentsDocumentAuditedBounds(t *testing.T) {
	cfg := Default()

	cfg.initializeRuntime()

	data, err := cfg.marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"19 MiB each; maximum 8, 152 MiB total",
		"migration hashes must use m=19456,t=2,p=1, a 16-byte salt, and a 32-byte output",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatalf("generated configuration does not document %q", want)
		}
	}
}

func TestAdoptIncludesReplyRejection(t *testing.T) {
	cfg := Default()

	cfg.initializeRuntime()

	other := Default()

	other.ReplyRejection.Enabled = true
	other.ReplyRejection.Domains = []string{"example.com"}
	other.ReplyRejection.Recipients = []ReplyRejectionRecipient{{Address: "noreply@example.com"}}

	cfg.adopt(other)

	if !cfg.ReplyRejection.Enabled || len(cfg.ReplyRejection.Domains) != 1 || cfg.ReplyRejection.Domains[0] != "example.com" || len(cfg.ReplyRejection.Recipients) != 1 || cfg.ReplyRejection.Recipients[0].Address != "noreply@example.com" {
		t.Fatalf("reply rejection not adopted: %+v", cfg.ReplyRejection)
	}
}

func TestSupportedMaximaAggregateBound(t *testing.T) {
	data := MaxMessageBytes*DataMemoryCopies + DataMemoryOverhead
	if data > DataMemoryBudget {
		t.Fatalf("single DATA worker memory=%d exceeds %d", data, DataMemoryBudget)
	}

	// Connections dominate descriptors/goroutines; delivery may run four attempt
	// goroutines per global MX slot.
	concurrent := MaxConnections + MaxGlobalConcurrency*4 + MaxAuthWorkers + MaxDataWorkers
	if concurrent > 5000 {
		t.Fatalf("aggregate concurrent maximum=%d", concurrent)
	}

	if MaxDeliveryAttempts > 100 {
		t.Fatalf("delivery attempts maximum=%d", MaxDeliveryAttempts)
	}
}

func TestAuthQueueRejected(t *testing.T) {
	dir := t.TempDir()

	body := strings.Replace(minimalYAML(filepath.Join(dir, "data"), validUserPHC(t)), "  data_directory:", "  auth_queue: 8\n  data_directory:", 1)

	_, err := LoadFile(writeYAML(t, dir, "config.yml", body))
	if err == nil {
		t.Fatal("obsolete auth_queue field was accepted")
	}
}

func TestReportURIValidation(t *testing.T) {
	valid := []string{"mailto:reports@example.com", "mailto:ops!alerts@example.com", "mailto:a@example.com!0m", "mailto:a@example.com!10m, https://reports.example.com/v1", "https://reports.example.com/path!segment", "https://reports.example.com/path!12x", "https://[2001:db8::1]:443/report"}
	invalid := []string{"mailto:Display <a@example.com>", "mailto:a@example.com,", "mailto:a@example.com!10x", "mailto:a@", "https:///report", "https://-bad.example/report", "https://user@example.com/report", "ftp://example.com/report"}

	for _, value := range valid {
		err := ValidateDMARCReportURIList(value)
		if err != nil {
			t.Errorf("valid %q: %v", value, err)
		}
	}

	for _, value := range invalid {
		err := ValidateDMARCReportURIList(value)
		if err == nil {
			t.Errorf("invalid URI accepted: %q", value)
		}
	}

	err := ValidateTLSReportURIList("https://reports.example.com/path!10m")
	if err != nil {
		t.Fatalf("TLS-RPT URI with literal path bang: %v", err)
	}

	err = ValidateTLSReportURIList("mailto:a@example.com!10m")
	if err == nil {
		t.Fatal("TLS-RPT accepted a DMARC size suffix")
	}
}

func TestSPFLookupBudget(t *testing.T) {
	cfg := Default()

	for i := 0; i <= SPFDNSLookupLimit; i++ {
		cfg.DNS.SPFIncludes = append(cfg.DNS.SPFIncludes, fmt.Sprintf("spf%d.example.com", i))
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "lookup limit") {
		t.Fatalf("expected SPF budget error, got %v", err)
	}
}

func TestGeneratedPathsConfined(t *testing.T) {
	dir := t.TempDir()

	cfg := Default()

	cfg.Server.DataDirectory = filepath.Join(dir, "data")

	inside := filepath.Join(cfg.Server.DataDirectory, "keys", "mail.key")

	for _, path := range []string{"../escape", filepath.Join(dir, "outside"), cfg.Server.DataDirectory, "C:\\outside\\mail.key"} {
		if runtime.GOOS != "windows" && strings.HasPrefix(path, "C:") {
			continue
		}

		_, err := cfg.ResolveGeneratedPath(path)
		if err == nil {
			t.Errorf("accepted escaping/generated-directory path %q", path)
		}
	}

	got, err := cfg.ResolveGeneratedPath(inside)
	if err != nil || filepath.Clean(got) != filepath.Clean(inside) {
		t.Fatalf("inside path: got %q err %v", got, err)
	}

	// TLS remains operator-managed and may be absolute outside data_directory.
	got = cfg.ResolvePath(filepath.Join(dir, "operator", "tls.key"))
	if got == "" {
		t.Fatal("absolute TLS path unexpectedly rejected")
	}
}

func TestConcurrentSubprocessAddUser(t *testing.T) {
	if os.Getenv("OUTBOXD_ADD_USER_CHILD") != "" {
		cfg, err := LoadFile(os.Getenv("OUTBOXD_TEST_CONFIG"))
		if err == nil {
			err = cfg.AddUser(User{Username: os.Getenv("OUTBOXD_TEST_USER"), PasswordHash: os.Getenv("OUTBOXD_TEST_HASH"), AllowedSenders: []string{os.Getenv("OUTBOXD_TEST_USER") + "@example.com"}, Enabled: true})
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	dir := t.TempDir()

	hash := validUserPHC(t)

	path := writeYAML(t, dir, "config.yml", minimalYAML(filepath.Join(dir, "data"), hash))

	commands := make([]*exec.Cmd, 2)
	outputs := make([]bytes.Buffer, 2)

	for i, username := range []string{"bob", "carol"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConcurrentSubprocessAddUser$")

		cmd.Env = append(os.Environ(), "OUTBOXD_ADD_USER_CHILD=1", "OUTBOXD_TEST_CONFIG="+path, "OUTBOXD_TEST_USER="+username, "OUTBOXD_TEST_HASH="+hash)

		commands[i] = cmd

		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]

		err := cmd.Start()
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, cmd := range commands {
		err := cmd.Wait()
		if err != nil {
			t.Fatalf("child failed: %v", err)
		}
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, username := range []string{"alice", "bob", "carol"} {
		_, ok := cfg.User(username)
		if !ok {
			t.Fatalf("concurrent update lost user %q", username)
		}
	}
}

func TestAddUserAtomicAndDuplicateCaseInsens(t *testing.T) {
	dir := t.TempDir()

	hash := validUserPHC(t)

	path := writeYAML(t, dir, "config.yml", minimalYAML(filepath.Join(dir, "data"), hash))

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Duplicate case-insensitive
	err = cfg.AddUser(User{
		Username: "Alice", PasswordHash: hash,
		AllowedSenders: []string{"other@example.com"}, Enabled: true,
	})

	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate, got %v", err)
	}

	// Successful add
	err = cfg.AddUser(User{
		Username: "bob", PasswordHash: hash,
		AllowedSenders: []string{"bob@example.com"}, Enabled: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Reload should see bob
	cfg2, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := cfg2.User("bob")
	if !ok {
		t.Fatal("bob not persisted")
	}

	// Failed add must not leave partial user permanently
	before := len(cfg2.Users)

	err = cfg2.AddUser(User{
		Username: "bad", PasswordHash: "not-a-hash",
		AllowedSenders: []string{"bad@example.com"}, Enabled: true,
	})

	if err == nil {
		t.Fatal("expected AddUser error")
	}

	if len(cfg2.Users) != before {
		t.Fatal("AddUser not atomic on failure")
	}
}

func TestResolvePathRelativeToConfigDir(t *testing.T) {
	dir := t.TempDir()

	hash := validUserPHC(t)

	dataRel := "rel-data"
	path := writeYAML(t, dir, "config.yml", minimalYAML(dataRel, hash))

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got := cfg.ResolvePath("tls/server.crt")
	want := filepath.Join(dir, dataRel, "tls", "server.crt")

	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("ResolvePath=%q want %q", got, want)
	}
}

func TestLoadFileMultiDocRejected(t *testing.T) {
	dir := t.TempDir()

	hash := validUserPHC(t)

	body := minimalYAML(filepath.Join(dir, "d"), hash) + "\n---\nserver:\n  hostname: x\n"

	path := writeYAML(t, dir, "multi.yml", body)

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("want multi-doc rejection")
	} else if !strings.Contains(err.Error(), "multiple YAML") && !strings.Contains(err.Error(), "trailing YAML") {
		t.Fatalf("want multi-doc/trailing rejection, got %v", err)
	}
}

func TestValidatePHCViaUser(t *testing.T) {
	cfg := Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"

	cfg.initializeRuntime()

	// Good user
	h := validUserPHC(t)

	cfg.Users = []User{{
		Username: "a", PasswordHash: h,
		AllowedSenders: []string{"a@example.com"}, Enabled: true,
	}}

	err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidatePrefixedPHCViaUser(t *testing.T) {
	cfg := Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"

	cfg.initializeRuntime()

	hash := validUserPHC(t)

	cfg.Users = []User{{
		Username: "a", PasswordHash: "{ARGON2ID}" + hash,
		AllowedSenders: []string{"a@example.com"}, Enabled: true,
	}}

	err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDKIMHeadersRequireSender(t *testing.T) {
	cfg := Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DKIM.Headers = []string{"From"}

	cfg.initializeRuntime()

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must contain Sender") {
		t.Fatalf("err=%v", err)
	}
}
