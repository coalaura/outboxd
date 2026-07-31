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

	"github.com/coalaura/outboxd/internal/passwd"
)

func writeYAML(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
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
  headers: [From]
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
  headers: [From]
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
	// Defaults from Default() survive for MaxQueue*
	if cfg.Server.MaxQueueMessages != 10000 {
		t.Fatalf("MaxQueueMessages %d", cfg.Server.MaxQueueMessages)
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
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "initial_retry_delay") {
		t.Fatalf("want initial>max error, got %v", err)
	}

	body2 := minimalYAML(filepath.Join(dir, "d2"), hash)
	body2 = strings.Replace(body2, "maximum_retry_delay: 1h", "maximum_retry_delay: 48h", 1)
	body2 = strings.Replace(body2, "maximum_lifetime: 24h", "maximum_lifetime: 24h", 1)
	path2 := writeYAML(t, dir, "bad2.yml", body2)
	if _, err := LoadFile(path2); err == nil || !strings.Contains(err.Error(), "maximum_retry_delay") {
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
	if _, err := LoadFile(path); err == nil {
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
		Username: "alice", PasswordHash: validUserPHC(t),
		AllowedSenders: []string{"alice@example.com"}, Enabled: false,
	}}
	if err := cfg.IsReady(); err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Fatalf("want enabled user error, got %v", err)
	}
	cfg.Users[0].Enabled = true
	if err := cfg.IsReady(); err != nil {
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
	if err := cfg.IsReady(); err == nil || !strings.Contains(err.Error(), "allow_self_signed_serving") {
		t.Fatalf("expected self-signed serving gate, got %v", err)
	}
	cfg.TLS.AllowSelfSignedServing = true
	if err := cfg.IsReady(); err != nil {
		t.Fatal(err)
	}
}

func TestResourceBoundaries(t *testing.T) {
	if MaxMessageBytes != 100<<20 || Default().Server.MaxMessageBytes != 25<<20 {
		t.Fatalf("message limits: maximum=%d default=%d", MaxMessageBytes, Default().Server.MaxMessageBytes)
	}
	tests := []struct {
		name string
		set  func(*Config)
	}{
		{"message too large", func(c *Config) { c.Server.MaxMessageBytes = MaxMessageBytes + 1 }},
		{"recipients hard limit", func(c *Config) { c.Server.MaxRecipients = MaxRecipients + 1 }},
		{"attempts", func(c *Config) { c.Delivery.MaxAttempts = MaxDeliveryAttempts + 1 }},
		{"domain concurrency", func(c *Config) { c.Delivery.DomainConcurrency = MaxDomainConcurrency + 1 }},
		{"global concurrency", func(c *Config) { c.Delivery.GlobalConcurrency = MaxGlobalConcurrency + 1 }},
		{"connections", func(c *Config) { c.Server.MaxConnections = MaxConnections + 1 }},
		{"connections per IP", func(c *Config) { c.Server.MaxConnectionsPerIP = MaxConnectionsPerIP + 1 }},
		{"auth workers", func(c *Config) { c.Server.AuthWorkers = MaxAuthWorkers + 1 }},
		{"negative queue messages", func(c *Config) { c.Server.MaxQueueMessages = -1 }},
		{"negative queue bytes", func(c *Config) { c.Server.MaxQueueBytes = -1 }},
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
	if err := Default().Validate(); err != nil {
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
	if err := max.Validate(); err != nil {
		t.Fatalf("inclusive maximum boundaries invalid: %v", err)
	}
}

func TestAuthWorkerMemoryBound(t *testing.T) {
	if MaxAuthWorkers != 16 {
		t.Fatalf("MaxAuthWorkers=%d want 16", MaxAuthWorkers)
	}
	if got := int64(MaxAuthWorkers) * 19 << 20; got > 304<<20 {
		t.Fatalf("maximum Argon2 worker memory=%d", got)
	}
}

func TestAuthQueueRejected(t *testing.T) {
	dir := t.TempDir()
	body := strings.Replace(minimalYAML(filepath.Join(dir, "data"), validUserPHC(t)), "  data_directory:", "  auth_queue: 8\n  data_directory:", 1)
	if _, err := LoadFile(writeYAML(t, dir, "config.yml", body)); err == nil {
		t.Fatal("obsolete auth_queue field was accepted")
	}
}

func TestReportURIValidation(t *testing.T) {
	valid := []string{"mailto:reports@example.com", "mailto:ops!alerts@example.com", "mailto:a@example.com!0m", "mailto:a@example.com!10m, https://reports.example.com/v1", "https://reports.example.com/path!segment", "https://reports.example.com/path!12x", "https://[2001:db8::1]:443/report"}
	invalid := []string{"mailto:Display <a@example.com>", "mailto:a@example.com,", "mailto:a@example.com!10x", "mailto:a@", "https:///report", "https://-bad.example/report", "https://user@example.com/report", "ftp://example.com/report"}
	for _, value := range valid {
		if err := ValidateDMARCReportURIList(value); err != nil {
			t.Errorf("valid %q: %v", value, err)
		}
	}
	for _, value := range invalid {
		if err := ValidateDMARCReportURIList(value); err == nil {
			t.Errorf("invalid URI accepted: %q", value)
		}
	}
	if err := ValidateTLSReportURIList("https://reports.example.com/path!10m"); err != nil {
		t.Fatalf("TLS-RPT URI with literal path bang: %v", err)
	}
	if err := ValidateTLSReportURIList("mailto:a@example.com!10m"); err == nil {
		t.Fatal("TLS-RPT accepted a DMARC size suffix")
	}
}

func TestSPFLookupBudget(t *testing.T) {
	cfg := Default()
	for i := 0; i <= SPFDNSLookupLimit; i++ {
		cfg.DNS.SPFIncludes = append(cfg.DNS.SPFIncludes, fmt.Sprintf("spf%d.example.com", i))
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "lookup limit") {
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
		if _, err := cfg.ResolveGeneratedPath(path); err == nil {
			t.Errorf("accepted escaping/generated-directory path %q", path)
		}
	}
	if got, err := cfg.ResolveGeneratedPath(inside); err != nil || filepath.Clean(got) != filepath.Clean(inside) {
		t.Fatalf("inside path: got %q err %v", got, err)
	}
	// TLS remains operator-managed and may be absolute outside data_directory.
	if got := cfg.ResolvePath(filepath.Join(dir, "operator", "tls.key")); got == "" {
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
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child failed: %v", err)
		}
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"alice", "bob", "carol"} {
		if _, ok := cfg.User(username); !ok {
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
	if _, ok := cfg2.User("bob"); !ok {
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
	if _, err := LoadFile(path); err == nil {
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
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
