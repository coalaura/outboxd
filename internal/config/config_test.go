package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// Omit new fields: max_queue_*, auth_*, message_burst, disable_*, etc.
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
	if cfg.Delivery.TLSMode != "opportunistic" {
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
	salt := passwdEncoding()
	// reuse validate path via config
	hostile := "$argon2id$v=19$m=2147483648,t=2,p=1$" + salt + "$" + salt + salt
	body := minimalYAML(filepath.Join(dir, "d"), hostile)
	// fix hash - Build larger key
	key := strings.Repeat("A", 43) // 32 bytes b64 raw
	_ = key
	// Use passwd package properly
	// Construct via fmt with valid b64 of correct size then patch m=
	good, _ := passwd.Hash("x")
	// swap m= to huge
	parts := strings.Split(good, "$")
	// $ argon2id v= m=,t=,p= salt key
	params := parts[3]
	params = "m=2147483648,t=2,p=1"
	hostile = "$" + parts[1] + "$" + parts[2] + "$" + params + "$" + parts[4] + "$" + parts[5]
	body = minimalYAML(filepath.Join(dir, "d"), hostile)
	path := writeYAML(t, dir, "hostile.yml", body)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("hostile PHC must fail Validate")
	}
}

// passwdEncoding helper — salt from a real hash
func passwdEncoding() string {
	h, _ := passwd.Hash("z")
	parts := strings.Split(h, "$")
	return parts[4]
}

func TestIsReadyRequiresEnabledUser(t *testing.T) {
	cfg := Default()
	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.1"
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

var _ = errors.New
