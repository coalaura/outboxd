package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/passwd"
)

func TestServeDataDirectoryResolvedAgainstConfig(t *testing.T) {
	// Relative data_directory must resolve next to the config file, not CWD.
	// t.Chdir keeps this test serial with respect to process CWD.
	cfgDir := t.TempDir()
	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	cfgBody := "server:\n  hostname: mail.example.com\n  domain: example.com\n  data_directory: ./data\n" +
		"  max_message_bytes: 1048576\n  max_recipients: 10\n  max_messages_per_hour: 100\n" +
		"  max_recipients_per_hour: 1000\n  read_timeout: 5m\n  write_timeout: 5m\n" +
		"tls:\n  mode: self_signed\n  certificate_file: tls/server.crt\n  private_key_file: tls/server.key\n  minimum_version: \"1.2\"\n" +
		"dkim:\n  selector: mail\n  private_key_file: dkim/mail.key\n  headers: [From]\n" +
		"delivery:\n  tls_mode: opportunistic\n  max_attempts: 5\n  maximum_lifetime: 24h\n" +
		"  initial_retry_delay: 1m\n  maximum_retry_delay: 1h\n  domain_concurrency: 2\n  global_concurrency: 4\n" +
		"  connection_timeout: 30s\n  command_timeout: 2m\n  submission_timeout: 5m\n" +
		"dns:\n  dmarc_policy: none\n  public_ipv4: 203.0.113.10\n  output_file: dns-records.txt\n" +
		"users:\n  - username: alice\n    password_hash: \"" + hash + "\"\n" +
		"    allowed_senders: [\"alice@example.com\"]\n    enabled: true\n"

	cfgPath := filepath.Join(cfgDir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0600); err != nil {
		t.Fatal(err)
	}

	cwd := t.TempDir()
	t.Chdir(cwd)

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Mirror serve: create the resolved data directory (not the raw relative path).
	if err := disk.Mkdir(cfg.ResolvedDataDir()); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(cfgDir, "data")
	if st, err := os.Stat(want); err != nil || !st.IsDir() {
		t.Fatalf("data dir next to config: %v (stat err %v)", want, err)
	}
	stray := filepath.Join(cwd, "data")
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatalf("stray data dir created under CWD %s", stray)
	}
}
