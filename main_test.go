package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
)

type versionInput struct {
	flag bool
	args []string
}

func TestVersionCLI(t *testing.T) {
	original := Version
	Version = "v1.2.3"

	t.Cleanup(func() {
		Version = original
	})

	for name, input := range map[string]versionInput{
		"flag":    {flag: true},
		"command": {args: []string{"version"}},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer

			handled, err := handleVersion(input.flag, input.args, &output)
			if err != nil {
				t.Fatal(err)
			}

			if !handled {
				t.Fatal("version invocation was not handled")
			}

			if got := output.String(); got != "v1.2.3\n" {
				t.Fatalf("version output=%q", got)
			}
		})
	}

	var output bytes.Buffer

	handled, err := handleVersion(false, []string{"user", "list"}, &output)
	if err != nil || handled || output.Len() != 0 {
		t.Fatalf("normal command handled=%v err=%v output=%q", handled, err, output.String())
	}
}

func TestParseGlobalVersionFlagPreservesCommands(t *testing.T) {
	configPath, showVersion, args := parseGlobalFlags([]string{"--config", "custom.yml", "user", "list"})
	if configPath != "custom.yml" || showVersion || strings.Join(args, " ") != "user list" {
		t.Fatalf("normal flags parsed as config=%q version=%v args=%q", configPath, showVersion, args)
	}

	configPath, showVersion, args = parseGlobalFlags([]string{"--config", "custom.yml", "--version"})
	if configPath != "custom.yml" || !showVersion || len(args) != 0 {
		t.Fatalf("version flags parsed as config=%q version=%v args=%q", configPath, showVersion, args)
	}
}

func TestConfigUpdatePreservesValuesAndAddsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	body := "# operator comment\n" +
		"server:\n  hostname: mail.example.com\n  domain: example.com\n  data_directory: ./state\n" +
		"tls:\n  mode: files\n  certificate_file: cert.pem\n  private_key_file: key.pem\n  minimum_version: \"1.3\"\n" +
		"dkim:\n  selector: outbound\n  private_key_file: dkim.key\n  headers: [From]\n" +
		"delivery:\n  tls_mode: required\n" +
		"dns:\n  dmarc_policy: reject\n  public_ipv4: 203.0.113.10\n" +
		"users:\n  - username: alice\n    password_hash: \"" + hash + "\"\n" +
		"    allowed_senders: [\"alice@example.com\"]\n    enabled: true\n"

	err = os.WriteFile(path, []byte(body), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = configCommand(path, []string{"update"})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if updated.Server.Hostname != "mail.example.com" || updated.Server.DataDirectory != "./state" {
		t.Fatalf("server values changed: %+v", updated.Server)
	}

	if updated.TLS.Mode != "files" || updated.TLS.MinimumVersion != "1.3" || updated.DKIM.Selector != "outbound" {
		t.Fatalf("signing or TLS values changed: tls=%+v dkim=%+v", updated.TLS, updated.DKIM)
	}

	if updated.DNS.DMARC != "reject" || updated.Server.MaxConnections != config.Default().Server.MaxConnections {
		t.Fatalf("configured/default values not retained: dns=%+v server=%+v", updated.DNS, updated.Server)
	}

	rewritten, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"reply_rejection:", "max_connections:", "openpgp:", "identities: []"} {
		if !bytes.Contains(rewritten, []byte(field)) {
			t.Fatalf("updated config missing %q", field)
		}
	}
}

func TestConfigUpdateRequiresExistingValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	err := configCommand(path, []string{"update"})
	if err == nil {
		t.Fatal("config update created a missing config")
	}

	for _, candidate := range []string{path, path + ".lock"} {
		if _, statErr := os.Stat(candidate); !os.IsNotExist(statErr) {
			t.Fatalf("config update created %s: %v", candidate, statErr)
		}
	}

	err = os.WriteFile(path, []byte("unknown: true\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = configCommand(path, []string{"update"})
	if err == nil {
		t.Fatal("config update accepted invalid config")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(after, before) {
		t.Fatal("failed config update rewrote the config")
	}
}

func TestConfigCommandRequiresExactArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"update", "extra"}, {"unknown"}} {
		err := configCommand("unused.yml", args)
		if err == nil || err.Error() != "usage: outboxd config update" {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
}

func TestServeDataDirectoryResolvedAgainstConfig(t *testing.T) {
	// Relative data_directory must resolve next to the config file, not CWD.
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

	err = os.WriteFile(cfgPath, []byte(cfgBody), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cwd := t.TempDir()
	t.Chdir(cwd)

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Mirror serve: create the resolved data directory (not the raw relative path).
	err = disk.Mkdir(cfg.ResolvedDataDir())
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(cfgDir, "data")

	st, err := os.Stat(want)
	if err != nil || !st.IsDir() {
		t.Fatalf("data dir next to config: %v (stat err %v)", want, err)
	}

	stray := filepath.Join(cwd, "data")

	_, err = os.Stat(stray)
	if !os.IsNotExist(err) {
		t.Fatalf("stray data dir created under CWD %s", stray)
	}
}

func TestRunCheckDoesNotGenerateMissingDKIMKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.10"
	cfg.TLS.AllowSelfSignedServing = true
	cfg.Users = []config.User{
		{
			Username:       "alice",
			PasswordHash:   hash,
			AllowedSenders: []string{"alice@example.com"},
			Enabled:        true,
		},
	}

	err = cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	keyPath, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	err = runCheck(path)
	if err == nil || !strings.Contains(err.Error(), "DKIM") {
		t.Fatalf("missing DKIM key must fail check, got %v", err)
	}

	_, err = os.Stat(keyPath)
	if !os.IsNotExist(err) {
		t.Fatalf("check generated DKIM key: %v", err)
	}
}

func TestRunCheckRejectsUnassignedDeliveryBindAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.10"
	cfg.TLS.AllowSelfSignedServing = true
	cfg.Users = []config.User{
		{
			Username:       "alice",
			PasswordHash:   hash,
			AllowedSenders: []string{"alice@example.com"},
			Enabled:        true,
		},
	}
	cfg.Delivery.BindIPv4 = "192.0.2.123"

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	err = runCheck(path)
	if err == nil || !strings.Contains(err.Error(), "delivery bind address 192.0.2.123 is not configured") {
		t.Fatalf("runCheck error=%v, want unassigned bind-address error", err)
	}
}

func TestOperationsRejectLinkedDataDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "external")

	err := os.Mkdir(target, 0700)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(target, cfg.ResolvedDataDir())
	if err != nil {
		t.Skipf("cannot create test data-directory link: %v", err)
	}

	for name, operation := range map[string]func(string) error{
		"provision": provision,
		"dns":       dns,
	} {
		t.Run(name, func(t *testing.T) {
			err := operation(path)
			if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
				t.Fatalf("%s error=%v, want linked data-directory rejection", name, err)
			}
		})
	}

	for _, path := range []string{"queue", cfg.DKIM.PrivateKeyFile, cfg.DNS.OutputFile} {
		if _, err := os.Lstat(filepath.Join(target, path)); !os.IsNotExist(err) {
			t.Fatalf("operation created output below linked data directory %s: %v", path, err)
		}
	}
}

func TestProvisionCreatesDKIMKeyOnce(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")

	err := provision(configPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	keyPath, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("first provision must stop after creating config: %v", err)
	}

	err = provision(configPath)
	if err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	err = provision(configPath)
	if err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(after) != string(before) {
		t.Fatal("repeated provision replaced DKIM identity")
	}
}

func TestServeDoesNotGenerateMissingDKIMKeyOrReplaceDNS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.10"
	cfg.TLS.AllowSelfSignedServing = true
	cfg.Users = []config.User{{Username: "alice", PasswordHash: hash, AllowedSenders: []string{"alice@example.com"}, Enabled: true}}

	err = cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	dnsPath, err := cfg.ResolveGeneratedPath(cfg.DNS.OutputFile)
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Write(dnsPath, []byte("published identity\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	keyPath, err := cfg.ResolveGeneratedPath(cfg.DKIM.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	err = serve(path)
	if err == nil || !strings.Contains(err.Error(), "DKIM") {
		t.Fatalf("serve with missing DKIM key error=%v", err)
	}

	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("serve generated missing DKIM key: %v", err)
	}

	if info, statErr := os.Stat(path + ".outboxd.lock"); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("serve did not create regular ownership lock: info=%v err=%v", info, statErr)
	}

	body, err := os.ReadFile(dnsPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "published identity\n" {
		t.Fatalf("serve replaced DNS output: %q", body)
	}
}

func TestServeMissingConfigDoesNotCreateIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yml")

	err := serve(path)
	if err == nil {
		t.Fatal("serve with missing config succeeded")
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("serve created missing config: %v", statErr)
	}

	if _, statErr := os.Stat(path + ".outboxd.lock"); !os.IsNotExist(statErr) {
		t.Fatalf("serve created ownership lock for missing config: %v", statErr)
	}
}

func TestRunCheckMissingTLSDoesNotMutateFilesystem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	cfg, _, err := config.EnsurePath(path)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := passwd.Hash("test-password-123")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.Domain = "example.com"
	cfg.DNS.PublicIPv4 = "203.0.113.10"
	cfg.TLS.AllowSelfSignedServing = true
	cfg.Users = []config.User{
		{
			Username:       "alice",
			PasswordHash:   hash,
			AllowedSenders: []string{"alice@example.com"},
			Enabled:        true,
		},
	}

	err = cfg.Init()
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Mkdir(cfg.ResolvedDataDir())
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = sign.Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	before := filesystemSnapshot(t, dir)

	err = runCheck(path)
	if err == nil || !strings.Contains(err.Error(), "TLS certificate") {
		t.Fatalf("missing TLS pair must fail check, got %v", err)
	}

	after := filesystemSnapshot(t, dir)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("check mutated filesystem\nbefore: %v\nafter:  %v", before, after)
	}
}

func filesystemSnapshot(t *testing.T, root string) []string {
	t.Helper()

	var snapshot []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		entry := rel + ":" + info.Mode().String()
		if !info.IsDir() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			entry += ":" + string(body)
		}

		snapshot = append(snapshot, entry)

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	return snapshot
}

func provisionOwnershipFiles(t *testing.T, cfg *config.Config) {
	t.Helper()

	err := disk.Mkdir(cfg.ResolvePath("queue"))
	if err != nil {
		t.Fatal(err)
	}

	lock, err := disk.Lock(cfg.Path() + ".outboxd.lock")
	if err != nil {
		t.Fatal(err)
	}

	err = lock.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestEscapeControl(t *testing.T) {
	got := escapeControl("a\n\tb")
	if got != `a\x0a\x09b` {
		t.Fatalf("escapeControl=%q", got)
	}
}

func TestServeLocksQueueBeforeGeneratingAssets(t *testing.T) {
	// serve must take exclusive queue ownership before writing TLS assets.
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
	cfgBody = strings.Replace(cfgBody, "  mode: self_signed\n", "  mode: self_signed\n  allow_self_signed_serving: true\n", 1)

	err = os.WriteFile(cfgPath, []byte(cfgBody), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	err = disk.Mkdir(cfg.ResolvedDataDir())
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = sign.Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	provisionOwnershipFiles(t, cfg)

	held, err := queue.Open(cfg.ResolvePath("queue"), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	defer held.Close()

	tlsCert := cfg.ResolvePath(cfg.TLS.CertificateFile)
	tlsKey := cfg.ResolvePath(cfg.TLS.PrivateKeyFile)
	dnsOut := cfg.ResolvePath(cfg.DNS.OutputFile)

	for _, p := range []string{tlsCert, tlsKey, dnsOut} {
		if _, err = os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("asset must not exist before serve: %s (%v)", p, err)
		}
	}

	err = serve(cfgPath)
	if !errors.Is(err, disk.ErrLocked) {
		t.Fatalf("serve want ErrLocked, got %v", err)
	}

	for _, p := range []string{tlsCert, tlsKey, dnsOut} {
		if _, err = os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("asset created despite lock failure: %s (%v)", p, err)
		}
	}
}
