package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/passwd"
)

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

// Validate normalizes a single user in place and reports why it is unusable.
func (u *User) Validate() error {
	u.Username = strings.TrimSpace(u.Username)

	if u.Username == "" {
		return errors.New("username must not be empty")
	}

	if strings.ContainsAny(u.Username, "\x00\r\n") {
		return fmt.Errorf("invalid username %q", u.Username)
	}

	migrationPrefix := "{ARGON2ID}$argon2id$"
	isMigrationHash := len(u.PasswordHash) >= len(migrationPrefix) && strings.EqualFold(u.PasswordHash[:len(migrationPrefix)], migrationPrefix)

	if !strings.HasPrefix(u.PasswordHash, "$argon2id$") && !isMigrationHash {
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

func (cfg *Config) adopt(other *Config) {
	cfg.dataMu.Lock()
	defer cfg.dataMu.Unlock()

	cfg.LogLevel = other.LogLevel
	cfg.Server = other.Server
	cfg.ReplyRejection = other.ReplyRejection
	cfg.TLS = other.TLS
	cfg.DKIM = other.DKIM
	cfg.OpenPGP = other.OpenPGP
	cfg.Delivery = other.Delivery
	cfg.DNS = other.DNS
	cfg.Users = slices.Clone(other.Users)
	cfg.userLookup = make(map[string]*User, len(cfg.Users))

	for i := range cfg.Users {
		cfg.userLookup[canonicalUsername(cfg.Users[i].Username)] = &cfg.Users[i]
	}
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

func canonicalUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}
