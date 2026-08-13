package config

import (
	"strings"
	"sync"
)

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

	for i := range cfg.OpenPGP.Identities {
		identity := &cfg.OpenPGP.Identities[i]

		identity.Sender = strings.TrimSpace(identity.Sender)
		identity.SigningKey = strings.TrimSpace(identity.SigningKey)
		identity.PassphraseFile = strings.TrimSpace(identity.PassphraseFile)
		identity.Signing = strings.ToLower(strings.TrimSpace(identity.Signing))
	}

	for i, inc := range cfg.DNS.SPFIncludes {
		cfg.DNS.SPFIncludes[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(inc), "."))
	}
}

func (cfg *Config) initializeRuntime() {
	if cfg.dataMu == nil {
		cfg.dataMu = new(sync.RWMutex)
	}

	if cfg.fileMu == nil {
		cfg.fileMu = new(sync.Mutex)
	}
}
