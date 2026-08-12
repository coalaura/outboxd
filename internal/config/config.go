package config

import "sync"

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
