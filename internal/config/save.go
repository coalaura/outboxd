package config

import (
	"bytes"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/goccy/go-yaml"
)

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
		"$.log_level":                            {yaml.HeadComment(` minimum log level: "debug", "print", "warn", or "error"; changes require a restart`)},
		"$.server":                               {yaml.HeadComment(" authenticated SMTP submission server")},
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
		"$.server.auth_workers":                  {yaml.HeadComment(" concurrent Argon2id authentications (19 MiB each; maximum 8, 152 MiB total)")},
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

		"$.reply_rejection":                        {yaml.HeadComment("\n# optional rejection-only public SMTP endpoint; never accepts message data")},
		"$.reply_rejection.enabled":                {yaml.HeadComment(" disabled by default; when false outboxd does not bind listen_addr")},
		"$.reply_rejection.listen_addr":            {yaml.HeadComment(` public SMTP listen address; default ":25"`)},
		"$.reply_rejection.unknown_recipients":     {yaml.HeadComment(` "listed_only" gives unknown addresses a generic rejection; "all" uses default_message`)},
		"$.reply_rejection.default_message":        {yaml.HeadComment(" rejection text for listed recipients without an override and all-mode unknown recipients")},
		"$.reply_rejection.domains":                {yaml.HeadComment(" domains for which this endpoint is authoritative; other domains are relay-denied")},
		"$.reply_rejection.recipients":             {yaml.HeadComment(" exact recipient addresses with optional customized rejection text")},
		"$.reply_rejection.max_connections":        {yaml.HeadComment(" independent global concurrent connection limit (maximum 1024)")},
		"$.reply_rejection.max_connections_per_ip": {yaml.HeadComment(" independent per-IP concurrent connection limit (maximum 64)")},
		"$.reply_rejection.read_timeout":           {yaml.HeadComment(" SMTP command read timeout (maximum 5m)")},
		"$.reply_rejection.write_timeout":          {yaml.HeadComment(" SMTP response write timeout (maximum 5m)")},

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

		"$.openpgp":            {yaml.HeadComment("\n# optional RFC 3156 OpenPGP/MIME signing; configured identities are required-signing")},
		"$.openpgp.identities": {yaml.HeadComment(" exact From identities and their generated or operator-managed private keys; sender local parts are case-sensitive, relative paths resolve below data_directory, and signing must be required")},

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

		"$.users": {yaml.HeadComment("\n# SMTP users; password_hash must contain an Argon2id hash, never plaintext; migration hashes must use m=19456,t=2,p=1, a 16-byte salt, and a 32-byte output")},
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
