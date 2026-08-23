# outboxd

[![codecov](https://codecov.io/gh/coalaura/outboxd/graph/badge.svg?token=0UH3AOB8ST)](https://codecov.io/gh/coalaura/outboxd)&nbsp;
[![golang](https://img.shields.io/badge/built%20in-go-5AC2D9?logo=go)](https://go.dev)

outboxd is a single-binary outbound mail server for applications and services that need reliable, properly signed email delivery without painfully assembling and maintaining a multi-service mail stack.

It accepts authenticated SMTP submission from configured users, durably queues mail, delivers directly to recipient MX servers, DKIM-signs messages and can optionally apply OpenPGP/MIME signatures per sender and encryption for recipients with operator-supplied keys.

It is for sending mail: transactional mail, notifications, error reporting and application delivery. It is not an inbound mailbox server, IMAP server, spam filter or webmail application. An optional rejection-only SMTP endpoint can reject attempted replies without accepting their message data.

The intended setup is one complete, understandable configuration file and one private data directory: set a hostname, sending domain and public IP, provision key material, add users, publish the generated DNS records, then start the daemon.

## What You Need

- A server with a stable public IP and outbound TCP port 25 available.
- A hostname such as `mail.example.com` with matching forward and reverse DNS.
- A sending domain such as `example.com`.
- A publicly trusted TLS certificate for the submission hostname. Certificate files are configured with `tls.mode: files`.
- A private local filesystem for `data_directory`. Put it on a quota-controlled volume if disk exhaustion matters.

outboxd listens for authenticated submission on port 587 (STARTTLS) and port 465 (implicit TLS) by default. It sends mail outbound on TCP port 25. The optional reply-rejection feature is disabled by default; unless explicitly enabled, outboxd never listens for internet mail on port 25.

## Install

The Linux service keeps its payload, private configuration and data together under `/opt/outboxd`. The binary and `conf` directory are root-owned, the service reads `/opt/outboxd/config.yml` and only `/opt/outboxd/data` is writable by the `outboxd` account.

For a fresh Linux server with systemd, the guided installer downloads and verifies the latest stable release, prompts for the essential configuration, provisions keys, optionally imports an existing Let's Encrypt certificate, adds SMTP users and optional OpenPGP keys, generates the DNS instructions and starts outboxd:

```bash
curl -fsSL https://src.ws2.sh/outboxd/install.sh | sh
```

The installer reads prompts directly from the controlling terminal, parses the complete script before taking action, uses `sudo` when the shell is not already root and refuses to overwrite an existing `/opt/outboxd`. Review `install.sh` before running a network-delivered root installer. Release checksums detect download corruption or mismatched assets; because the checksum and archive come from the same GitHub release, they are not an independent signature.

### Release archive

Download the archive and its checksum from the release page. Substitute the release version and platform shown there:

```bash
tag=v1.2.3
version=${tag#v}
archive="outboxd_${version}_linux_amd64.tar.gz"
base_url="https://github.com/coalaura/outboxd/releases/download/${tag}"

curl -fLO "$base_url/$archive"
curl -fLO "$base_url/SHA256SUMS"
sha256sum --ignore-missing --check SHA256SUMS

sudo install -d -o root -g root -m 0755 /opt/outboxd
sudo tar --no-same-owner -xzf "$archive" -C /opt/outboxd --strip-components=1
sudo /opt/outboxd/conf/setup.sh
```

Inspect the release page rather than guessing a checksum. The archive's top-level directory is stripped so that the binary is always `/opt/outboxd/outboxd`.

### Build from source

Go 1.26.6 or newer is required. Build the binary, assemble the same payload and run the same setup script:

```bash
git clone https://github.com/coalaura/outboxd.git
cd outboxd
go test ./...
go build -trimpath -buildvcs=false -o outboxd .

sudo install -d -o root -g root -m 0755 /opt/outboxd/conf
sudo install -o root -g root -m 0755 outboxd /opt/outboxd/outboxd
sudo install -o root -g root -m 0644 conf/outboxd.conf conf/outboxd.service /opt/outboxd/conf/
sudo install -o root -g root -m 0755 conf/setup.sh conf/uninstall.sh /opt/outboxd/conf/
sudo /opt/outboxd/conf/setup.sh
```

`setup.sh` must run as root. It creates or reuses the `outboxd` system account, prepares `/opt/outboxd/data` with mode `0700`, links the sysusers and systemd paths to the files in `/opt/outboxd/conf`, reloads systemd, enables the service and restarts it if it is already running. Editing those source files takes effect after `systemctl daemon-reload`; rerunning setup refreshes ownership and modes without recursively changing the data directory.

## Quick Start

The root-owned `/opt/outboxd` directory prevents the service account from replacing the binary or the systemd/sysusers source files. Create the initial configuration as root:

```bash
sudo -g outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml provision
```

The first run creates a commented config file and stops. Edit the essentials, then rerun setup to make it root-owned and read-only to the service account:

```bash
sudoedit /opt/outboxd/config.yml
sudo /opt/outboxd/conf/setup.sh
```

Configure certificate paths that match your deployment. Files under the private state directory are compatible with the supplied systemd sandbox:

```yaml
server:
  hostname: mail.example.com
  domain: example.com
  data_directory: /opt/outboxd/data

tls:
  mode: files
  certificate_file: /opt/outboxd/data/tls/fullchain.pem
  private_key_file: /opt/outboxd/data/tls/privkey.pem

dns:
  public_ipv4: 203.0.113.10
```

Set the remaining options in the generated comments as needed. In particular, keep the default secure outbound TLS policy unless you intentionally need a weaker compatibility policy.

To reject replies without operating a receiving mail server, enable the rejection-only endpoint in the same configuration. The same `outboxd serve` process then listens on port 25; a second process is neither needed nor supported.

```yaml
reply_rejection:
  enabled: true
  listen_addr: ":25"
  unknown_recipients: listed_only
  default_message: This address does not accept replies
  domains: [example.com]
  recipients:
    - address: noreply@example.com
      message: This address does not accept replies. Contact support@example.com.
```

`listed_only` uses customized messages for listed addresses and a generic nonexistent-recipient rejection for other addresses in an authoritative domain. `all` uses `default_message` for every otherwise-unlisted address in those domains. Other domains are always relay-denied. The endpoint rejects every recipient during SMTP and never accepts `DATA`, queues inbound messages, sends automatic replies or exposes submission users. It has independent connection limits and no STARTTLS requirement. Restart outboxd after changing this startup configuration.

Provision again to create the data directory, spool and create-once DKIM key:

```bash
sudo -u outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml provision
```

Add an SMTP user. If stdin is a terminal, outboxd generates a password and prints it once. To supply one yourself, pipe a single-line password of at least 12 bytes.

```bash
sudo -g outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml user add alice alice@example.com
printf '%s\n' 'a-long-password' | sudo -g outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml user add alice alice@example.com
sudo /opt/outboxd/conf/setup.sh
```

The user command always stores a native Argon2id hash. For migration, a `password_hash` copied into the configuration may instead use the Dovecot-style `{ARGON2ID}$argon2id$...` form. Imported hashes must use the audited native profile: Argon2id `m=19456,t=2,p=1`, a 16-byte salt and a 32-byte output. This keeps each authentication within 19 MiB and all eight permitted authentication workers within 152 MiB, while making unknown-user timing work use the same cost profile. Regenerate incompatible hashes before importing them, then restart outboxd after editing users.

Generate the DNS instructions while the daemon is stopped:

```bash
sudo -u outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml dns
```

Copy the generated records into DNS, then verify the deployment and start the service:

```bash
sudo -u outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml check
sudo systemctl start outboxd
sudo systemctl status outboxd
```

`dns`, `check` and `serve` load an existing DKIM key; they never create or replace one. Run `provision` if the key is missing. Stop the daemon before running `dns`, changing the DKIM key or generated DNS path or changing the config/data-directory path.

## OpenPGP Signing, Encryption And Key Discovery

OpenPGP/MIME signing is optional globally and explicit per exact header `From` identity. Add an `openpgp.identities` entry with `sender`, `signing_key` and `signing: required`. The sender local part is case-sensitive and its domain is case-insensitive. A message whose `From` has no configured identity remains unsigned; a configured identity is never allowed to fall back to unsigned delivery.

Generate and configure an encrypted RSA-3072 key for an existing user's exact allowed sender with `outboxd -config /path/to/config.yml openpgp create <username> <sender>`. The command creates a random passphrase file and armored private key below `server.data_directory`, never overwrites existing material, validates the key through the production signing loader and atomically updates the configuration. It does not print the passphrase. The config is committed only after both private files are durable; if durability confirmation fails after config replacement, the command reports that partial-success state and preserves the referenced files. With the supplied Linux layout, run the command as root with group `outboxd`, run `sudo chown -R --no-dereference outboxd:outboxd /opt/outboxd/data/openpgp` so the service can traverse and read the complete generated tree, rerun `setup.sh` to restore config ownership and mode, and restart outboxd afterward.

`signing_key` accepts one armored or binary private-key entity and must contain the configured sender as a key identity plus a currently valid signing key. For an encrypted private key, set `passphrase_file` to a private file containing exactly one passphrase line. Do not put passphrases in the YAML or command line. Relative paths resolve below `server.data_directory`; absolute paths are allowed. Keys and passphrase files must be private regular files and may not be symlinks or reparse points.

Signing produces RFC 3156 `multipart/signed` data before recipient encryption, and DKIM is applied last to each final message variant. The exact canonical MIME entity placed in the signed first part is covered, with 8-bit MIME leaf bodies converted to quoted-printable. If key loading, canonicalization, signing or encryption fails, submission receives an error and the message is not queued or accepted. Normal `serve`, `check`, `dns` and `provision` operations never generate OpenPGP keys. outboxd supports OpenPGP/MIME, not inline PGP. `check` validates configured OpenPGP keys without modifying them. Keys and passphrases are loaded only at startup, so rotation requires a restart.

For static recipient encryption, set `openpgp.recipient_keys_directory` to a private directory containing armored `.asc` or binary `.pgp` public-key files. Each file must contain exactly one public entity, no private packets and a currently valid encryption key. outboxd derives exact recipient addresses from active, self-signed email user IDs; local parts are case-sensitive, while domains are case-insensitive and normalized to their ASCII IDNA form. A recipient with a configured key is always encrypted, and encryption failure never falls back to plaintext. Recipients without keys remain plaintext unless listed in `openpgp.require_encryption_for`; every required address must have a usable key or startup fails. Mixed plaintext and encrypted recipients are committed atomically as immutable per-recipient message variants and retries reuse those stored bytes.

Static recipient keys are operator-trusted input rather than automatically discovered keys. outboxd does not currently fetch recipient keys from WKD, OPENPGPKEY or keyservers. Verify key fingerprints independently before placing keys in the directory.

outboxd derives a minimized public key containing the primary public key, exactly one active configured user ID and its self-signature, public subkeys and their binding signatures, and applicable revocations. It never publishes private packets, unrelated user IDs or third-party certifications. Three optional discovery mechanisms use these same bytes:

- Run `outboxd -config /path/to/config.yml openpgp publish <new-output-directory>` to atomically create armored public-key files, a manifest, and static advanced and direct WKD trees with empty policy files. The destination must not already exist. Deploy the preferred advanced tree at `openpgpkey.<domain>` over HTTPS, or the direct tree at the sending domain, following the URLs in `MANIFEST.txt`. outboxd does not run an HTTP service.
- Set `autocrypt: true` on an identity to add one folded Autocrypt Level 1 header to its signed messages. The public key must have a currently valid encryption key. `Autocrypt` must be present in `dkim.headers`, as it is in new configurations, so outboxd rejects a configuration that would publish an unauthenticated header. No `prefer-encrypt=mutual` claim is emitted because static recipient encryption does not implement Autocrypt peer-state negotiation.
- Set `dns.publish_openpgpkey: true` to include RFC 7929 OPENPGPKEY records in `outboxd dns` output. The guide provides standard base64 RDATA and generic TYPE61 presentation. Treat OPENPGPKEY as authenticated discovery only when the resolver reports a DNSSEC Secure result.

Discovery is not a substitute for key trust. WKD authenticates publication through the domain's HTTPS deployment, Autocrypt provides in-band discovery and continuity rather than strong identity authentication, and OPENPGPKEY depends on DNSSEC. Publish fingerprints through an independent trusted channel when identity assurance matters.

## TLS Certificates

Certificate deployment is intentionally left to the operator so outboxd can be used with any certificate authority or existing automation. The `outboxd` service account must be able to read both configured files. On Unix, the private key must have no group or other permission bits; use mode `0600` and ownership that permits the service account to read it. Do not weaken the key permissions to make an external certificate directory accessible. Copying or deploying certificate material into a private location such as `/opt/outboxd/data/tls` is one compatible approach, but outboxd does not prescribe or install that automation.

outboxd checks the configured certificate and key during TLS handshakes, rate-limited to avoid filesystem reads on every connection. A valid changed pair is loaded automatically; no signal, systemd reload or restart is needed. If a transient read or validation failure occurs while files are replaced, outboxd continues serving the previously loaded certificate while it remains valid and retries on a later handshake. Once the old certificate expires, an invalid replacement cannot be used and affected TLS handshakes fail. The guided installer's Certbot hook copies renewed files into the root-controlled `/opt/outboxd/tls` directory so a compromised service account cannot redirect a root renewal hook through a replaced parent directory.

## DNS Checklist

`outboxd dns` writes and prints the records to publish. It includes the DKIM record and guidance for SPF, DMARC and TLS-RPT, plus OPENPGPKEY records when explicitly enabled. When reply rejection is enabled, it also includes MX records for each explicitly configured rejection domain; no MX records are generated for this feature while it is disabled.

- Publish A (and optionally AAAA) for `server.hostname` using `dns.public_ipv4` and `dns.public_ipv6`.
- Set reverse DNS for each sending IP to `server.hostname` and ensure the hostname resolves back to the same IP.
- Publish the generated DKIM TXT record.
- If `dns.publish_openpgpkey` is enabled, publish each generated OPENPGPKEY record in a DNSSEC-signed zone.
- Publish one SPF TXT record for each sending identity domain.
- Start DMARC with `p=none`, inspect reports, then move to `quarantine` or `reject` when appropriate.
- Use a separate service with an MX record wherever bounces or replies must actually be received. The optional outboxd MX endpoint only returns permanent SMTP rejections and does not receive or store mail.

New IPs also need normal reputation work: authenticated users only, sensible sending rates and low complaint rates.

## Configuration And Files

The generated `config.yml` documents every setting. Relative paths resolve next to the config file; generated DKIM material, operator-supplied OpenPGP material, self-signed development TLS material, DNS instructions and queue state live under `server.data_directory`.

Operator-managed TLS files may be outside `data_directory`, subject to service sandbox access and private-key permission requirements. The config ownership lock and short-lived atomic-write files live beside the config file.

Configuration, users, DKIM and OpenPGP keys, queue limits and delivery policy are loaded at startup. Restart outboxd after changing them. TLS certificate and key contents are the only runtime-reloaded files.

The top-level `log_level` setting accepts `debug`, `print`, `warn` or `error` and defaults to `print`. Debug logging includes detailed outbound delivery timings and is intended for development and troubleshooting.

To remove the installed systemd and sysusers links, run `sudo /opt/outboxd/conf/uninstall.sh`. It deliberately preserves `/opt/outboxd` and the `outboxd` account so private configuration and data retain their owner. Remove the preserved directory and then the account manually only when permanently decommissioning the service.

Useful limits include:

- `server.max_queue_messages` and `server.max_queue_bytes` for the ready queue.
- `server.max_queue_messages_per_user` and `server.max_queue_bytes_per_user` to keep one account from consuming the shared ready queue.
- `server.max_spool_bytes`, `spool_emergency_bytes` and `min_free_disk_bytes` for conservative spool admission control.
- `delivery.user_concurrency`, `domain_concurrency`, `global_concurrency` and candidate/deadline limits for outbound work.

`max_spool_bytes` is an admission estimate, not an operating-system disk quota. Use a dedicated local volume with an OS/filesystem quota as the actual physical boundary.

## Queue And Failures

Mail is durably queued before outboxd reports SMTP acceptance. If the process or host stops unexpectedly, queued mail is recovered and delivery resumes when the service returns.

Delivery is at least once: if a crash or lost final SMTP response occurs after a recipient accepts `DATA` but before local completion is recorded, a message can be delivered again. Recipient acceptance cannot be guaranteed: recipient policy, invalid addresses, DNS, network failures and sending reputation remain outside outboxd's control.

Permanent failures and exhausted retries move to the dead-letter area. Corrupt entries are isolated rather than stopping unrelated delivery. Retention pruning runs at daemon startup and periodically while serving.

The spool must be private to the outboxd service account. Do not place symlinks, junctions, mount points or files created by other processes below it.

## Operations

```text
outboxd [-config path] serve                 # default when no command is given
outboxd [-config path] provision             # create config, data/spool and DKIM key
outboxd [-config path] config update         # add current defaults to an existing config
outboxd [-config path] user add <user> [sender...]
outboxd [-config path] openpgp create <username> <sender>
outboxd [-config path] openpgp publish <output-directory>
outboxd [-config path] dns                   # write and print DNS instructions
outboxd [-config path] check                 # verify local configuration and DNS
outboxd [-config path] queue list
outboxd [-config path] queue show <id>
outboxd [-config path] queue export <id>
outboxd [-config path] queue retry <id>
outboxd [-config path] queue delete <id>
outboxd [-config path] dead list
outboxd [-config path] dead show <id>
outboxd [-config path] dead export <id>
outboxd [-config path] dead retry <id>
outboxd [-config path] dead delete <id>
outboxd [-config path] corrupt list
outboxd [-config path] corrupt delete <name>
```

The application defaults to `config.yml` in the working directory. The supplied Linux service explicitly selects `/opt/outboxd/config.yml`. Use `OUTBOXD_CONFIG` or `-config` to select a different path.

`queue list`, `queue show` and `queue export` are read-only and may run while the daemon is serving. `queue retry` makes an existing message immediately due without clearing its attempt or recipient history. Retry and delete require the daemon to be stopped so they cannot race delivery. Deletion is crash-safe and refuses messages with linked DSN state.

After replacing the binary, run `config update` as root with group `outboxd` to atomically rewrite an existing configuration in the current documented format, then rerun `setup.sh` to restore its service-readable ownership and mode. Configured values are retained and fields omitted by older versions receive current defaults. The command requires an existing valid configuration, does not provision keys or other assets and requires a daemon restart before the updated startup configuration takes effect. The canonical rewrite replaces custom YAML formatting and comments with outboxd's generated documentation.

## Security Notes

- Use `tls.mode: files` with a publicly trusted certificate in production. `self_signed` is development-only and requires an explicit opt-in.
- Keep the config root-owned and readable only by the `outboxd` group, and keep DKIM keys, OpenPGP keys, passphrase files and the data directory readable and writable only by the service account. On Windows, configure the service account and ACLs yourself.
- Outbound delivery defaults to verified, required TLS. Do not enable plaintext or insecure TLS unless the compatibility tradeoff is deliberate.
- outboxd does not accept inbound message data and does not implement inbound mail storage, DANE, MTA-STS or DNSSEC validation.
- A private local filesystem with reliable rename/sync behavior is required for the queue durability guarantees.
