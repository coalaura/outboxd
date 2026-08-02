# outboxd

Outbound-only mail submission and delivery daemon. Clients submit over authenticated SMTP (ports 587/465); outboxd DKIM-signs and delivers outbound on port 25. It is **not** an inbound MX and does not accept public mail on port 25.

Filesystem free-space enforcement is implemented on Linux, macOS, FreeBSD, and Windows. Other operating systems are not supported.

## What it is / is not

| Does | Does not |
|------|----------|
| Authenticated submission (STARTTLS :587, implicit TLS :465) | Inbound SMTP/MX on port 25 |
| Durable at-least-once outbound queue | Exactly-once delivery |
| DKIM signing, DNS record hints (SPF/DMARC/TLS-RPT) | MTA-STS, DANE, ACME automation |
| Dead-letter administration (`dead` command) | Hosted bounce/complaint mailbox |
| Per-user send quotas and queue/disk caps | Full mail suite (IMAP, filtering, …) |

Bounce and reply handling require a **separate** mailbox (and MX) for envelope-sender domains. Point `dns.dmarc_report_uri` and any bounce address at infrastructure that actually receives mail — outboxd will not.

## Quick start

```bash
# config path: -config path | OUTBOXD_CONFIG | ./config.yml
outboxd -config /etc/outboxd/config.yml provision # create config if needed; edit it before continuing
# after editing the config, rerun provision to create the DKIM identity once
outboxd -config /etc/outboxd/config.yml provision
# provision TLS files, then:
outboxd -config ... user add alice alice@example.com
# stop a running daemon before regenerating DNS
outboxd -config ... dns
outboxd -config ... check
outboxd -config ... serve
outboxd -config ... dead list|show|retry|export|delete <id>
outboxd -config ... corrupt list|delete <name>
```

## Submission vs delivery

- **Submission** (clients → outboxd): ports **587** (STARTTLS) and **465** (implicit TLS). AUTH required; opens for your users only.
- **Delivery** (outboxd → world): outbound **TCP 25** to recipient MX hosts. No listener on 25 for arbitrary internet senders.

## DNS and reputation (operator checklist)

1. **A/AAAA** for `server.hostname` must match `dns.public_ipv4` / `dns.public_ipv6`.
2. **PTR + FCrDNS**: reverse DNS for the sending IP(s) must be the HELO hostname, and that name must resolve back to the same IP(s).
3. **SPF**: exactly one SPF TXT per owner name (envelope domain, distinct allowed-sender domains, and HELO host when different). Built from public IPs and optional `dns.spf_includes`.
4. **DKIM**: selector TXT must match the key outboxd loads.
5. **DMARC**: start with `dmarc_policy: none` (monitor); stage to `quarantine` then `reject` after reports look clean. Aggregate `rua` is separate from TLS-RPT (`dns.tlsrpt_uri`).
6. **Envelope sender domains** need MX (or A/AAAA implicit MX) at a mailbox that accepts bounces — not at outboxd.
7. **IP reputation**: warm new IPs; stay off blocklists; authenticate all submitters; keep complaint rates low. outboxd cannot fix a burned IP.

External DMARC report destinations need the usual `<org-domain>._report._dmarc.<rua-host>` authorization TXT. outboxd emits a reminder in `dns-records.txt` but does not collect reports.

Run `outboxd provision` before `dns`, `check`, or `serve`. If the config is absent, the command creates only the default config so you can edit paths and settings safely; rerun it afterward to create the data/spool paths and configured DKIM private key. Once the key exists, later provisioning runs load and preserve the existing identity. Operational commands never generate or replace a missing DKIM identity and fail instead. Back up the private key before publishing its DNS record.

`dns` takes exclusive ownership of both the config startup snapshot and spool before loading the DKIM key and writing `dns.output_file`. It therefore cannot run alongside the daemon. Stop the daemon, run `outboxd dns`, publish/verify the resulting records, then restart the daemon. Use the same stop/provision-or-DNS/restart workflow after changing `server.data_directory`, `dkim.private_key_file`, `dns.output_file`, or the config path; do not use a newly configured path to work around ownership of the old one.

## TLS

| `tls.mode` | Meaning |
|------------|---------|
| `self_signed` | **Development only.** Generates an untrusted leaf (not a CA). Serving also requires the explicit `tls.allow_self_signed_serving: true` opt-in. |
| `files` | Operator-supplied certificate + key paths. Use a publicly trusted cert in production. |

Minimum TLS version is configurable (`1.2` / `1.3`). Certificate files are content-fingerprint hot-reloaded; a bad reload is logged and keeps the previous certificate only while it remains valid.

Outbound delivery TLS policy is separate (`delivery.tls_mode`: `opportunistic`, `required`, `opportunistic_insecure`). New configurations default to required, verified TLS with plaintext disabled. Weaker policies require explicit configuration.

On Unix, the config and generated DKIM private key must be regular, non-symlink files with no group/other access. Operator-managed TLS paths may use renewal symlinks (including Let's Encrypt `live/` paths), but their opened final targets must be regular files and the private key must have no group/other access. On Windows, outboxd validates opened files as regular and rejects direct symlinks for config/generated secrets, but it does not validate DACLs; operators must explicitly restrict config and private-key ACLs.

## Queue semantics

- On-disk spool under the data directory: **at-least-once** delivery. A crash between a successful remote DATA response and local `Finish` can redeliver; receivers must tolerate duplicates.
- Exhausted or permanently failed messages move to the **dead-letter** area (`outboxd dead …`).
- `max_queue_bytes` is the logical ready-message body quota. `max_spool_bytes` is a conservative admission estimate across ready, tmp, DSN, dead, corrupt, and trash; `spool_emergency_bytes` is unavailable to ordinary submissions but available to DSNs and necessary state transitions. Filesystem allocation, metadata, and external writes mean this is not a hard physical guarantee.
- Put the data directory on a dedicated, local, quota-controlled volume sized with additional filesystem headroom. The OS/filesystem quota is the physical boundary; do not rely on `max_spool_bytes` to protect a shared root volume.
- The spool must be a private namespace writable only by outboxd. Do not place symlinks, junctions, mount points, or other reparse/redirecting entries anywhere below it, and do not let other processes create files there.
- Positive `dead_retention` and `corrupt_retention` bound retained failures. Startup and hourly pruning use crash-safe trash transitions; operators can also delete dead/corrupt entries explicitly.

## Configuration

See the generated `config.yml` comments after `provision`. Important knobs:

- `server.hostname` / `server.domain` — HELO name vs organizational domain
- `server.max_message_bytes`, connection and auth worker limits
- `dns.*` — public IPs and DNS generation only (not outbound bind addresses)
- `delivery.bind_ipv4` / `bind_ipv6` — must exist on a local interface at startup

Configuration and the DKIM key are loaded as one startup snapshot and remain fixed for the process lifetime. Config-file edits and `user add` mutations do not affect a running daemon; restart outboxd to apply them. The only runtime file reload is the documented TLS certificate/key content reload.

`user add` intentionally retains create behavior: when the selected config does not exist, it creates the default config before adding the user. It does not provision the data directory, spool, or DKIM key; run `provision` afterward.

## Commands

```
outboxd [-config path]              # run submission + delivery
outboxd provision                   # create the DKIM key once; preserve it thereafter
outboxd user add <user> [senders…]  # append user via config.AddUser
outboxd dns                         # exclusively own spool, then write/print DNS instructions
outboxd check                       # PASS/WARN/FAIL deployment checks
outboxd dead list|show|retry|export|delete
outboxd corrupt list|delete
```

`OUTBOXD_CONFIG` overrides the default `config.yml` path when `-config` is omitted.
