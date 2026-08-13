# outboxd Agent Guide

## Purpose

outboxd is a small, self-contained outbound mail server. It accepts authenticated SMTP submissions from configured users, validates and prepares messages, applies DKIM signatures, commits them to a durable local queue and delivers them directly to recipient MX servers over TCP port 25.

The intended deployment is one understandable configuration file, one private local data directory and one daemon. Prefer focused, auditable behavior over broad features or framework-like abstractions.

## Product Boundaries

outboxd is for sending mail only. Do not turn it into an inbound MX, mailbox store, IMAP/POP server, spam filter, webmail application, HTTP API, control panel, mailing-list manager or general-purpose MTA.

It intentionally does not implement DANE, MTA-STS, DNSSEC validation, certificate-authority automation, inbound bounce handling, reply handling or DMARC report collection. Operators use separate services and their own certificate deployment automation for those concerns.

Submission listens on port 587 with STARTTLS and port 465 with implicit TLS by default. It must remain authenticated and relay-restricted; outboxd does not listen for internet mail on port 25. Outbound delivery uses port 25 and defaults to verified, required TLS. Never silently downgrade TLS or broaden relay access.

## Core Rules

- Report SMTP acceptance only after the message is durably committed to the queue.
- Preserve the documented at-least-once delivery model. A crash after remote acceptance but before local completion can cause duplicate delivery; do not claim exactly-once delivery.
- Keep queue namespace transitions, file syncs, atomic renames, revisions, body digests, quotas, reservations and recovery ordering intact. Ambiguous persistence outcomes must fail conservatively or be reconciled from durable state.
- Generated DSNs and their source messages must not become simultaneously deliverable. Preserve terminal recipient snapshots and reciprocal DSN identity across crashes.
- Isolate corrupt entries without preventing unrelated delivery. Preserve uncertain linked state rather than destructively guessing after transient I/O failures.
- Treat the spool, configuration, password hashes, DKIM keys and TLS private keys as private material. Keep Unix modes and Windows DACL validation strict, reject links or reparse points inside managed private namespaces and do not weaken checks for convenience.
- Destination filtering must happen before dialing. Private, loopback, link-local, reserved, mapped, multicast and other restricted addresses remain blocked unless explicitly allowlisted.
- Bound untrusted input, SMTP responses, message sizes, recipients, workers, connections, DNS work, delivery attempts and deadlines.
- DKIM keys are create-once managed material. Normal `dns`, `check` and `serve` paths must not create or replace them.
- TLS certificate contents are the only runtime-reloaded files. Configuration, users, DKIM material, queue limits and delivery policy are startup state and require a restart.

## Repository Map

- Root command files implement `serve`, `provision`, `user`, `dns`, `check`, `dead` and `corrupt` CLI behavior.
- `internal/smtpd` handles authenticated submission, connection/rate limits, SMTP transactions and durable queue admission.
- `internal/message` parses, validates, normalizes and prepares submitted messages.
- `internal/sign` manages DKIM keys and signing.
- `internal/queue` owns durable storage, scheduling, quotas, recovery, DSNs, dead letters and corruption quarantine.
- `internal/deliver` performs MX discovery, destination hardening, SMTP delivery, retries, terminal outcomes and DSN generation.
- `internal/config`, `internal/certs`, `internal/disk` and `internal/windowsacl` enforce configuration, certificate, filesystem durability and private-access policy.
- `internal/check` and `internal/records` validate deployment DNS and generate publication guidance.
- `conf` and `.github/workflows/release.yml` define the supported Linux service layout and release pipeline.

## Change Discipline

- Make the smallest correct change. Do not add compatibility layers, new services, protocols, commands, configuration fields or dependencies without a concrete requirement.
- Preserve existing APIs, on-disk formats, YAML behavior, security defaults and operational paths unless the task explicitly requires a migration or behavior change.
- Follow established Go style and file organization. Keep declarations ordered consistently, use cohesive files and prefer clear direct code over unnecessary helpers or abstractions.
- Do not define anonymous structs with fields. Give them concise unexported names near the other type declarations; empty `struct{}{}` remains appropriate.
- Keep code readable, maintainable, performant and secure. Comments should explain non-obvious invariants or compatibility constraints, not restate code.
- Do not weaken a production invariant or merely increase production limits to make a test pass. Timing-sensitive tests may use generous margins, but must continue proving the same deadline or cancellation property.
- Preserve platform-specific behavior. macOS permits only its verified standard `/var`, `/tmp` and `/etc` aliases; arbitrary links remain invalid. Windows managed objects require protected private DACLs.
- Update documentation, generated configuration comments, service packaging and tests when user-visible behavior genuinely changes.

## Deployment And Releases

- Keep the supported Linux layout coherent: release payload under `/opt/outboxd`, private configuration and state under `/var/lib/outboxd` and the daemon running as the `outboxd` account.
- Ports 465 and 587 require `CAP_NET_BIND_SERVICE` on standard Linux systems. Do not remove the systemd bounding and ambient capability unless the listener defaults or privilege model also change.
- Certificate deployment remains operator-owned and certificate-authority-neutral. Do not add project-managed ACME or Let's Encrypt automation. TLS file reload must retain the last valid unexpired pair when a replacement is transiently invalid.
- Preserve release workflow gates: stable annotated SemVer tags, module verification, tidy check, vet, race tests, native Linux/Windows/macOS tests, cross-platform builds, version smoke tests, packaged documentation/configuration and verified checksums.
- Do not move or recreate a release tag until the exact tagged commit passes the mandatory workflow. A failed release workflow must not publish artifacts.

## Verification

Run the narrowest relevant tests while developing, then before completing a meaningful change run:

```text
gofmt on changed Go files
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
git diff --check
```

For filesystem, security, release or platform-specific changes, also compile or test the affected Linux, Windows and macOS targets. Release tags are stable annotated SemVer tags; the release workflow is a mandatory gate and must not publish when validation or tests fail.
