**Release Gate**

**NOT PRODUCTION-READY. Release blocked.**

No unauthenticated remote-code execution, open relay, plaintext TLS downgrade, direct SSRF bypass, or called dependency vulnerability was found. However, four high-severity defects and several medium-severity integrity/availability defects prevent a production release.

No files were edited.

**Release Blockers**

### 1. High: SMTP can acknowledge mail without proven durable acceptance

**Location:** `internal/queue/queue.go:913-954`, `internal/queue/queue.go:1292-1347`, `internal/smtpd/session.go:288-301`

**Scenario:** The acceptance marker write becomes page-cache visible, its `Sync` returns an ambiguous failure, rollback fails, and quarantine also fails. `Queue.Add` rereads the visible marker and may return success because it reads `accepted`, despite no successful durability barrier. SMTP then sends final success. A subsequent power loss can restore `pending`, torn, or older state, causing startup quarantine instead of delivery.

**Impact:** Loss of a message after the client received successful SMTP acceptance. This violates the queue’s core durability contract.

**Smallest robust fix:** Never return success unless the acceptance sync itself returned success. Preserve ambiguous entries as unresolved and return a transient SMTP failure, accepting possible duplicates. Preferably replace the mutable marker protocol with an immutable publish-by-rename commit.

**Deterministic test:** Introduce an I/O fault model that distinguishes visible bytes from durable bytes. Make marker sync, rollback, and quarantine fail, let reads see `accepted`, simulate power loss, and assert `Queue.Add` returns an error and SMTP never sends final success.

### 2. High: Tiny headers bypass the intended DATA memory budget

**Location:** `internal/message/message.go:79-119`, `internal/message/message.go:415-480`, `internal/smtpd/smtpd.go:64-70`, `internal/smtpd/smtpd.go:156-175`, `internal/config/config.go:139-140,161`

**Scenario:** An authenticated account submits a 25 MiB default or 100 MiB maximum message containing millions of tiny headers such as `a:x\r\n`. Parsing allocates a `field`, string, and slice representation for every header. There is no independent header-byte or field-count limit.

**Impact:** Hundreds of megabytes to gigabytes of object overhead, severe GC pressure, process OOM, and submission outage from one compromised account.

**Smallest robust fix:** Enforce both a bounded header section, such as 1 MiB, and a bounded field count, such as 1,000. Include parser object overhead in DATA worker admission calculations.

**Deterministic test:** Exercise exact header-byte and field-count boundaries, reject one over each limit, and add an allocation-bound test for many minimal fields.

### 3. High: One recipient domain can starve all outbound delivery

**Location:** `internal/deliver/deliver.go:127-130`, `internal/deliver/deliver.go:157-182`, `internal/deliver/deliver.go:268-285`, `internal/deliver/deliver.go:358-371`

**Scenario:** The global bounded attempt slot is acquired before the per-domain limiter. At defaults, 64 messages to one slow attacker-controlled domain can consume all attempt slots: two perform SMTP while 62 wait for that domain token. Unrelated domains cannot run despite unused global network capacity.

The existing fairness test at `internal/deliver/deliver_test.go:517-584` queues only two blocked-domain messages, below the eight-slot minimum attempt capacity, so it does not cover saturation.

**Impact:** Global head-of-line blocking and potentially hours of delayed delivery across unrelated customers and domains.

**Smallest robust fix:** Use a domain-aware dispatcher that admits work only when domain capacity exists, or cap admitted waiters per domain and reschedule excess. Merely moving the domain acquisition into unbounded goroutines is insufficient.

**Deterministic test:** Configure global concurrency 2 and domain concurrency 1, fill all eight attempt slots with one blocked domain, queue a fast-domain message, and assert the fast message is delivered before the blocked domain is released while network sessions remain bounded.

### 4. High: Missing DKIM keys silently create a new signing identity

**Location:** `internal/sign/sign.go:32-55`, `internal/sign/sign.go:126-168`, `main.go:151-160`, `dns.go:10-23`

**Scenario:** A restore omits the DKIM key, so startup silently generates another key and signs before DNS is updated. More seriously, a running daemon can retain key A while `outboxd dns`, after deletion of the file, generates key B and emits B’s DNS record.

**Impact:** Immediate DKIM failures and possible DMARC rejection or quarantine. DNS and the running signer can advertise different identities.

**Smallest robust fix:** Separate explicit DKIM provisioning from serving and DNS inspection. Production startup and `dns` must load an existing key and fail if it is absent. Implement active/next selectors for safe overlap and rotation.

**Deterministic test:** Start with key A, delete its file while the signer remains active, invoke `dns`, and assert no B is created. Assert restart fails without a key. Test selector overlap and atomic cutover.

### 5. Medium: Queue namespace links can redirect destructive operations

**Location:** `internal/disk/disk.go:132-178`, `internal/queue/queue.go:2062-2189`, `internal/queue/queue.go:2796-2819`, `internal/queue/queue.go:2975-2995`, `internal/queue/queue.go:3322-3325`

**Scenario:** Existing `ready`, `trash`, `dead`, `tmp`, `dsn`, or `corrupt` paths can be symlinks, junctions, or reparse points because directory validation follows them. Cleanup and recursive deletion then operate under the external target.

**Impact:** Writes, moves, quarantine, or deletion outside the spool, limited to locations writable by the service account. Under the stated private-spool assumption this requires operator error, unsafe restore, or local compromise, but the operation is destructive.

**Smallest robust fix:** Reject linked/reparse namespace components, verify same filesystem or volume, and use descriptor-relative no-follow operations where supported.

**Deterministic test:** Replace `trash` with a Unix symlink and Windows junction to an external sentinel directory; startup must reject it without touching the sentinel. Add a component-swap race test.

### 6. Medium: Sender policy ignores retained originator identities

**Location:** `internal/smtpd/session.go:56-99`, `internal/smtpd/session.go:229-237`, `internal/message/message.go:125-161`, `internal/message/message.go:241-258`, `internal/config/config.go:187-201`

**Scenario:** A restricted user submits an allowed envelope sender and `From`, but adds unauthorized `Sender`, `Resent-From`, or `Resent-Sender` identities. These headers are retained, are not authorized, and are absent from the default DKIM header list.

**Impact:** Sender-policy bypass, misleading “on behalf of” or resent attribution, and phishing opportunities depending on recipient-client presentation.

**Smallest robust fix:** Parse and authorize every retained originator identity. If resent semantics are unsupported, strip complete resent blocks. Mandatorily DKIM-sign the retained security-sensitive fields.

**Deterministic test:** Submit each unauthorized originator field separately and in combination; assert rejection before signing and queueing. Verify authorized variants remain DKIM-covered.

### 7. Medium: Delivery does not enforce the queued body’s exact length

**Location:** `internal/queue/queue.go:2640-2718`, `internal/deliver/deliver.go:701-731`

**Scenario:** `Queue.Reader` verifies size when opening, but delivery subsequently uses unbounded `io.Copy`. Truncation after open produces clean EOF and can commit a truncated message. Growth after open sends bytes beyond the recorded envelope size.

**Impact:** Transmission of corrupted, DKIM-invalid, or unaccepted bytes. This requires local modification or filesystem corruption.

**Smallest robust fix:** Read at most `Envelope.Size+1`, require an exact byte count, and abort the SMTP socket without closing the dot writer when the body is short or long.

**Deterministic test:** Cover short, exact, and one-byte-excess readers. Short and excess cases must not emit the DATA terminator or mark recipients sent.

### 8. Medium: Graceful shutdown is not bounded end-to-end

**Location:** `internal/smtpd/smtpd.go:324-370`, `internal/smtpd/smtpd.go:401-415`, `internal/queue/queue.go:2895-2934`

**Scenario:** After the 30-second `go-smtp` shutdown timeout, only listeners are closed. Active sockets and session goroutines survive. If a session is blocked in queue I/O, the subsequent queue close can wait indefinitely.

**Impact:** Hung restart, upgrade, failover, or orchestration termination. A forced process kill may occur during queue maintenance.

**Smallest robust fix:** Force-close both SMTP servers after graceful timeout and make queue-operation shutdown context/deadline aware while retaining conservative commit semantics.

**Deterministic test:** Block an Add after operation admission, cancel the service, and assert forced socket closure and top-level termination within a fixed bound. Confirm any already-committed entry remains recoverable.

### 9. Medium: The documented hard physical spool limit is not hard

**Location:** `README.md:63`, `internal/queue/queue.go:143-165`, `internal/queue/queue.go:419-456`, `internal/queue/queue.go:604-638`, `internal/queue/queue.go:1467-1570`, `internal/disk/disk.go:12-31`

**Scenario:** Accounting assumes fixed 64 KiB allocation per object, excludes journal/COW/snapshot costs and concurrent shared-volume consumption, and refreshes only near the modeled limit at most once per minute. Metadata replacement reservations are permanently added even though old metadata is normally released, causing false growth during retries.

**Impact:** The “No write may cross” claim is false on some filesystems, and retry-heavy workloads can falsely exhaust the modeled spool and reject submissions.

**Smallest robust fix:** Describe this as an admission estimate unless backed by a dedicated quota-controlled volume. Discover allocation units, reconcile allocated blocks after commits, preserve explicit filesystem headroom, and do not permanently charge replacement reservations.

**Deterministic test:** Simulate large allocation units/COW overhead, execute thousands of retries within one refresh interval, and consume volume space concurrently between admission and write.

### 10. Medium: Internationalized DSNs use incompatible legacy report types

**Location:** `internal/deliver/dsn.go:56-98`, `internal/deliver/dsn.go:163-180`, `internal/deliver/dsn.go:195-228`

**Scenario:** UTF-8 recipients are written into legacy `message/delivery-status` fields using `Final-Recipient: rfc822`, with the original represented as `message/rfc822`.

**Impact:** Strict receivers can reject or misparse bounces for internationalized addresses despite successful SMTPUTF8 transport.

**Smallest robust fix:** Retain RFC 3464 forms for ASCII DSNs and use RFC 6533 global delivery-status, address types, and original-message media types for internationalized reports.

**Deterministic test:** Parse generated ASCII and UTF-8 MIME reports, assert their exact media/address types, and deliver the UTF-8 form through an SMTPUTF8-capable fake MX.

**Non-Blocking Findings**

### 11. Medium: Equal-length body corruption is undetected

**Location:** `internal/queue/queue.go:103-138`, `internal/queue/queue.go:2544-2561`, `internal/queue/queue.go:2640-2718`

**Scenario:** Bit rot or same-length replacement passes all regular-file and length checks.

**Impact:** Corrupted content can be sent with broken DKIM.

**Fix:** Persist a versioned SHA-256 body digest and verify it before beginning the remote SMTP transaction, or require a checksummed filesystem explicitly.

**Test:** Flip one byte without changing length and assert quarantine or refusal before `MAIL`/`DATA`.

### 12. Medium: Runtime configuration silently remains stale

**Location:** `main.go:94-205`, `user.go:48-70`, `internal/smtpd/smtpd.go:116-153`, `internal/deliver/deliver.go:157-201`

**Scenario:** `user add` reports success, but the running daemon retains its startup snapshot. User revocation, credential changes, and policy edits also require restart without clear CLI signaling.

**Impact:** Operators may incorrectly believe authorization or emergency revocation has taken effect.

**Fix:** Implement transactional reload or state explicitly that restart is required and refuse misleading online mutation behavior.

**Test:** Add, disable, and modify a user while serving; verify defined behavior and race-safe handling of invalid reloads.

### 13. Medium: Resource-control configuration accepts extreme values

**Location:** `internal/config/config.go:598-604`, `internal/config/config.go:634-672`, `internal/config/config.go:743-749`, `internal/config/config.go:1181-1191`

**Scenario:** Positive but extreme durations can retain sockets/workers for months. Negative bursts can be defaulted instead of rejected.

**Impact:** Configuration typos become prolonged availability failures.

**Fix:** Define practical maxima and relationships for durations, rates, and bursts; reject negative values.

**Test:** Boundary tables for zero, negative, maximum, maximum+1, and overflow-adjacent values.

### 14. Low: Valid non-UTF-8 8BITMIME bodies are rejected

**Location:** `internal/message/message.go:210-223`

**Scenario:** Valid ISO-8859-1 `Content-Transfer-Encoding: 8bit` content is rejected because all high-bit bodies are required to be UTF-8.

**Impact:** Standards-compliant legacy clients cannot submit some mail.

**Fix:** Permit arbitrary non-NUL octets under `BODY=8BITMIME`; infer UTF-8 MIME only when bytes are valid UTF-8.

**Test:** Accept explicit ISO-8859-1 under 8BITMIME and reject it under 7BIT.

### 15. Low: Advertised SIZE is one byte too large

**Location:** `internal/smtpd/smtpd.go:178-208`, `internal/smtpd/session.go:183-195`

**Scenario:** The server advertises and accepts `MAIL SIZE` at configured maximum plus one, then rejects the body during DATA.

**Impact:** Inaccurate capability negotiation and wasted upload resources.

**Fix:** Correct or wrap the dependency’s exact-boundary behavior and advertise the actual application limit.

**Test:** Verify EHLO, `MAIL SIZE`, DATA, and BDAT at exact maximum and maximum+1.

### 16. Low: Temporary delivery diagnostics can be assigned to the wrong recipient

**Location:** `internal/deliver/deliver.go:370-375`, `internal/deliver/deliver.go:393-407`, `internal/deliver/deliver.go:674-699`

**Scenario:** The final domain error overwrites envelope-wide `LastError` and is copied to every pending recipient. All-451 RCPT responses can leave retry logging without a useful domain error.

**Impact:** Misleading DSNs, dead-letter records, and operational diagnosis.

**Fix:** Store structured errors per recipient/domain and maintain a separate aggregate only for logs.

**Test:** Use two domains with distinct failures and an all-451 transaction; assert exact recipient-specific details.

### 17. Low: DSN metadata loses timing and terminal-status semantics

**Location:** `internal/deliver/dsn.go:155-170`, `internal/deliver/dsn.go:239-250`

**Scenario:** `Arrival-Date` uses DSN generation time rather than envelope creation, and expiry/exhaustion often becomes generic `5.0.0`.

**Impact:** Inaccurate bounce diagnostics.

**Fix:** Use `Envelope.Created` and explicit enhanced statuses such as delivery-time expiry.

**Test:** Use a fixed historical creation time and deterministic expiry/status assertions.

### 18. Low: Quarantine directory creation is not fully durable

**Location:** `internal/queue/queue.go:3349-3368`, `internal/disk/disk.go:127-130`

**Scenario:** `corrupt/<name>` is created without syncing the `corrupt` parent before the source object is moved.

**Impact:** A power failure can lose malformed evidence.

**Fix:** Use `MkdirDurable` or sync the parent before relocation.

**Test:** Fault after source-parent sync while modeling the unsynced destination entry as lost.

### 19. Low: Allowed-sender validation differs between config and SMTP

**Location:** `internal/config/config.go:887-932`, `internal/mailbox/mailbox.go:66-97`

**Scenario:** Configuration can accept an overlong sender address that SMTP will always reject.

**Impact:** Unusable account policy accepted at startup.

**Fix:** Reuse strict mailbox validation.

**Test:** Cover exact 64-octet local-part and 254-octet mailbox boundaries.

**Hardening**

- Proactively reload and monitor certificates instead of checking only during handshakes; add 7/14/30-day expiry health.
- Strictly reject duplicate DKIM tags and verify complete generated DKIM, DMARC `rua`, and TLS-RPT semantics in deployment checks.
- Add safe DKIM active/next selector rotation and oversigning support. Current duplicate-header configuration rejection at `internal/config/config.go:704-727` prevents ordinary oversigning configuration.
- Add per-domain TLS policy maps, hold/release and domain-pause controls, structured metrics, machine-readable health, privilege separation, and proactive queue-age alerts.
- Avoid printing generated passwords to ordinary stdout by default; support hidden TTY input and owner-only password files.
- Document `dead list/show/export` as best-effort while the daemon is pruning; it is not snapshot-consistent.
- Add bounded total DNS/domain-attempt and SMTP transaction durations in addition to per-operation deadlines.

**Required Operations**

- Protect config, spool, DKIM key, and TLS key with service/SYSTEM/Administrators-only Windows DACLs. The code intentionally does not enforce Windows ACLs.
- Prevent untrusted users from creating junctions or reparse points beneath the spool.
- Use a local filesystem with truthful flush and rename behavior. Do not use SMB/NFS/cloud-synced storage.
- Prefer a dedicated quota-controlled volume and maintain headroom beyond `MinFreeDisk`.
- Monitor queue age/depth, dead/corrupt growth, high-water state, storage-pressure retries, certificate state, TLS reload failures, DKIM alignment, and bounce/complaint rates.
- Back up config, DKIM identity, and spool consistently. Never restore individual queue files into a live spool.
- Maintain correct system time, trusted CA roots, reliable recursive DNS, outbound TCP/25, PTR/FCrDNS, SPF, DKIM, and DMARC.
- Use a separate inbound mailbox/MX for bounces and replies.
- Treat config and user changes as restart-required until reload semantics are implemented.

**Intentional Limitations**

- Outbound-only authenticated submission; no inbound mailbox or MX.
- At-least-once delivery, including duplicates after ambiguous remote DATA acceptance or local completion.
- No DANE/TLSA, DNSSEC validation, or MTA-STS.
- Verified PKIX TLS cannot defeat insecure DNS redirection to an attacker-controlled hostname with its own valid certificate.
- No outbound PIPELINING, BDAT, connection reuse, BINARYMIME, DSN extension parameters, success DSNs, or delay DSNs.
- No ACME automation, hosted bounce processing, PROXY protocol, persistent rate-limit state, or exactly-once transaction identifier.

**Verified Controls**

- AUTH is TLS-only and unknown/disabled users receive comparable bounded Argon2 work.
- MAIL requires authentication; envelope sender and `From` are authorized.
- Recipient routing uses strict IDNA validation.
- Explicit resolved-IP dialing avoids a second resolver lookup.
- Private and special-use destinations are comprehensively filtered unless explicitly allowlisted.
- STARTTLS policy is fixed before dialing; advertised TLS failure never downgrades to plaintext.
- Verified TLS uses MX hostname/SNI, system roots, TLS 1.2+, and mandatory post-TLS EHLO.
- SMTP replies and stored diagnostics are bounded and sanitized.
- Partial RCPT outcomes, cancellation, null-sender DSN loop prevention, queue revision/incarnation guards, DSN reciprocal linking, and crash recovery are substantially implemented.
- Queue mutation is exclusively locked; stale revisions cannot commit transitions.
- Unix directory fsync and Windows `MoveFileEx(...WRITE_THROUGH)` paths are present.

**Verification Results**

All required commands passed:

```text
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
staticcheck ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go vet ./...
```

Focused repeated race suites also passed:

- Queue durability/recovery selection, `-count=10`
- Delivery concurrency/protocol selection, `-count=20`
- SMTP concurrency/limits selection, `-count=20`

No races or intermittent failures were observed. The existing tests do not model page-cache visibility versus durable storage, saturated same-domain fairness, header object amplification, or body mutation after reader validation.

`govulncheck` found no called or imported vulnerability. Verbose module analysis noted GO-2026-5932 in the unimported `golang.org/x/crypto/openpgp` package from `x/crypto v0.54.0`; it is not reachable by outboxd and has no available fix.

**Unverifiable Claims**

- True power-loss behavior depends on the deployed filesystem, controller cache, virtualization layer, and hardware flush implementation.
- Windows DACL inheritance and junction/reparse behavior were not exercised under the production service identity.
- Resolver integrity, CA-store contents, firewall policy, PTR reputation, certificate renewal, and real-world deliverability are deployment properties.
- Public-chain trust is checked by `outboxd check`, not necessarily by startup; private CA use may be intentional.
- Filesystem bit-rot protection cannot be established without body digests or a verified checksummed storage stack.