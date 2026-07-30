# outboxd

Outbound-only mail submission and delivery daemon. Clients submit over authenticated SMTP (ports 587/465); outboxd DKIM-signs and delivers outbound on port 25. It is **not** an inbound MX and does not accept public mail on port 25.

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
outboxd -config /etc/outboxd/config.yml          # serve
outboxd -config ... user add alice alice@example.com
outboxd -config ... dns
outboxd -config ... check
outboxd -config ... dead list|show|retry|export <id>
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

## TLS

| `tls.mode` | Meaning |
|------------|---------|
| `self_signed` | **Development only.** Generates an untrusted leaf (not a CA). Ordinary MUAs will reject it. |
| `files` | Operator-supplied certificate + key paths. Use a publicly trusted cert in production. |

Minimum TLS version is configurable (`1.2` / `1.3`). Certificate files are hot-reloaded; a bad reload keeps the last valid cert.

Outbound delivery TLS policy is separate (`delivery.tls_mode`: `opportunistic`, `required`, `opportunistic_insecure`).

## Queue semantics

- On-disk spool under the data directory: **at-least-once** delivery. A crash between a successful remote DATA response and local `Finish` can redeliver; receivers must tolerate duplicates.
- Exhausted or permanently failed messages move to the **dead-letter** area (`outboxd dead …`).
- Quotas: `max_queue_messages`, `max_queue_bytes`, `min_free_disk_bytes`, plus per-user hourly message/recipient limits.

## Configuration

See the generated `config.yml` comments after first start. Important knobs:

- `server.hostname` / `server.domain` — HELO name vs organizational domain
- `server.max_message_bytes`, connection and auth worker limits
- `dns.*` — public IPs and DNS generation only (not outbound bind addresses)
- `delivery.bind_ipv4` / `bind_ipv6` — must exist on a local interface at startup

## Commands

```
outboxd [-config path]              # run submission + delivery
outboxd user add <user> [senders…]  # append user via config.AddUser
outboxd dns                         # write and print DNS instructions
outboxd check                       # PASS/WARN/FAIL deployment checks
outboxd dead list|show|retry|export
```

`OUTBOXD_CONFIG` overrides the default `config.yml` path when `-config` is omitted.
