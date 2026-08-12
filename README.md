# outboxd

outboxd is a small outbound mail server for straightforward, properly signed mail delivery. It accepts authenticated SMTP submission from configured users, DKIM-signs messages, queues them durably and delivers them to recipient MX servers.

It is for sending mail. It is not an inbound MX, mailbox server, IMAP server, spam filter or webmail application.

The project was started after I spent way too long configuring Postfix, Dovecot and OpenDKIM to work together for a small sending service. The intended setup is one complete, understandable configuration file and one private data directory: set a hostname, sending domain and public IP, provision key material, add users, publish the generated DNS records, then start the daemon.

## What You Need

- A server with a stable public IP and outbound TCP port 25 available.
- A hostname such as `mail.example.com` with matching forward and reverse DNS.
- A sending domain such as `example.com`.
- A publicly trusted TLS certificate for the submission hostname. Let's Encrypt paths are supported in `tls.mode: files`.
- A private local filesystem for `data_directory`. Put it on a quota-controlled volume if disk exhaustion matters.

outboxd listens for authenticated submission on port 587 (STARTTLS) and port 465 (implicit TLS) by default. It sends mail outbound on TCP port 25. It does not listen for internet mail on port 25.

## Quick Start

Choose a config path, then create the initial configuration:

```bash
outboxd -config /etc/outboxd/config.yml provision
```

The first run creates a commented config file and stops. Edit the essentials:

```yaml
server:
  hostname: mail.example.com
  domain: example.com
  data_directory: /var/lib/outboxd

tls:
  mode: files
  certificate_file: /etc/letsencrypt/live/mail.example.com/fullchain.pem
  private_key_file: /etc/letsencrypt/live/mail.example.com/privkey.pem

dns:
  public_ipv4: 203.0.113.10
```

Set the remaining options in the generated comments as needed. In particular, keep the default secure outbound TLS policy unless you intentionally need a weaker compatibility policy.

Provision again to create the data directory, spool and create-once DKIM key:

```bash
outboxd -config /etc/outboxd/config.yml provision
```

Add an SMTP user. If stdin is a terminal, outboxd generates a password and prints it once. To supply one yourself, pipe a single-line password of at least 12 bytes.

```bash
outboxd -config /etc/outboxd/config.yml user add alice alice@example.com
printf '%s\n' 'a-long-password' | outboxd -config /etc/outboxd/config.yml user add alice alice@example.com
```

Generate the DNS instructions while the daemon is stopped:

```bash
outboxd -config /etc/outboxd/config.yml dns
```

Copy the generated records into DNS, then verify the deployment and start the service:

```bash
outboxd -config /etc/outboxd/config.yml check
outboxd -config /etc/outboxd/config.yml serve
```

`dns`, `check` and `serve` load an existing DKIM key; they never create or replace one. Run `provision` if the key is missing. Stop the daemon before running `dns`, changing the DKIM key or generated DNS path or changing the config/data-directory path.

## DNS Checklist

`outboxd dns` writes and prints the records to publish. It includes the DKIM record and guidance for SPF, DMARC and TLS-RPT.

- Publish A (and optionally AAAA) for `server.hostname` using `dns.public_ipv4` and `dns.public_ipv6`.
- Set reverse DNS for each sending IP to `server.hostname` and ensure the hostname resolves back to the same IP.
- Publish the generated DKIM TXT record.
- Publish one SPF TXT record for each sending identity domain.
- Start DMARC with `p=none`, inspect reports, then move to `quarantine` or `reject` when appropriate.
- Use a separate service with an MX record for bounces, replies and DMARC reports. outboxd does not receive mail.

New IPs also need normal reputation work: authenticated users only, sensible sending rates and low complaint rates.

## Configuration And Files

The generated `config.yml` documents every setting. Relative paths resolve next to the config file; generated DKIM material, self-signed development TLS material, DNS instructions and queue state live under `server.data_directory`.

Operator-managed TLS files may be outside `data_directory`, which is useful for Let's Encrypt. The config ownership lock and short-lived atomic-write files live beside the config file.

Configuration, users, DKIM keys, queue limits and delivery policy are loaded at startup. Restart outboxd after changing them. TLS certificate and key contents are the only runtime-reloaded files.

Useful limits include:

- `server.max_queue_messages` and `server.max_queue_bytes` for the ready queue.
- `server.max_queue_messages_per_user` and `server.max_queue_bytes_per_user` to keep one account from consuming the shared ready queue.
- `server.max_spool_bytes`, `spool_emergency_bytes` and `min_free_disk_bytes` for conservative spool admission control.
- `delivery.user_concurrency`, `domain_concurrency`, `global_concurrency` and candidate/deadline limits for outbound work.

`max_spool_bytes` is an admission estimate, not an operating-system disk quota. Use a dedicated local volume with an OS/filesystem quota as the actual physical boundary.

## Queue And Failures

Mail is durably queued before outboxd reports SMTP acceptance. Delivery is at least once: if a crash or lost final SMTP response occurs after a recipient accepts DATA but before local completion is recorded, a message can be delivered again.

Permanent failures and exhausted retries move to the dead-letter area. Corrupt entries are isolated rather than stopping unrelated delivery. Retention pruning runs at daemon startup and periodically while serving.

The spool must be private to the outboxd service account. Do not place symlinks, junctions, mount points or files created by other processes below it.

## Operations

```text
outboxd [-config path] serve                 # default when no command is given
outboxd [-config path] provision             # create config, data/spool and DKIM key
outboxd [-config path] user add <user> [sender...]
outboxd [-config path] dns                   # write and print DNS instructions
outboxd [-config path] check                 # verify local configuration and DNS
outboxd [-config path] dead list
outboxd [-config path] dead show <id>
outboxd [-config path] dead export <id>
outboxd [-config path] dead retry <id>
outboxd [-config path] dead delete <id>
outboxd [-config path] corrupt list
outboxd [-config path] corrupt delete <name>
```

Use `OUTBOXD_CONFIG` instead of `-config` to select a config path.

## Security Notes

- Use `tls.mode: files` with a publicly trusted certificate in production. `self_signed` is development-only and requires an explicit opt-in.
- Keep the config, DKIM key and data directory readable and writable only by the service account. On Windows, configure the service account and ACLs yourself.
- Outbound delivery defaults to verified, required TLS. Do not enable plaintext or insecure TLS unless the compatibility tradeoff is deliberate.
- outboxd does not implement inbound mail, DANE, MTA-STS or DNSSEC validation.
- A private local filesystem with reliable rename/sync behavior is required for the queue durability guarantees.
