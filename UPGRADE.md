# Upgrade Guide

## Upgrading to v0.6.0

v0.6.0 replaces `server.domain` and the top-level `dkim` section with the `domains` list. Configurations from v0.5.1 and earlier must be edited before the new binary can load them; `config update` requires a valid configuration and does not migrate these removed fields automatically.

Stop the daemon and privately back up the configuration before replacing the binary. Remove `server.domain`, use its existing value as the first `domains[].name` and move the entire top-level `dkim` section under that entry. Keep the existing selector, private-key path and signed-header list so the published DKIM record and create-once key remain valid. For example, an existing `example.com` identity with selector `mail` and key path `dkim/mail.key` becomes:

```yaml
domains:
  - name: example.com
    dkim:
      selector: mail
      private_key_file: dkim/mail.key
      headers: [From, To, Subject, Date, Message-ID, MIME-Version, Content-Type, Content-Transfer-Encoding, Reply-To, Sender, Autocrypt]
```

Use your existing values rather than substituting the example's. Leave the other configuration sections and queued mail in place. For additional domains, use distinct key paths, explicitly authorize sender addresses and run `provision` as the service account to create only the missing keys. Publish the output of `dns`, run `check` and restart after [updating configuration comments and defaults](README.md#updating-configuration-comments-and-defaults).
