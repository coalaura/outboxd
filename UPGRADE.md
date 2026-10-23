# Upgrade Guide

## Upgrading to v0.7.0

v0.7.0 adds opt-in recipient WKD discovery and private caching. Configurations and queued mail from v0.6.0 remain compatible; no configuration or queue migration is required. WKD discovery stays disabled unless `openpgp.use_wkd` is explicitly enabled. Upgrades from v0.5.1 and earlier must first apply the [v0.6.0 configuration migration](#upgrading-to-v060) below.

Stop the daemon and privately back up the configuration before replacing the binary. Follow [updating configuration comments and defaults](README.md#updating-configuration-comments-and-defaults) to add the documented `openpgp.use_wkd: false` and `openpgp.wkd_cache_directory: openpgp/cache` defaults while retaining configured values. Run `check` as the service account before restarting.

To enable discovery, set `openpgp.use_wkd: true` and list the exact required recipient addresses in `openpgp.require_encryption_for`. Local recipient keys take precedence; WKD is used only for required recipients without a local key. Startup and `check` require a usable key for every required recipient and fail rather than permitting plaintext fallback. Allow outbound DNS and verified HTTPS on port 443 to public WKD endpoints when discovery is enabled.

The WKD cache defaults to `openpgp/cache` beneath `server.data_directory` and must remain private and writable by the service account. Valid cached keys are reused for up to 24 hours at load time; older or unusable keys require a successful refresh. Loaded keys remain startup state, so restart to pick up key changes. To force discovery before a cache entry expires, remove the corresponding entry while the daemon is stopped. See [OpenPGP signing, encryption and key discovery](README.md#openpgp-signing-encryption-and-key-discovery) for the full lookup, validation and cache policy.

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
