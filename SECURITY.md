# Security Policy

## Supported Versions

| Version  | Supported |
| -------- | --------- |
| 0.4.0    | Yes       |
| <= 0.3.0 | No        |

Only the latest release receives security updates. outboxd is new software; review the documentation and security notes before deploying it in production.

Security reports affecting supported releases or the current `master` branch are welcome.

## Project Status

outboxd 0.1.0 was the first stable release. The maintainer uses outboxd for personal self-hosted services that need outgoing email, including GlitchTip error reporting and Beszel monitoring.

It is not currently deployed in large-scale infrastructure and is not backed by a company. This project does not provide an SLA or other support guarantee. Review the documentation and security notes before deploying it in production.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately using [GitHub Private Vulnerability Reporting](https://github.com/coalaura/outboxd/security/advisories/new).

Do not report security vulnerabilities through public GitHub issues, discussions, pull requests or social media.

A useful report includes:

* The affected version, commit or configuration.
* A clear description of the issue and its security impact.
* Reproduction steps or a minimal proof of concept.
* Relevant logs, configuration details and environmental assumptions.
* A suggested fix, if you have one.

Please do not access data that is not yours, disrupt systems, send mail to recipients you do not control or use destructive testing while validating a report.

## Handling Reports

Reports are assessed in good faith. Additional information may be requested to reproduce and understand an issue.

For confirmed vulnerabilities, a fix will be prepared where practical and disclosure will be coordinated with the reporter. Please allow a reasonable opportunity to prepare and release a fix before disclosing details publicly.

With your permission, confirmed reports may credit you in the relevant security advisory or release notes.
