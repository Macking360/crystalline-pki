# Security

crystalline-pki is a research and learning tool, not a production certificate
authority. Do not use its lab root to secure anything you cannot afford to lose.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or email the
maintainer listed on the repository profile. Please include steps to reproduce.
Do not open a public issue for a vulnerability.

## What is in scope

- The local web interface (token handling, Host/Origin checks, request limits)
- Path handling for exports and reports
- The URL validation that restricts the site examiner to public HTTPS hosts
- The audit hash chain and CRL enforcement

## Known, documented limits

See the Limitations section of the README. In particular: private keys are
unencrypted PEM files, and the audit chain is tamper-evident but not tamper-proof.

## Responsible use

The site examiner sends one `HEAD` request per examination. Use it only against
sites you own or are permitted to test.
