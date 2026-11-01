# Changelog

All notable changes to cbom-scout are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-31

First public release.

### Added

- **Static engine** — call-level Python AST scanning (import-resolved; an
  import alone is never a finding) for key generation (with key-size
  extraction), weak hashes (MD5/SHA-1), DES/3DES/RC4, ECB mode, symmetric
  cipher construction, JWT, and TLS contexts; PEM/DER X.509 certificate
  discovery with algorithm/key/subject/expiry parsing. Symlink-safe tree
  walking and `.cbom-ignore` suppression globs.
- **Live TLS probe** (`--probe`) — negotiated TLS version, cipher suite, and
  leaf-certificate public key for any host:port, including internal services.
- **Raw PQC probe** (`--pqc-probe`) — hand-built TLS 1.3 ClientHello offering
  hybrid ML-KEM groups first (`X25519MLKEM768`, `SecP256r1MLKEM768`,
  `SecP384r1MLKEM1024`, draft Kyber) with coefficient-valid probe shares;
  parses ServerHello/HelloRetryRequest (with HRR confirmation retry) to report
  the key-exchange group a server actually selects.
- **Classifier** — NIST FIPS 203/204/205 and CNSA 2.0 posture: RSA/ECC/EdDSA/
  DSA classified `CRITICAL_SHORS_VULNERABLE` (quantum level 0), hybrid groups
  as transitional (levels 3/5), weak classical algorithms flagged separately,
  with remediation guidance per finding.
- **Exporters** — CycloneDX v1.6 CBOM JSON (validated against the official
  schema), SARIF for GitHub Code Scanning, and a Rich terminal summary.
  `--fail-on-vulnerable` provides a CI gate; `--probe-only` enables
  network-only scans.
- **Supply-chain hardening** — 7-day dependency cool-off
  (`[tool.uv] exclude-newer`), committed `uv.lock`, locked CI installs
  (Python 3.11–3.13), and Dependabot cooldown configuration.

### Verified

- Output validates against the official CycloneDX 1.6 schema
  (`bom-1.6.schema.json`).
- Live-verified against public endpoints: google.com and cloudflare.com
  negotiate `X25519MLKEM768`; github.com selects classical X25519.
