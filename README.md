# cbom-scout

Open-source **Cryptographic Bill of Materials (CBOM)** engine. It inventories
the cryptography actually in use — in code and on the wire — and exports a
standards-compliant **CycloneDX v1.6** CBOM with NIST post-quantum risk
classification (FIPS 203/204/205, CNSA 2.0 posture).

## Why not just grep?

`grep -r "crypto/rsa"` flags every import, comment, and test fixture. cbom-scout
parses the Python AST and resolves imports to call sites: an import alone
produces **zero findings**, while `rsa.generate_private_key(..., key_size=1024)`
produces one, with file:line, evidence, key size, and remediation.
See `examples/safe_app.py` (zero findings) vs `examples/vulnerable_app.py`.

## Quickstart

```bash
pip install -e ".[dev]"
cbom-scout scan . --probe example.com:443 --pqc-probe example.com:443 -o cyclonedx-cbom.json --sarif cbom.sarif
cbom-scout scan . --fail-on-vulnerable   # CI gate: exit 1 on Shor-vulnerable / weak crypto
pytest
```

Suppress known legacy debt with a `.cbom-ignore` file (one glob per line).

## What it detects (v0.1 MVP)

| Engine | Coverage |
|---|---|
| Static AST | Python call sites: `generate_private_key` (+ key size), weak hashes (MD5/SHA-1), DES/3DES/RC4, ECB mode, symmetric `Cipher`, JWT, TLS contexts — import-resolved, call-level only |
| Certificates | PEM/DER X.509 in the tree: algorithm, key size/curve, subject/issuer, expiry |
| Live TLS probe | Negotiated TLS version + cipher suite + peer leaf public key for any host:port (incl. internal services) |
| Raw PQC probe (`--pqc-probe`) | Hand-built TLS 1.3 ClientHello offering hybrid groups first (`X25519MLKEM768` 0x11ec, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, draft Kyber) with coefficient-valid ML-KEM probe shares; parses ServerHello/HelloRetryRequest to report the group the server *actually selects*, with an HRR confirmation retry |
| Classifier | RSA/ECC/EdDSA/DSA → `CRITICAL_SHORS_VULNERABLE` (NIST quantum level 0), weak classical algos, classical security bits, ML-KEM/ML-DSA parameter sets |
| Exporters | CycloneDX v1.6 JSON (schema-shaped `cryptoProperties`), SARIF for GitHub Code Scanning, Rich terminal table |

Safety: the tree walker never follows symlinks, skips VCS/vendor dirs, caps
file size, and never crashes on corrupt input.

## CycloneDX 1.6 compliance note

CycloneDX 1.6 `cryptoProperties` has **no** `quantumProperties` object — tools
that emit one fail schema validation. cbom-scout expresses quantum posture via
the spec's real fields (`classicalSecurityLevel`, `nistQuantumSecurityLevel`,
where 0 = broken by Shor) plus namespaced `cbom:quantumStatus` /
`cbom:remediation` component properties, which the schema permits.

Validate output yourself:

```bash
pip install check-jsonschema
check-jsonschema --schemafile https://cyclonedx.org/schema/bom-1.6.schema.json cyclonedx-cbom.json
```

## Known limitations (stated, not hidden)

- The stdlib-based `--probe` still cannot offer PQC groups (use `--pqc-probe`
  for that; the two are complementary — cert identity vs. group negotiation).
  The raw prober reads group selection only and never completes the handshake:
  its ML-KEM shares are coefficient-valid probe encodings, not real keypairs.
  Verified live: google.com and cloudflare.com select `X25519MLKEM768`;
  github.com selects classical X25519 despite hybrid being offered first.
- AST engine is Python-only in v0.1; Go (`go/parser`) is next. eBPF runtime
  discovery (uprobes on `SSL_do_handshake`, `sys_enter_connect` PID mapping)
  remains the differentiation wedge on the roadmap below.

## Roadmap

1. ~~Raw TLS ClientHello prober with hybrid PQC key shares~~ ✅ done; next: cert-chain analysis
2. Go AST engine; Terraform/Kubernetes/NGINX crypto-config parsers; ELF/container linked-library scan
3. eBPF runtime engine (Linux): libssl uprobes + socket/PID mapping for internal mTLS discovery
4. GitHub Action + baseline diffing; Docker image

## License

MIT
