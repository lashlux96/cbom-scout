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

## Installation

**Prerequisites:** Python 3.11 or newer, and `git`. The recommended installer
is [`uv`](https://docs.astral.sh/uv/) (it enforces the 7-day dependency
cool-off described below); plain `pip` also works.

```bash
git clone git@github.com:lashlux96/cbom-scout.git
cd cbom-scout
```

**Option A — uv (recommended):**

```bash
uv sync --locked --all-extras   # creates .venv from the pinned uv.lock
uv run cbom-scout version       # sanity check: prints "cbom-scout 0.1.0"
```

**Option B — pip / venv:**

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cbom-scout version
```

With uv, prefix every command below with `uv run` (as shown). With pip and an
activated venv, run `cbom-scout ...` directly. You can also run the module
form: `python -m cbom_scout scan ...`. For full option help at any time:
`cbom-scout scan --help`.

## Running the tool

The single command is `cbom-scout scan`. It always writes a CycloneDX CBOM
JSON file (default: `cyclonedx-cbom.json`) and prints a summary table.

**1. Scan a codebase** (static AST + certificates under the given path):

```bash
uv run cbom-scout scan /path/to/your/project
uv run cbom-scout scan . -o my-cbom.json          # custom output file
```

**2. Try the bundled examples first** (a safe smoke test):

```bash
uv run cbom-scout scan examples
# -> 4 findings, all from examples/vulnerable_app.py (1024-bit keygen, MD5,
#    ECB, Cipher); examples/safe_app.py (import-only) yields zero findings.
```

**3. Probe a live TLS endpoint** (works for internal hosts and non-443 ports
too; repeat `--probe` for multiple targets). Use `--probe-only` to skip the
static scan of the current directory:

```bash
uv run cbom-scout scan . --probe-only --probe google.com:443
uv run cbom-scout scan . --probe-only --probe internal.corp:8443 --probe db.corp:5432
```

**4. Check post-quantum key-exchange support** (raw ClientHello prober —
reports the group the server actually selects, e.g. `X25519MLKEM768` vs
classical X25519):

```bash
uv run cbom-scout scan . --probe-only --pqc-probe google.com:443
```

**5. Combine everything, with SARIF output** for GitHub Code Scanning:

```bash
uv run cbom-scout scan . \
  --probe api.example.com:443 --pqc-probe api.example.com:443 \
  -o cyclonedx-cbom.json --sarif cbom.sarif
```

**Inspect the result:**

```bash
python3 -m json.tool cyclonedx-cbom.json | head -50
```

**Useful flags:**

- `--fail-on-vulnerable` — exit code 1 if any Shor-vulnerable or weak crypto
  is found; use this as a CI gate (`uv run cbom-scout scan . --fail-on-vulnerable`).
- `--sarif <file>` — additionally write SARIF for GitHub's Security tab.
- `-o <file>` — CBOM output path (default `cyclonedx-cbom.json`).
- **`.cbom-ignore`** — put one glob per line in a file at the scan root to
  suppress known legacy findings (e.g. `legacy/*.py`).

**Troubleshooting:** `command not found: cbom-scout` → use `uv run cbom-scout ...`
or activate the venv. A probe that "fails" with a timeout usually means the
host doesn't expose TLS on that port (or a firewall drops it) — the scan
continues and still writes the CBOM from the remaining engines. Run the test
suite with `uv run pytest`.

## Supply-chain cool-off (7 days)

New dependency releases are a common supply-chain attack window (compromised
maintainer, yanked-then-replaced artifacts). This project therefore enforces
a **7-day minimum release age** before a dependency version may be used:

- **Resolver:** `[tool.uv] exclude-newer = "7 days"` in `pyproject.toml` —
  `uv lock`/`uv sync`/`uv add` cannot select a version published < 7 days ago.
- **Lockfile:** `uv.lock` pins the vetted set; CI installs with
  `uv sync --locked`, so CI never re-resolves around the cool-off.
- **Dependabot:** `.github/dependabot.yml` sets a 7-day cooldown (14 for
  major bumps), so update PRs aren't even opened for fresh releases.

The cool-off governs *resolution and upgrades*, not installs from the
existing lockfile — pinned versions in `uv.lock` are already past it.

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
- AST engine is Python-only in v0.1 (Go support is planned). Runtime eBPF
  discovery (uprobes on `SSL_do_handshake`, `sys_enter_connect` PID mapping)
  is not yet implemented, so internal-only traffic is not yet covered.

## License

MIT
