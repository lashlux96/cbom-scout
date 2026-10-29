"""Static engine: call-level AST analysis + certificate discovery.

Anti-false-positive rule: an *import* of a crypto module is never a finding.
Only an actual call site (with its arguments, when statically visible) is.
"""
from __future__ import annotations

import ast
from pathlib import Path

from cryptography import x509

from .classifier import WEAK_ALGORITHMS, evaluate_public_key
from .models import Finding

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "__pycache__", ".tox", "dist", "build"}
MAX_FILE_BYTES = 10 * 1024 * 1024
CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der"}


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _const_int(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.keyword) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
        return node.value.value
    return None


class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}  # local name -> fully qualified origin

    # -- import resolution -------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    def _resolve(self, dotted: str) -> str:
        head, _, rest = dotted.partition(".")
        return f"{self.aliases[head]}.{rest}" if head in self.aliases and rest else self.aliases.get(head, dotted)

    # -- call sites ----------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        dotted = self._resolve(_dotted(node.func))
        leaf = dotted.rsplit(".", 1)[-1]
        loc = f"{self.rel_path}:{node.lineno}"
        evidence = ast.unparse(node)[:200]

        def add(**kw) -> None:  # type: ignore[no-untyped-def]
            self.findings.append(Finding(location=loc, evidence=evidence, asset_type="algorithm", **kw))

        if leaf == "generate_private_key" or dotted.endswith("rsa.GenerateKey") or leaf == "GenerateKey":
            key_size = next((v for v in (_const_int(a) for a in node.args) if v), None) or \
                next((v for v in (_const_int(k) for k in node.keywords if k.arg in {"key_size", "bits"}) if v), None)
            weak = key_size is not None and key_size < 2048
            add(name="Asymmetric private key generation", algorithm="RSA/ECC (generate_private_key)",
                primitive="pke", key_size=key_size, parameter_set=str(key_size) if key_size else None,
                quantum_vulnerable=True, quantum_status="WEAK_CLASSICAL" if weak else "CRITICAL_SHORS_VULNERABLE",
                classical_security_bits=80 if weak else None, nist_quantum_level=0,
                crypto_functions=["keygen"],
                remediation=("Key size < 2048 bits is below NIST SP 800-131A minimum. " if weak else "")
                + "Plan migration to ML-KEM (FIPS 203) / ML-DSA (FIPS 204); wrap behind a crypto-agile interface.")
        elif leaf in WEAK_ALGORITHMS and ("." in dotted or leaf in {"MD5", "SHA1", "DES", "RC4"}):
            info = WEAK_ALGORITHMS[leaf]
            add(name=f"Weak algorithm call: {leaf}", algorithm=leaf, **info, quantum_vulnerable=False,
                crypto_functions=["digest"] if info["primitive"] == "hash" else ["encrypt", "decrypt"])
        elif leaf == "ECB":
            info = WEAK_ALGORITHMS["ECB"]
            add(name="ECB mode call", algorithm="ECB", **info, quantum_vulnerable=False,
                crypto_functions=["encrypt", "decrypt"])
        elif leaf == "Cipher":
            add(name="Symmetric Cipher construction", algorithm="symmetric-cipher", primitive="block-cipher",
                quantum_vulnerable=False, quantum_status="UNKNOWN", crypto_functions=["encrypt", "decrypt"],
                remediation="Verify AEAD mode and >=256-bit key for Grover margin (AES-256).")
        elif leaf in {"encode", "decode"} and "jwt" in dotted:
            add(name="JWT signing/verification", algorithm="JWT", primitive="signature",
                quantum_vulnerable=True, quantum_status="CRITICAL_SHORS_VULNERABLE", nist_quantum_level=0,
                crypto_functions=["sign", "verify"],
                remediation="RS*/ES* JWT algorithms are Shor-vulnerable; track for ML-DSA migration. Avoid 'none'/weak HMAC secrets.")
        elif leaf in {"wrap_socket", "SSLContext"} or "ssl." in dotted:
            add(name="TLS context configuration", algorithm="TLS", primitive="unknown",
                quantum_vulnerable=True, quantum_status="CRITICAL_SHORS_VULNERABLE", nist_quantum_level=0,
                remediation="Enforce TLS 1.3 and, where supported, hybrid ML-KEM groups (X25519MLKEM768).")
        self.generic_visit(node)


def _cert_finding(cert: x509.Certificate, rel: str) -> Finding:
    ev = evaluate_public_key(cert.public_key())
    return Finding(
        name=f"Certificate: {cert.subject.rfc4514_string() or '(empty subject)'}",
        asset_type="certificate", location=rel, cert_subject=cert.subject.rfc4514_string(),
        cert_issuer=cert.issuer.rfc4514_string(),
        cert_not_after=cert.not_valid_after_utc.isoformat(), **ev)


def scan_tree(root: str | Path, ignore_globs: list[str] | None = None) -> list[Finding]:
    """Walk `root` without ever following a symlink outside it."""
    root_path = Path(root).resolve()
    findings: list[Finding] = []
    ignore_globs = ignore_globs or []

    def ignored(rel: str) -> bool:
        return any(Path(rel).match(g) or rel == g for g in ignore_globs)

    import os
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink()]
        for filename in filenames:
            path = Path(dirpath) / filename
            rel = str(path.relative_to(root_path))
            if ignored(rel) or path.is_symlink():
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                if path.suffix == ".py":
                    tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=rel)
                    scanner = PythonASTScanner(rel)
                    scanner.visit(tree)
                    findings.extend(scanner.findings)
                elif path.suffix in CERT_SUFFIXES:
                    raw = path.read_bytes()
                    certs = []
                    if b"-----BEGIN CERTIFICATE-----" in raw:
                        certs = x509.load_pem_x509_certificates(raw)
                    elif path.suffix in {".der", ".cer"}:
                        try:
                            certs = [x509.load_der_x509_certificate(raw)]
                        except ValueError:
                            certs = []
                    findings.extend(_cert_finding(c, rel) for c in certs)
            except (SyntaxError, ValueError, OSError):
                continue  # a scanner must never crash on hostile/corrupt input
    return findings


def load_ignore_file(root: str | Path) -> list[str]:
    f = Path(root) / ".cbom-ignore"
    if not f.exists():
        return []
    return [ln.strip() for ln in f.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
