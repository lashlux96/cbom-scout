from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """One cryptographic asset. Fields map onto CycloneDX 1.6 cryptoProperties."""

    name: str
    asset_type: str  # algorithm | certificate | protocol | related-crypto-material
    location: str
    primitive: str = "unknown"  # must be a CycloneDX 1.6 primitive enum value
    algorithm: str = "unknown"
    parameter_set: str | None = None
    key_size: int | None = None
    quantum_vulnerable: bool | None = None
    quantum_status: str = "UNKNOWN"  # CRITICAL_SHORS_VULNERABLE | QUANTUM_RESISTANT | HYBRID_TRANSITIONAL | WEAK_CLASSICAL | UNKNOWN
    classical_security_bits: int | None = None
    nist_quantum_level: int | None = None  # 0 (broken by quantum) .. 5
    crypto_functions: list[str] = field(default_factory=list)
    remediation: str = ""
    confidence: str = "high"  # AST call-site evidence, not an import guess
    evidence: str = ""
    tls_version: str | None = None
    cipher_suite: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_after: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", [])}
