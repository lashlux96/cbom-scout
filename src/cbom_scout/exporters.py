"""CycloneDX v1.6 exporter.

Spec compliance notes: v1.6 `cryptoProperties` has no `quantumProperties`
object (the blueprint's invention would fail schema validation). Quantum
posture is therefore expressed through the spec's real fields —
`algorithmProperties.classicalSecurityLevel` / `nistQuantumSecurityLevel`
(0 = Shor-broken) — plus namespaced `cbom:*` component properties, which
the schema explicitly permits.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import Finding


def _component(f: Finding) -> dict:
    props = [
        {"name": "cbom:location", "value": f.location},
        {"name": "cbom:quantumStatus", "value": f.quantum_status},
        {"name": "cbom:confidence", "value": f.confidence},
    ]
    if f.remediation:
        props.append({"name": "cbom:remediation", "value": f.remediation})
    if f.evidence:
        props.append({"name": "cbom:evidence", "value": f.evidence})

    crypto: dict = {"assetType": f.asset_type}
    if f.asset_type == "protocol":
        suite: dict = {"name": f.cipher_suite or "unknown"}
        crypto["protocolProperties"] = {"type": "tls", "version": (f.tls_version or "").removeprefix("TLSv"),
                                        "cipherSuites": [suite]}
        crypto["algorithmProperties"] = {"primitive": f.primitive, "parameterSetIdentifier": f.parameter_set or f.algorithm,
                                         "executionEnvironment": "software-plain-ram", "cryptoFunctions": f.crypto_functions or ["keyderive"]}
    elif f.asset_type == "certificate":
        crypto["certificateProperties"] = {
            "certificateFormat": "X.509", "subjectName": f.cert_subject or "", "issuerName": f.cert_issuer or ""}
        if f.cert_not_after:
            crypto["certificateProperties"]["notValidAfter"] = f.cert_not_after
        crypto["algorithmProperties"] = {"primitive": f.primitive, "parameterSetIdentifier": f.parameter_set or f.algorithm,
                                         "cryptoFunctions": f.crypto_functions or ["verify"]}
    else:
        crypto["algorithmProperties"] = {"primitive": f.primitive, "parameterSetIdentifier": f.parameter_set or f.algorithm,
                                         "executionEnvironment": "software-plain-ram",
                                         "cryptoFunctions": f.crypto_functions or ["unknown"]}
    algo = crypto["algorithmProperties"]
    if f.classical_security_bits is not None:
        algo["classicalSecurityLevel"] = f.classical_security_bits
    if f.nist_quantum_level is not None:
        algo["nistQuantumSecurityLevel"] = f.nist_quantum_level

    return {"type": "cryptographic-asset", "bom-ref": f"crypto-asset-{f.id}", "name": f.name,
            "properties": props, "cryptoProperties": crypto}


def to_cyclonedx(findings: list[Finding]) -> dict:
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "cbom-scout", "version": __version__,
                                       "bom-ref": "tool-cbom-scout"}]},
            "component": {"type": "application", "bom-ref": "root-application", "name": "scanned-target"},
        },
        "components": [_component(f) for f in findings],
    }


def to_sarif(findings: list[Finding]) -> dict:
    results = [{
        "ruleId": f"cbom/{f.quantum_status.lower()}",
        "level": "error" if f.quantum_vulnerable or f.quantum_status == "WEAK_CLASSICAL" else "note",
        "message": {"text": f"{f.name}: {f.algorithm} at {f.location}. {f.remediation}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location.split(":")[0]},
                                            "region": {"startLine": int(f.location.rsplit(":", 1)[-1]) if f.location.rsplit(":", 1)[-1].isdigit() else 1}}}],
    } for f in findings]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cbom-scout", "version": __version__,
                                          "rules": [{"id": "cbom/critical_shors_vulnerable", "shortDescription": {"text": "Shor-vulnerable cryptography"}}]}},
                      "results": results}]}


def write_cyclonedx(findings: list[Finding], output: str | Path) -> Path:
    p = Path(output)
    p.write_text(json.dumps(to_cyclonedx(findings), indent=2))
    return p


def write_sarif(findings: list[Finding], output: str | Path) -> Path:
    p = Path(output)
    p.write_text(json.dumps(to_sarif(findings), indent=2))
    return p
