"""Live TLS probe.

Honesty note: Python's stdlib `ssl` cannot offer or observe PQC/hybrid
NamedGroups (that needs raw ClientHello construction or an OpenSSL 3.5+ /
oqs-provider build). So this probe reports exactly what stdlib *can* prove —
negotiated version, cipher suite, and the peer leaf certificate's public key —
and marks hybrid/PQC negotiation as UNKNOWN rather than guessing. A raw
ClientHello prober is the Week-3 roadmap item in the README.
"""
from __future__ import annotations

import socket
import ssl

from cryptography import x509

from .classifier import evaluate_public_key
from .models import Finding


def probe_tls_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> Finding | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inventory, not validation; we record what is served
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher() or ("unknown", ssock.version(), 0)
                der = ssock.getpeercert(binary_form=True)
                ev: dict = {}
                subject = None
                if der:
                    cert = x509.load_der_x509_certificate(der)
                    ev = evaluate_public_key(cert.public_key())
                    subject = cert.subject.rfc4514_string()
                return Finding(
                    name=f"Live TLS endpoint {host}:{port}", asset_type="protocol",
                    location=f"tls://{host}:{port}", primitive="key-agree",
                    algorithm=ev.get("algorithm", "unknown"), key_size=ev.get("key_size"),
                    parameter_set=ev.get("parameter_set"), tls_version=ssock.version(),
                    cipher_suite=cipher[0], cert_subject=subject,
                    quantum_vulnerable=ev.get("quantum_vulnerable", True),
                    quantum_status=ev.get("quantum_status", "CRITICAL_SHORS_VULNERABLE"),
                    classical_security_bits=ev.get("classical_security_bits"),
                    nist_quantum_level=ev.get("nist_quantum_level", 0),
                    crypto_functions=["key-agree", "encrypt", "decrypt"],
                    remediation=(ev.get("remediation", "") +
                                 " PQC group negotiation (X25519MLKEM768) could not be determined via stdlib ssl; verify with the raw ClientHello prober.").strip(),
                    evidence=f"{ssock.version()} {cipher[0]} bits={cipher[2]}")
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"[!] TLS probe failed for {host}:{port} -> {exc}")
        return None
