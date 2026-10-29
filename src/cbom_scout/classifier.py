"""NIST / CNSA 2.0 classification.

Quantum facts used here (not marketing):
- RSA, finite-field DH/DSA, and ECC (ECDH/ECDSA/EdDSA) are broken by Shor's
  algorithm on a cryptographically relevant quantum computer -> level 0.
- Symmetric crypto is only weakened quadratically by Grover: AES-256 and
  SHA-384+ remain acceptable; AES-128 is marginal.
- FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA are the standardized
  replacements. CNSA 2.0 targets ML-KEM-1024 / ML-DSA-87 for NSS, with
  ML-KEM-768 / ML-DSA-65 as the common commercial baseline.
"""
from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

VULNERABLE = "CRITICAL_SHORS_VULNERABLE"
RESISTANT = "QUANTUM_RESISTANT"
HYBRID = "HYBRID_TRANSITIONAL"
WEAK = "WEAK_CLASSICAL"

_RSA_REMEDIATION = "Migrate key establishment to ML-KEM-768/1024 (FIPS 203) and signatures to ML-DSA-65/87 (FIPS 204); hybrid X25519+ML-KEM-768 during transition."
_ECC_REMEDIATION = "Replace with ML-DSA-65 (FIPS 204) for signatures or hybrid X25519+ML-KEM-768 (FIPS 203) for key exchange."


def _classical_bits_rsa(bits: int) -> int:
    return {1024: 80, 2048: 112, 3072: 128, 4096: 140, 7680: 192}.get(bits, 112 if bits >= 2048 else 80)


def evaluate_public_key(pub_key: Any) -> dict[str, Any]:
    if isinstance(pub_key, rsa.RSAPublicKey):
        return dict(algorithm="RSA", primitive="pke", key_size=pub_key.key_size,
                    parameter_set=str(pub_key.key_size), quantum_vulnerable=True,
                    quantum_status=VULNERABLE, classical_security_bits=_classical_bits_rsa(pub_key.key_size),
                    nist_quantum_level=0, crypto_functions=["encrypt", "verify"], remediation=_RSA_REMEDIATION)
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return dict(algorithm=f"EC-{pub_key.curve.name}", primitive="key-agree",
                    key_size=pub_key.curve.key_size, parameter_set=pub_key.curve.name,
                    quantum_vulnerable=True, quantum_status=VULNERABLE,
                    classical_security_bits=pub_key.curve.key_size // 2,
                    nist_quantum_level=0, crypto_functions=["keyderive", "verify"], remediation=_ECC_REMEDIATION)
    if isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        name = "Ed25519" if isinstance(pub_key, ed25519.Ed25519PublicKey) else "Ed448"
        return dict(algorithm=name, primitive="signature", key_size=256, parameter_set=name,
                    quantum_vulnerable=True, quantum_status=VULNERABLE, classical_security_bits=128,
                    nist_quantum_level=0, crypto_functions=["sign", "verify"],
                    remediation="Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).")
    if isinstance(pub_key, dsa.DSAPublicKey):
        return dict(algorithm="DSA", primitive="signature", key_size=pub_key.key_size,
                    parameter_set=str(pub_key.key_size), quantum_vulnerable=True,
                    quantum_status=VULNERABLE, classical_security_bits=80, nist_quantum_level=0,
                    crypto_functions=["sign", "verify"], remediation=_RSA_REMEDIATION)
    # PQC keys from `cryptography` or other libs land here: never claim vulnerable without evidence.
    return dict(algorithm=type(pub_key).__name__, primitive="unknown", key_size=None,
                parameter_set=type(pub_key).__name__, quantum_vulnerable=None,
                quantum_status="UNKNOWN", classical_security_bits=None, nist_quantum_level=None,
                crypto_functions=[], remediation="Audit manually; algorithm not in classical catalog.")


# Weak classical algorithms flagged at AST call sites regardless of quantum risk.
WEAK_ALGORITHMS: dict[str, dict[str, Any]] = {
    "MD5": dict(primitive="hash", quantum_status=WEAK, classical_security_bits=0,
                remediation="MD5 is collision-broken. Use SHA-256+ (SHA-384+ if quantum margin matters)."),
    "SHA1": dict(primitive="hash", quantum_status=WEAK, classical_security_bits=0,
                 remediation="SHA-1 is collision-broken (SHAttered). Use SHA-256+."),
    "DES": dict(primitive="block-cipher", quantum_status=WEAK, classical_security_bits=56,
                remediation="DES/3DES are deprecated (NIST SP 800-131A). Use AES-256-GCM."),
    "3DES": dict(primitive="block-cipher", quantum_status=WEAK, classical_security_bits=112,
                 remediation="3DES is deprecated. Use AES-256-GCM."),
    "RC4": dict(primitive="stream-cipher", quantum_status=WEAK, classical_security_bits=0,
                remediation="RC4 is prohibited (RFC 7465). Use AES-GCM or ChaCha20-Poly1305."),
    "ECB": dict(primitive="block-cipher", quantum_status=WEAK, classical_security_bits=None,
                remediation="ECB leaks plaintext structure. Use an AEAD mode (GCM/ChaCha20-Poly1305)."),
}

PQC_ALGORITHMS: dict[str, dict[str, Any]] = {
    "ML-KEM-512": dict(nist_quantum_level=1, classical_security_bits=128),
    "ML-KEM-768": dict(nist_quantum_level=3, classical_security_bits=192),
    "ML-KEM-1024": dict(nist_quantum_level=5, classical_security_bits=256),
    "ML-DSA-44": dict(nist_quantum_level=2, classical_security_bits=128),
    "ML-DSA-65": dict(nist_quantum_level=3, classical_security_bits=192),
    "ML-DSA-87": dict(nist_quantum_level=5, classical_security_bits=256),
}

# IANA TLS NamedGroup IDs -> (name, quantum status). 0x11ec/0x11eb/0x11ed are
# the standardized hybrid ML-KEM groups; draft Kyber IDs varied by draft.
TLS_GROUPS: dict[int, tuple[str, str]] = {
    0x11EC: ("X25519MLKEM768", HYBRID), 0x11EB: ("SecP256r1MLKEM768", HYBRID),
    0x11ED: ("SecP384r1MLKEM1024", HYBRID), 0x6399: ("X25519Kyber768Draft00", HYBRID),
    0x001D: ("X25519", VULNERABLE), 0x0017: ("secp256r1", VULNERABLE),
    0x0018: ("secp384r1", VULNERABLE), 0x0019: ("secp521r1", VULNERABLE),
}
