import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cbom_scout.classifier import evaluate_public_key
from cbom_scout.exporters import to_cyclonedx, to_sarif
from cbom_scout.static_scan import scan_tree


def _write_cert(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cbom-test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    p = tmp_path / "cert.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key


def test_rsa_classification_is_shor_vulnerable():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ev = evaluate_public_key(key.public_key())
    assert ev["quantum_status"] == "CRITICAL_SHORS_VULNERABLE"
    assert ev["nist_quantum_level"] == 0 and ev["classical_security_bits"] == 112


def test_pem_certificate_discovered(tmp_path):
    _write_cert(tmp_path)
    findings = scan_tree(tmp_path)
    certs = [f for f in findings if f.asset_type == "certificate"]
    assert len(certs) == 1 and certs[0].algorithm == "RSA" and certs[0].key_size == 2048


def test_cyclonedx_structure_is_spec_shaped(tmp_path):
    _write_cert(tmp_path)
    bom = to_cyclonedx(scan_tree(tmp_path))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    comp = bom["components"][0]
    assert comp["type"] == "cryptographic-asset"
    crypto = comp["cryptoProperties"]
    # The blueprint's invented quantumProperties must NOT appear; real fields must.
    assert "quantumProperties" not in crypto
    assert crypto["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    json.dumps(bom)  # serializable


def test_crypto_functions_are_valid_cyclonedx_enums(tmp_path):
    # Regression: 'key-agree' is a valid primitive but NOT a valid cryptoFunction;
    # it broke schema validation on live TLS / EC-certificate components.
    valid = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag",
             "keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"}
    _write_cert(tmp_path)
    bom = to_cyclonedx(scan_tree(tmp_path))
    for comp in bom["components"]:
        funcs = comp["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"]
        assert set(funcs) <= valid, funcs


def test_sarif_output():
    sarif = to_sarif([])
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"] == []
