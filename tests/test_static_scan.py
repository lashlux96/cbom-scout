from pathlib import Path

from cbom_scout.static_scan import scan_tree

ROOT = Path(__file__).parent.parent


def test_import_only_file_has_zero_findings(tmp_path):
    (tmp_path / "safe.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\nimport hashlib\nprint('hi')\n")
    assert scan_tree(tmp_path) == []


def test_call_sites_are_flagged_with_locations(tmp_path):
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "d = hashes.MD5()\n")
    findings = scan_tree(tmp_path)
    names = [f.name for f in findings]
    assert any("key generation" in n for n in names)
    assert any("MD5" in n for n in names)
    weak_key = next(f for f in findings if "key generation" in f.name)
    assert weak_key.key_size == 1024 and weak_key.quantum_status == "WEAK_CLASSICAL"
    assert weak_key.location == "app.py:3"


def test_examples_vulnerable_vs_safe():
    vuln = scan_tree(ROOT / "examples")
    assert any(f.location.startswith("vulnerable_app.py") for f in vuln)
    assert not any(f.location.startswith("safe_app.py") for f in vuln)


def test_symlink_escaping_root_is_not_followed(tmp_path):
    outside = tmp_path.parent / "outside_secret.py"
    outside.write_text("from cryptography.hazmat.primitives import hashes\nd = hashes.MD5()\n")
    (tmp_path / "link.py").symlink_to(outside)
    assert scan_tree(tmp_path) == []
