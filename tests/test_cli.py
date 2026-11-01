import json
from pathlib import Path

from typer.testing import CliRunner

from cbom_scout.cli import app

runner = CliRunner()
ROOT = Path(__file__).parent.parent


def test_scan_examples_writes_cbom(tmp_path):
    out = tmp_path / "cbom.json"
    result = runner.invoke(app, ["scan", str(ROOT / "examples"), "-o", str(out)])
    assert result.exit_code == 0, result.output
    bom = json.loads(out.read_text())
    assert bom["specVersion"] == "1.6" and len(bom["components"]) == 4
    assert "Cryptographic assets (4)" in result.output


def test_probe_only_skips_static_scan(tmp_path):
    out = tmp_path / "cbom.json"
    result = runner.invoke(app, ["scan", str(ROOT / "examples"), "--probe-only", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["components"] == []


def test_fail_on_vulnerable_exits_1(tmp_path):
    result = runner.invoke(app, ["scan", str(ROOT / "examples"), "--fail-on-vulnerable",
                                 "-o", str(tmp_path / "cbom.json")])
    assert result.exit_code == 1
