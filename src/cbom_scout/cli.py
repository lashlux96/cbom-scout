from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .exporters import write_cyclonedx, write_sarif
from .models import Finding
from .pqc_probe import probe_pqc
from .static_scan import load_ignore_file, scan_tree
from .tls_probe import probe_tls_endpoint

app = typer.Typer(help="cbom-scout — Cryptographic Bill of Materials (CycloneDX v1.6)")
console = Console()


def _render(findings: list[Finding]) -> None:
    table = Table(title=f"Cryptographic assets ({len(findings)})", show_lines=False)
    for col in ("Asset", "Algorithm", "Location", "Quantum status"):
        table.add_column(col)
    for f in findings:
        style = "red" if f.quantum_vulnerable or f.quantum_status == "WEAK_CLASSICAL" else "yellow"
        table.add_row(f.name, f.algorithm, f.location, f"[{style}]{f.quantum_status}[/{style}]")
    console.print(table or "No cryptographic assets found.")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repository / directory to scan statically"),
    probe: list[str] = typer.Option([], "--probe", help="Live TLS endpoint host[:port]; repeatable"),
    pqc_probe: list[str] = typer.Option([], "--pqc-probe", help="Raw ClientHello PQC/hybrid group probe host[:port]; repeatable"),
    output: Path = typer.Option(Path("cyclonedx-cbom.json"), "--output", "-o"),
    sarif: Path | None = typer.Option(None, "--sarif", help="Also write a SARIF file"),
    fail_on_vulnerable: bool = typer.Option(False, "--fail-on-vulnerable", help="Exit 1 if Shor-vulnerable/weak crypto is found (CI gate)"),
    probe_only: bool = typer.Option(False, "--probe-only", help="Skip the static scan; only run --probe/--pqc-probe endpoints"),
) -> None:
    """Scan a codebase and/or live endpoints, then export a CycloneDX 1.6 CBOM."""
    findings: list[Finding] = []
    if not probe_only and path.exists():
        findings.extend(scan_tree(path, load_ignore_file(path)))
    for target in probe:
        host, _, port = target.partition(":")
        if f := probe_tls_endpoint(host, int(port) if port else 443):
            findings.append(f)
    for target in pqc_probe:
        host, _, port = target.partition(":")
        if f := probe_pqc(host, int(port) if port else 443):
            findings.append(f)
    _render(findings)
    write_cyclonedx(findings, output)
    console.print(f"[green][+][/green] CycloneDX 1.6 CBOM -> {output} ({len(findings)} assets)")
    if sarif:
        write_sarif(findings, sarif)
        console.print(f"[green][+][/green] SARIF -> {sarif}")
    if fail_on_vulnerable and any(f.quantum_vulnerable or f.quantum_status == "WEAK_CLASSICAL" for f in findings):
        console.print("[red][!] Shor-vulnerable or weak cryptography present — failing as requested.[/red]")
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    from . import __version__
    console.print(f"cbom-scout {__version__}")


if __name__ == "__main__":
    app()
