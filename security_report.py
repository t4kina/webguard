#!/usr/bin/env python3
"""
security_report.py — Mini Web Security Scanner
Orquesta Trivy (local o imagen Docker) + OWASP ZAP (staging) y muestra un reporte en consola.

Uso:
    # Proyecto real contra staging
    python security_report.py --url https://staging.mi-web.com --path ./mi-proyecto

    # Con Basic Auth
    python security_report.py --url https://staging.mi-web.com --auth usuario:contraseña

    # Prueba local con DVWA (solo ZAP)
    python security_report.py --url http://dvwa:80 --network security-scan --skip-trivy

    # Prueba local con DVWA (ZAP + Trivy escaneando la imagen)
    python security_report.py --url http://dvwa:80 --network security-scan --trivy-image vulnerables/web-dvwa
"""

import argparse
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.rule import Rule

_term_cols = shutil.get_terminal_size((100, 40)).columns
CONSOLE_WIDTH = max(60, min(_term_cols, 100) - 2)
console = Console(width=CONSOLE_WIDTH)

# ─────────────────────────────────────────────
# Estructuras de datos
# ─────────────────────────────────────────────

@dataclass
class Finding:
    tool: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    description: str = ""
    reference: str = ""


@dataclass
class ScanResult:
    tool: str
    success: bool
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    duration: float = 0.0


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "INFO":     "bold cyan",
}

# ─────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────

def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout tras {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"Comando no encontrado: {e}"


def docker_available() -> bool:
    code, _, _ = run_cmd(["docker", "info"])
    return code == 0


def trivy_available() -> bool:
    code, _, _ = run_cmd(["trivy", "--version"])
    return code == 0


# ─────────────────────────────────────────────
# HERRAMIENTA 1 — Trivy
# ─────────────────────────────────────────────

def _parse_trivy_output(stdout: str, result: ScanResult) -> ScanResult:
    """Parsea el JSON de Trivy y rellena result.findings."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        result.error = f"JSON inválido de Trivy: {stdout[:200]}"
        return result

    result.success = True

    for report in data.get("Results", []):
        for vuln in report.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "INFO").upper()
            result.findings.append(Finding(
                tool="Trivy",
                severity=sev,
                title=f"{vuln.get('VulnerabilityID', '?')} en {vuln.get('PkgName', '?')}",
                description=(vuln.get("Title") or vuln.get("Description", ""))[:120],
                reference=vuln.get("PrimaryURL", ""),
            ))
        for mis in report.get("Misconfigurations") or []:
            sev = mis.get("Severity", "INFO").upper()
            result.findings.append(Finding(
                tool="Trivy",
                severity=sev,
                title=mis.get("Title", "Misconfiguration"),
                description=mis.get("Description", "")[:120],
                reference=mis.get("PrimaryURL", ""),
            ))
        for sec in report.get("Secrets") or []:
            result.findings.append(Finding(
                tool="Trivy",
                severity="HIGH",
                title=f"Secret expuesto: {sec.get('Title', '?')}",
                description=sec.get("Match", "")[:80],
            ))
    return result


def run_trivy_fs(path: str) -> ScanResult:
    """Escanea dependencias, secrets y misconfigs en la carpeta del proyecto."""
    t0 = time.time()
    result = ScanResult(tool="Trivy", success=False)
    abs_path = str(Path(path).resolve())

    if trivy_available():
        cmd = [
            "trivy", "fs", abs_path,
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
        ]
    elif docker_available():
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{abs_path}:/scan:ro",
            "aquasec/trivy:latest",
            "fs", "/scan",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
        ]
    else:
        result.error = "Trivy no disponible (instala el binario o Docker)"
        result.duration = time.time() - t0
        return result

    code, stdout, stderr = run_cmd(cmd, timeout=180)
    result.duration = time.time() - t0

    if code not in (0, 1):
        result.error = stderr[:300] or "Error desconocido en Trivy"
        return result

    return _parse_trivy_output(stdout, result)


def run_trivy_image(image: str) -> ScanResult:
    """Escanea una imagen Docker en busca de CVEs en paquetes del SO y dependencias."""
    t0 = time.time()
    result = ScanResult(tool="Trivy", success=False)

    if trivy_available():
        cmd = [
            "trivy", "image", image,
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
        ]
    elif docker_available():
        # Necesita acceso al socket para inspeccionar imágenes locales
        cmd = [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "aquasec/trivy:latest",
            "image", image,
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
        ]
    else:
        result.error = "Trivy no disponible (instala el binario o Docker)"
        result.duration = time.time() - t0
        return result

    code, stdout, stderr = run_cmd(cmd, timeout=300)
    result.duration = time.time() - t0

    if code not in (0, 1):
        result.error = stderr[:300] or "Error desconocido en Trivy"
        return result

    return _parse_trivy_output(stdout, result)


# ─────────────────────────────────────────────
# HERRAMIENTA 2 — OWASP ZAP
# ─────────────────────────────────────────────

def build_auth_header(credentials: str) -> str:
    """Codifica credenciales en Base64 para Basic Auth."""
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"


def write_zap_context(tmpdir: str, url: str, auth_header: str) -> str:
    """Escribe un fichero de contexto XML con Basic Auth configurado a nivel de sitio.

    ZAP lo carga con -n antes de arrancar el escaneo, de modo que todas las
    peticiones llevan el header Authorization desde la primera.

    Returns:
        Ruta del fichero dentro del tmpdir (se monta en /zap/wrk).
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    site = f"{parsed.scheme}://{parsed.netloc}"

    ctx_path = Path(tmpdir) / "context.context"
    ctx_path.write_text(f"""<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<configuration>
    <context>
        <name>scan</name>
        <desc/>
        <inscope>true</inscope>
        <incregexes>{site}.*</incregexes>
        <authentication>
            <type>3</type>
            <httpauth>
                <hostname>{parsed.netloc}</hostname>
                <realm/>
                <port>{parsed.port or (443 if parsed.scheme == "https" else 80)}</port>
            </httpauth>
        </authentication>
    </context>
    <replacer>
        <full_list>
            <item>
                <description>BasicAuth</description>
                <enabled>true</enabled>
                <matchtype>REQ_HEADER</matchtype>
                <matchstring>Authorization</matchstring>
                <matchregex>false</matchregex>
                <replacement>{auth_header}</replacement>
                <initiators/>
            </item>
        </full_list>
    </replacer>
</configuration>
""")
    return "/zap/wrk/context.context"


def run_zap(url: str, auth: str | None = None, docker_network: str | None = None) -> ScanResult:
    """Escaneo pasivo de la web con OWASP ZAP Baseline via Docker.

    Args:
        url:            URL del entorno de staging.
        auth:           Credenciales Basic Auth 'usuario:contraseña' (opcional).
        docker_network: Red Docker a la que unirse para alcanzar contenedores por nombre.
    """
    t0 = time.time()
    result = ScanResult(tool="OWASP ZAP", success=False)

    if not docker_available():
        result.error = "Docker no disponible — ZAP lo requiere"
        return result

    if auth and ":" not in auth:
        result.error = "--auth debe tener formato 'usuario:contraseña'"
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = "zap_report.json"
        report_path = Path(tmpdir) / report_file

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{tmpdir}:/zap/wrk:rw",
            "--user", "root",
        ]

        if docker_network:
            cmd += ["--network", docker_network]

        cmd += [
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t", url,
            "-J", report_file,
            "-I",
        ]

        if auth:
            auth_header = build_auth_header(auth)
            ctx_container_path = write_zap_context(tmpdir, url, auth_header)
            cmd += ["-n", ctx_container_path]

        code, _, stderr = run_cmd(cmd, timeout=300)
        result.duration = time.time() - t0

        if code not in (0, 1, 2):
            result.error = f"ZAP falló (código {code}): {stderr[:300]}"
            return result

        if not report_path.exists():
            result.error = "ZAP no generó el fichero de reporte JSON"
            return result

        try:
            data = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            result.error = "JSON inválido de ZAP"
            return result

    result.success = True
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskcode", "0"))
            sev  = risk_map.get(risk, "INFO")
            desc = alert.get("desc", "").replace("<p>", " ").replace("</p>", "").strip()
            result.findings.append(Finding(
                tool="ZAP",
                severity=sev,
                title=alert.get("alert", "Alerta desconocida"),
                description=desc[:120],
                reference=alert.get("reference", "")[:80],
            ))

    return result



# ─────────────────────────────────────────────
# Renderizado
# ─────────────────────────────────────────────

def render_report(
    url: str,
    path: str,
    results: list[ScanResult],
    auth: bool = False,
    docker_network: str | None = None,
    trivy_image: str | None = None,
    show_all: bool = False,
):
    all_findings = sorted(
        [f for r in results for f in r.findings],
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    console.print()
    console.print(Rule("[bold cyan]SECURITY REPORT[/bold cyan]", style="cyan"))
    console.print()

    # ── Cabecera ──────────────────────────────────────────────────────────────
    info = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    info.add_column(style="dim", width=14, no_wrap=True)
    info.add_column(overflow="fold")
    info.add_row("Objetivo",     f"[bold white]{url}[/bold white]")
    if trivy_image:
        info.add_row("Trivy imagen", f"[cyan]{trivy_image}[/cyan]")
    else:
        info.add_row("Ruta local",   f"[white]{Path(path).resolve()}[/white]")
    info.add_row("Herramientas", "Trivy / OWASP ZAP")
    info.add_row("Basic Auth",   "[green]configurado[/green]" if auth else "[dim]no[/dim]")
    info.add_row("Docker net",   f"[cyan]{docker_network}[/cyan]" if docker_network else "[dim]no[/dim]")
    console.print(Panel(info, title="Escaneo", border_style="cyan"))
    console.print()

    # ── Resumen por severidad ─────────────────────────────────────────────────
    sev_table = Table(box=box.SIMPLE_HEAD, header_style="bold white", expand=True)
    sev_table.add_column("Severidad", ratio=1)
    sev_table.add_column("Hallazgos", justify="center", ratio=1)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n     = counts.get(sev, 0)
        style = SEVERITY_STYLE[sev]
        sev_table.add_row(
            f"[{style}]{sev}[/{style}]",
            f"[{style}]{n}[/{style}]",
        )

    console.print(Panel(sev_table, title="Resumen", border_style="dim"))
    console.print()

    # ── Estado herramientas ───────────────────────────────────────────────────
    tool_table = Table(box=box.SIMPLE, header_style="bold white", expand=True)
    tool_table.add_column("Herramienta", ratio=3, no_wrap=True)
    tool_table.add_column("Estado",      ratio=2, no_wrap=True)
    tool_table.add_column("Hallazgos",   justify="center", ratio=2)
    tool_table.add_column("Duración",    justify="right",  ratio=2, no_wrap=True)
    tool_table.add_column("Error",       ratio=5, style="dim red", overflow="fold")

    for r in results:
        status = "[green]OK[/green]" if r.success else "[red]Error[/red]"
        tool_table.add_row(
            f"[bold]{r.tool}[/bold]",
            status,
            str(len(r.findings)) if r.success else "—",
            f"{r.duration:.1f}s",
            r.error[:60] if r.error else "",
        )

    console.print(Panel(tool_table, title="Herramientas", border_style="dim"))
    console.print()

    # ── Hallazgos detallados ──────────────────────────────────────────────────
    def render_findings(title: str, findings: list[Finding], border: str):
        if not findings:
            return
        t = Table(
            box=box.MINIMAL_DOUBLE_HEAD, header_style="bold white",
            border_style=border, expand=True,
        )
        t.add_column("Sev",      ratio=2, no_wrap=True)
        t.add_column("Tool",     ratio=2, no_wrap=True)
        t.add_column("Hallazgo", ratio=5, overflow="fold")
        t.add_column("Detalle",  ratio=7, style="dim", overflow="fold")

        for f in findings:
            style = SEVERITY_STYLE.get(f.severity, "white")
            t.add_row(
                f"[{style}]{f.severity}[/{style}]",
                f"[dim]{f.tool}[/dim]",
                f.title[:70],
                f.description[:80] if f.description else "",
            )
        console.print(Panel(t, title=title, border_style=border))
        console.print()

    critical_high = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH")]
    medium_low    = [f for f in all_findings if f.severity in ("MEDIUM", "LOW")]
    info_only     = [f for f in all_findings if f.severity == "INFO"]

    hidden = len(medium_low) + len(info_only)

    if critical_high:
        render_findings(f"Críticos y Altos ({len(critical_high)})", critical_high, "red")
    elif not all_findings:
        console.print(Panel(
            "\n  [bold green]¡Sin hallazgos detectados![/bold green]\n",
            border_style="green",
        ))

    if show_all:
        if medium_low:
            render_findings(f"Medios y Bajos ({len(medium_low)})", medium_low, "yellow")
        if info_only:
            render_findings(f"Informativos ({len(info_only)})", info_only, "cyan")
    elif hidden:
        console.print(
            f"[dim]  + {hidden} hallazgos de severidad MEDIUM/LOW/INFO omitidos "
            f"— usa [bold]--all[/bold] para verlos todos[/dim]\n"
        )

    # ── Footer ────────────────────────────────────────────────────────────────
    console.print(Rule(style="dim"))
    total = sum(r.duration for r in results)
    console.print(
        f"[dim]Completado en {total:.1f}s  •  "
        f"{len(all_findings)} hallazgos totales[/dim]\n"
    )


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Mini Security Scanner — Trivy + OWASP ZAP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ejemplos:
  # Proyecto real contra staging
  %(prog)s --url https://staging.mi-web.com --path ./mi-proyecto

  # Prueba con DVWA — solo ZAP
  %(prog)s --url http://dvwa:80 --network security-scan --skip-trivy

  # Prueba con DVWA — ZAP + Trivy escaneando la imagen
  %(prog)s --url http://dvwa:80 --network security-scan --trivy-image vulnerables/web-dvwa
        """,
    )
    parser.add_argument("--url",  required=True,
                        help="URL a escanear con ZAP")
    parser.add_argument("--path", default=".",
                        help="Carpeta local del proyecto para Trivy fs (default: .)")
    parser.add_argument("--trivy-image", default=None, metavar="IMAGEN",
                        help="Escanear imagen Docker con Trivy en lugar de carpeta local")
    parser.add_argument("--auth", default=None, metavar="USUARIO:CONTRASEÑA",
                        help="Credenciales Basic Auth para ZAP")
    parser.add_argument("--network", default=None, metavar="NOMBRE_RED",
                        help="Red Docker a la que unir ZAP")
    parser.add_argument("--skip-trivy", action="store_true",
                        help="Omitir Trivy")
    parser.add_argument("--skip-zap",   action="store_true",
                        help="Omitir ZAP")
    parser.add_argument("--all", action="store_true", dest="show_all",
                        help="Mostrar todos los hallazgos incluyendo MEDIUM, LOW e INFO")
    args = parser.parse_args()

    if not args.url.startswith("http"):
        console.print("[red]La URL debe empezar por http:// o https://[/red]")
        sys.exit(1)

    if args.auth and ":" not in args.auth:
        console.print("[red]--auth debe tener formato 'usuario:contraseña'[/red]")
        sys.exit(1)

    if not args.skip_trivy and not args.trivy_image and not Path(args.path).exists():
        console.print(f"[red]La ruta '{args.path}' no existe[/red]")
        sys.exit(1)

    console.print()
    console.print(Panel(
        "[bold cyan]Mini Security Scanner[/bold cyan]\n"
        "[dim]Trivy (local o imagen) · OWASP ZAP (staging)[/dim]",
        border_style="cyan", expand=False,
    ))
    console.print()

    tasks = []
    if not args.skip_trivy:
        if args.trivy_image:
            tasks.append((
                f"Trivy — imagen {args.trivy_image}",
                lambda: run_trivy_image(args.trivy_image),
            ))
        else:
            tasks.append((
                "Trivy — dependencias, secrets y misconfigs",
                lambda: run_trivy_fs(args.path),
            ))
    if not args.skip_zap:
        tasks.append((
            "ZAP — escaneo web pasivo",
            lambda: run_zap(args.url, auth=args.auth, docker_network=args.network),
        ))

    if not tasks:
        console.print("[yellow]No hay ninguna herramienta activa.[/yellow]")
        sys.exit(0)

    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        for desc, fn in tasks:
            tid = progress.add_task(desc, total=None)
            r   = fn()
            results.append(r)
            icon = "[green]✓[/green]" if r.success else "[red]✗[/red]"
            progress.update(tid, description=f"{icon} {desc}", completed=True)

    render_report(
        args.url, args.path, results,
        auth=bool(args.auth),
        docker_network=args.network,
        trivy_image=args.trivy_image,
        show_all=args.show_all,
    )


if __name__ == "__main__":
    main()