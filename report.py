"""
report.py - Render scan findings into an HTML report using Jinja2.
"""
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_rank(finding: dict) -> tuple[int, float]:
    """Rank a host:port finding by its highest CVSS score, for sorting."""
    cves = finding["cves"]
    if not cves:
        return (0, 0.0)
    best = max((c["cvss_score"] or 0.0) for c in cves)
    return (1, best)


def render_report(findings: list[dict], output_path: str, target: str, scan_time: datetime) -> None:
    findings_sorted = sorted(findings, key=_severity_rank, reverse=True)

    total_cves = sum(len(f["cves"]) for f in findings)
    high_risk = sum(
        1 for f in findings for c in f["cves"] if (c["cvss_score"] or 0) >= 7.0
    )

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report_template.html")

    html = template.render(
        target=target,
        scan_time=scan_time.strftime("%Y-%m-%d %H:%M UTC"),
        findings=findings_sorted,
        total_hosts=len({f["host"] for f in findings}),
        total_open_ports=len(findings),
        total_cves=total_cves,
        high_risk=high_risk,
    )

    Path(output_path).write_text(html, encoding="utf-8")
