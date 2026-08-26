#!/usr/bin/env python3
"""
generate_sample.py - Renders docs/sample_report.html from synthetic findings,
so the report format can be previewed without running a real scan.
Run from the repo root: python docs/generate_sample.py
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from report import render_report

SAMPLE_FINDINGS = [
    {
        "host": "192.168.1.10", "hostname": "web-server.lab",
        "port": 22, "protocol": "tcp", "service": "ssh",
        "product": "OpenSSH", "version": "7.2p2",
        "cves": [
            {
                "id": "CVE-2016-6210", "cvss_score": 5.9, "severity": "MEDIUM",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6210",
                "description": "OpenSSH before 7.3 allows remote attackers to enumerate "
                               "valid usernames via a timing side-channel in password auth.",
            },
        ],
    },
    {
        "host": "192.168.1.10", "hostname": "web-server.lab",
        "port": 80, "protocol": "tcp", "service": "http",
        "product": "Apache httpd", "version": "2.4.49",
        "cves": [
            {
                "id": "CVE-2021-41773", "cvss_score": 9.8, "severity": "CRITICAL",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "description": "A path traversal flaw in Apache HTTP Server 2.4.49 allows "
                               "remote attackers to map URLs to files outside the document root.",
            },
            {
                "id": "CVE-2021-42013", "cvss_score": 9.8, "severity": "CRITICAL",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
                "description": "Incomplete fix for CVE-2021-41773 in Apache HTTP Server "
                               "2.4.50, still exploitable for RCE via path traversal.",
            },
        ],
    },
    {
        "host": "192.168.1.15", "hostname": "db-server.lab",
        "port": 3306, "protocol": "tcp", "service": "mysql",
        "product": "MySQL", "version": "5.5.60",
        "cves": [
            {
                "id": "CVE-2020-14812", "cvss_score": 4.9, "severity": "MEDIUM",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-14812",
                "description": "Vulnerability in the MySQL Server component allows "
                               "low-privileged attackers with network access to affect availability.",
            },
        ],
    },
    {
        "host": "192.168.1.15", "hostname": "db-server.lab",
        "port": 443, "protocol": "tcp", "service": "https",
        "product": "nginx", "version": "1.18.0",
        "cves": [],
    },
]


def main():
    output_path = Path(__file__).parent / "sample_report.html"
    render_report(
        findings=SAMPLE_FINDINGS,
        output_path=str(output_path),
        target="192.168.1.0/24 (sample data)",
        scan_time=datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc),
    )
    print(f"Sample report written to {output_path}")


if __name__ == "__main__":
    main()
