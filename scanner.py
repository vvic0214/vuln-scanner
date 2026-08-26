#!/usr/bin/env python3
"""
scanner.py - CLI entry point for the vulnerability scanner.

Performs host discovery + service/version detection via nmap, correlates
detected services with known CVEs via the NVD API, and renders an HTML report.

LEGAL NOTICE: Only scan hosts/networks you own or have explicit written
authorization to test. Unauthorized scanning may violate laws such as the
U.S. Computer Fraud and Abuse Act (CFAA) or equivalent statutes elsewhere.
"""
import argparse
import sys
from datetime import datetime, timezone

import nmap

from cve_lookup import lookup_cves_for_service
from report import render_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network vulnerability scanner: nmap scan + CVE correlation + HTML report."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target host/range to scan, e.g. 192.168.1.10 or 192.168.1.0/24. "
             "Only scan systems you own or are authorized to test.",
    )
    parser.add_argument(
        "--ports",
        default="1-1000",
        help="Port range to scan (default: 1-1000).",
    )
    parser.add_argument(
        "--output",
        default="report.html",
        help="Path to write the HTML report to (default: report.html).",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help="Optional NVD API key for higher rate limits. "
             "Can also be set via the NVD_API_KEY environment variable.",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip the authorization confirmation prompt.",
    )
    return parser.parse_args()


def confirm_authorization(target: str) -> bool:
    print(
        f"You are about to scan: {target}\n"
        "Only proceed if you own this system/network or have explicit written "
        "authorization to test it. Unauthorized scanning may be illegal.\n"
    )
    answer = input("Type 'yes' to confirm you are authorized to scan this target: ")
    return answer.strip().lower() == "yes"


def run_scan(target: str, ports: str) -> nmap.PortScanner:
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target} (ports {ports}) ...")
    scanner.scan(hosts=target, ports=ports, arguments="-sV")
    return scanner


def collect_findings(scanner: nmap.PortScanner, nvd_api_key: str | None) -> list[dict]:
    findings = []
    for host in scanner.all_hosts():
        host_info = scanner[host]
        hostname = host_info.hostname() or host
        for proto in host_info.all_protocols():
            ports = host_info[proto].keys()
            for port in sorted(ports):
                service = host_info[proto][port]
                if service.get("state") != "open":
                    continue
                product = service.get("product", "")
                version = service.get("version", "")
                name = service.get("name", "")

                print(f"[*] {host}:{port} -> {name} {product} {version}".strip())

                cves = []
                if product:
                    cves = lookup_cves_for_service(product, version, api_key=nvd_api_key)

                findings.append({
                    "host": host,
                    "hostname": hostname,
                    "port": port,
                    "protocol": proto,
                    "service": name,
                    "product": product,
                    "version": version,
                    "cves": cves,
                })
    return findings


def main():
    args = parse_args()

    if not args.yes and not confirm_authorization(args.target):
        print("Authorization not confirmed. Aborting.")
        sys.exit(1)

    scanner = run_scan(args.target, args.ports)
    findings = collect_findings(scanner, args.nvd_api_key)

    render_report(
        findings=findings,
        output_path=args.output,
        target=args.target,
        scan_time=datetime.now(timezone.utc),
    )
    print(f"[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
