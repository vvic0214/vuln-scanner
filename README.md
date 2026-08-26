# vuln-scanner

A Python CLI tool that scans a network target with `nmap`, correlates detected
services/versions against known CVEs via the [NVD API](https://nvd.nist.gov/developers/vulnerabilities),
and generates a ranked HTML vulnerability report.

📄 [**View a sample report**](docs/sample_report.html) rendered from synthetic
data (`docs/generate_sample.py`) — open it locally to see the report format
without running a real scan.

## ⚠️ Legal notice

**Only scan hosts or networks you own or have explicit written authorization
to test.** Unauthorized scanning of systems you don't control may violate the
U.S. Computer Fraud and Abuse Act (CFAA) or equivalent laws elsewhere. This
tool prompts for confirmation before every scan as a safeguard, but that
confirmation does not constitute legal authorization — that's on you.

## Features

- Host discovery + service/version fingerprinting via `nmap -sV`
- CVE correlation against the NIST NVD database (keyword search on
  product + version)
- Findings ranked by CVSS severity (Critical/High/Medium/Low)
- Clean, self-contained HTML report (dark theme, no external dependencies)
- Simple CLI: one command, one report

## Setup

```bash
# nmap must be installed and on PATH
brew install nmap          # macOS
# sudo apt install nmap    # Debian/Ubuntu

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py --target 192.168.1.10 --output report.html
```

Scan a range and only look at common ports:

```bash
python scanner.py --target 192.168.1.0/24 --ports 1-1024 --output report.html
```

Use an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) to
raise the CVE lookup rate limit from 5 req/30s to 50 req/30s:

```bash
python scanner.py --target 192.168.1.10 --nvd-api-key YOUR_KEY
# or: export NVD_API_KEY=YOUR_KEY
```

Skip the interactive authorization prompt (e.g. in CI, only for targets you
own):

```bash
python scanner.py --target 127.0.0.1 --yes
```

Open the generated `report.html` in a browser to see the results.

## How it works

1. **Scan** — `nmap -sV` performs host discovery and service/version
   fingerprinting on the target.
2. **Correlate** — for each detected service (e.g. `OpenSSH 8.2p1`), the tool
   queries the NVD API's keyword search and pulls back matching CVEs with
   their CVSS score and severity.
3. **Rank & report** — findings are sorted by highest CVSS score and rendered
   into a single self-contained HTML file.

## Project structure

```
vuln-scanner/
├── scanner.py        # CLI entry point + nmap scan + orchestration
├── cve_lookup.py      # NVD API client with caching + rate limiting
├── report.py          # Jinja2 HTML report rendering
├── templates/
│   └── report_template.html
├── requirements.txt
└── README.md
```

## Limitations

- CVE matching is keyword-based (NVD doesn't provide a clean CPE match for
  free-text `product`/`version` strings from nmap banners), so results can
  include false positives and miss some real matches. Treat this as a
  triage aid, not ground truth — always verify manually before acting on it.
- No authenticated/credentialed scanning — this only sees what's visible from
  an unauthenticated network scan.
- Rate-limited by the NVD API (5 req/30s without a key).

## What I learned

_(fill this in after using it against a real lab target — e.g. notes on nmap
service detection accuracy, NVD API quirks, CVSS interpretation, what you'd
add next such as CPE-based matching or a MITRE ATT&CK mapping.)_

## License

MIT — see [LICENSE](LICENSE).
