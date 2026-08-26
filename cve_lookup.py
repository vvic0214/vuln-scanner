"""
cve_lookup.py - Correlate detected service/version strings with known CVEs
via the NIST NVD REST API (v2.0).

Docs: https://nvd.nist.gov/developers/vulnerabilities
Without an API key, NVD rate-limits to 5 requests / 30s. Pass --nvd-api-key
(or set NVD_API_KEY) to raise that to 50 requests / 30s.
"""
import os
import time

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_request_time = 0.0
_MIN_REQUEST_INTERVAL_NO_KEY = 6.5  # seconds, keeps us under 5 req/30s
_MIN_REQUEST_INTERVAL_WITH_KEY = 0.7  # seconds, keeps us under 50 req/30s

_cache: dict[str, list[dict]] = {}


def _throttle(has_key: bool):
    global _last_request_time
    min_interval = _MIN_REQUEST_INTERVAL_WITH_KEY if has_key else _MIN_REQUEST_INTERVAL_NO_KEY
    elapsed = time.monotonic() - _last_request_time
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_request_time = time.monotonic()


def lookup_cves_for_service(
    product: str, version: str, api_key: str | None = None, max_results: int = 5
) -> list[dict]:
    """Return CVEs matching a product (+ optional version), sorted by CVSS score desc."""
    api_key = api_key or os.environ.get("NVD_API_KEY")
    keyword = f"{product} {version}".strip()
    if not keyword:
        return []

    if keyword in _cache:
        return _cache[keyword]

    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}

    _throttle(has_key=bool(api_key))

    try:
        resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[!] NVD lookup failed for '{keyword}': {exc}")
        return []

    data = resp.json()
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        cvss_score, cvss_severity = _extract_cvss(cve)

        results.append({
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": cvss_severity,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    results.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)
    _cache[keyword] = results
    return results


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity", "UNKNOWN")
            return score, severity
    return None, "UNKNOWN"
