#!/usr/bin/env python3
"""
Tier 1 SOC IOC enrichment script.
Supports: IPv4, domains, URLs, MD5/SHA1/SHA256 hashes.
Uses public APIs (no keys required for basic VT v3 rate limits with optional key).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Install requests: pip install requests", file=sys.stderr)
    sys.exit(1)

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    verdict: str
    source: str
    details: dict
    error: Optional[str] = None


def clean_ioc(value: str) -> str:
    """Normalize defanged URLs, domains, and IPs to their standard format."""
    value = value.strip().lower()
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[-]", "-")
    value = value.replace("[d]", ".").replace("[D]", ".")
    value = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
    value = value.replace("hxxp[s]://", "https://").replace("hxxp(s)://", "https://")
    return value


def classify_ioc(value: str) -> str:
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if IPV4_RE.match(value):
        return "ip"
    if HASH_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def enrich_ip(ip: str, session: requests.Session) -> EnrichmentResult:
    """Classify lab/sanitized IPs locally; use ip-api.com only for real public IPs."""
    parsed_ip = ipaddress.ip_address(ip)
    test_nets = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    if any(parsed_ip in network for network in test_nets):
        return EnrichmentResult(
            ip,
            "ip",
            "sanitized_documentation_ip",
            "local_classification",
            {"note": "RFC5737 documentation address used to sanitize lab evidence; no live reputation lookup performed"},
        )
    if parsed_ip.is_private:
        return EnrichmentResult(
            ip,
            "ip",
            "internal_lab_ip",
            "local_classification",
            {"note": "RFC1918/private lab address; no public reputation lookup performed"},
        )

    details: dict = {}
    verdict = "unknown"
    try:
        r = session.get(f"https://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,query", timeout=10)
        data = r.json()
        if data.get("status") == "success":
            details = {
                "country": data.get("country"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
            }
            verdict = "investigate" if "hosting" in (data.get("isp") or "").lower() else "informational"
        else:
            verdict = "error"
            details = {"message": data.get("message")}
    except requests.RequestException as exc:
        return EnrichmentResult(ip, "ip", "error", "ip-api", {}, str(exc))
    return EnrichmentResult(ip, "ip", verdict, "ip-api", details)


def enrich_domain(domain: str, session: requests.Session, vt_key: Optional[str]) -> EnrichmentResult:
    details: dict = {}
    verdict = "unknown"
    headers = {"x-apikey": vt_key} if vt_key else {}
    if domain.endswith(".corp.lab"):
        return EnrichmentResult(
            domain,
            "domain",
            "internal_lab_domain",
            "local_classification",
            {"note": "Internal lab namespace; no public DNS lookup performed"},
        )
    try:
        if vt_key:
            r = session.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=15)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                details = {"vt_stats": stats, "reputation": malicious}
                verdict = "malicious" if malicious >= 3 else "suspicious" if malicious >= 1 else "clean"
            else:
                verdict = "error"
                details = {"status_code": r.status_code}
        else:
            # DNS existence check only without API key
            import socket
            try:
                socket.gethostbyname(domain)
                verdict = "resolves"
                details = {"note": "Add VT_API_KEY for reputation"}
            except socket.gaierror:
                verdict = "nxdomain"
    except requests.RequestException as exc:
        return EnrichmentResult(domain, "domain", "error", "virustotal", {}, str(exc))
    return EnrichmentResult(domain, "domain", verdict, "virustotal" if vt_key else "dns", details)


def enrich_url(url: str, session: requests.Session) -> EnrichmentResult:
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    details = {
        "scheme": parsed.scheme,
        "host": domain,
        "path": parsed.path,
        "port": parsed.port,
    }
    suspicious_tlds = (".tk", ".ml", ".ga", ".cf", ".gq")
    verdict = "suspicious" if domain.endswith(suspicious_tlds) else "investigate"
    if "8888" in url or "beacon" in url.lower():
        verdict = "suspicious"
        details["note"] = "Matches lab C2 URL pattern"
    return EnrichmentResult(url, "url", verdict, "local_heuristic", details)


def enrich_hash(file_hash: str, session: requests.Session, vt_key: Optional[str]) -> EnrichmentResult:
    if not vt_key:
        return EnrichmentResult(
            file_hash, "hash", "unknown", "none",
            {"note": "Set VT_API_KEY environment variable for hash lookup"},
        )
    headers = {"x-apikey": vt_key}
    try:
        r = session.get(f"https://www.virustotal.com/api/v3/files/{file_hash.lower()}", headers=headers, timeout=15)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            verdict = "malicious" if malicious >= 5 else "suspicious" if malicious >= 1 else "clean"
            return EnrichmentResult(
                file_hash, "hash", verdict, "virustotal",
                {"vt_stats": stats, "meaningful_name": attrs.get("meaningful_name")},
            )
        if r.status_code == 404:
            return EnrichmentResult(file_hash, "hash", "unknown", "virustotal", {"note": "Not in VT"})
        return EnrichmentResult(file_hash, "hash", "error", "virustotal", {"status_code": r.status_code})
    except requests.RequestException as exc:
        return EnrichmentResult(file_hash, "hash", "error", "virustotal", {}, str(exc))


def enrich_one(ioc: str, session: requests.Session, vt_key: Optional[str]) -> EnrichmentResult:
    cleaned = clean_ioc(ioc)
    ioc_type = classify_ioc(cleaned)
    if ioc_type == "ip":
        return enrich_ip(cleaned, session)
    if ioc_type == "domain":
        return enrich_domain(cleaned, session, vt_key)
    if ioc_type == "url":
        return enrich_url(cleaned, session)
    if ioc_type == "hash":
        return enrich_hash(cleaned, session, vt_key)
    return EnrichmentResult(cleaned, "unknown", "skipped", "none", {})


def load_iocs(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser(description="Tier 1 IOC enrichment")
    parser.add_argument("--input", "-i", required=True, help="Text file with one IOC per line")
    parser.add_argument("--output", "-o", default="enrichment_report.json", help="Output JSON path")
    parser.add_argument("--vt-key", default=None, help="VirusTotal API key (or VT_API_KEY env)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between API calls (seconds)")
    args = parser.parse_args()

    import os
    vt_key = args.vt_key or os.environ.get("VT_API_KEY")

    iocs = load_iocs(args.input)
    session = requests.Session()
    results = []

    for ioc in iocs:
        result = enrich_one(ioc, session, vt_key)
        results.append(asdict(result))
        print(f"[{result.ioc_type}] {ioc} -> {result.verdict} ({result.source})")
        time.sleep(args.delay)

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ioc_count": len(results),
        "results": results,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
