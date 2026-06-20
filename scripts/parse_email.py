#!/usr/bin/env python3
"""
Automated Phishing Email Header Parser and Triage Script.
Parses raw email (.eml) files, extracts critical security headers, 
authentications (SPF/DKIM/DMARC), hops, decoded body links, and attachment hashes.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import html
import ipaddress
import json
import re
import sys
from email.message import Message
from typing import Any, Optional
from urllib.parse import urlparse
# Reconfigure stdout/stderr to use UTF-8 to prevent encoding errors on Windows terminal environments when printing emojis.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Regex for IPv4
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Regex for general URLs
URL_RE = re.compile(r"\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"'<>]*)?")


def defang_url(url: str) -> str:
    """Defangs a URL to prevent accidental clicks (e.g. hxxps://attacker[.]com/path)."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return url
        defanged_host = host.replace(".", "[.]")
        scheme = parsed.scheme.lower().replace("http", "hxxp")
        
        # Reconstruct the URL path and queries
        rest = url.split(host, 1)[1] if host in url else ""
        return f"{scheme}://{defanged_host}{rest}"
    except Exception:
        return url.replace(".", "[.]").replace("http", "hxxp")


def extract_ips(text: str) -> list[str]:
    """Finds all IP addresses in text and returns unique ones."""
    return sorted(list(set(IP_RE.findall(text))))


def get_external_ips(ips: list[str]) -> list[str]:
    """Filters out private/loopback/lab IP addresses to isolate the external source."""
    external = []
    # Lab networks to filter
    lab_nets = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            if not any(ip in net for net in lab_nets) and not ip.is_multicast and not ip.is_reserved:
                external.append(ip_str)
        except ValueError:
            continue
    return external


def parse_authentication_results(msg: Message) -> dict[str, str]:
    """Extracts and parses SPF, DKIM, and DMARC alignment from headers."""
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "raw": ""}
    
    # Check Authentication-Results header
    auth_headers = msg.get_all("Authentication-Results") or []
    # Also check other common headers as fallbacks
    auth_headers.extend(msg.get_all("X-Authentication-Results") or [])
    
    if not auth_headers:
        return results
        
    raw_auth = " ".join(auth_headers)
    results["raw"] = raw_auth
    
    # Normalize spacing to simplify regex matching
    auth_clean = " ".join(raw_auth.split())
    
    # Search for spf, dkim, dmarc status
    spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z0-9_-]+)", auth_clean, re.IGNORECASE)
    dkim_match = re.search(r"\bdkim\s*=\s*([a-zA-Z0-9_-]+)", auth_clean, re.IGNORECASE)
    dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z0-9_-]+)", auth_clean, re.IGNORECASE)
    
    if spf_match:
        results["spf"] = spf_match.group(1).lower()
    if dkim_match:
        results["dkim"] = dkim_match.group(1).lower()
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).lower()
        
    return results


def extract_received_hops(msg: Message) -> list[dict[str, Any]]:
    """Parses Received headers into sequential hops from oldest to newest."""
    hops = []
    received_headers = msg.get_all("Received") or []
    
    # Reverse to represent chronologically: bottom-most is first ingress (oldest)
    for index, header in enumerate(reversed(received_headers)):
        header_clean = " ".join(header.split())
        ips = extract_ips(header_clean)
        
        # Extract sender name if matching pattern "from server-name"
        from_match = re.search(r"from\s+([^\s()]+)", header_clean, re.IGNORECASE)
        by_match = re.search(r"by\s+([^\s()]+)", header_clean, re.IGNORECASE)
        
        hops.append({
            "hop": index + 1,
            "raw": header_clean,
            "from": from_match.group(1) if from_match else "unknown",
            "by": by_match.group(1) if by_match else "unknown",
            "ips": ips,
            "external_ips": get_external_ips(ips)
        })
    return hops


def decode_mime_header(val: Optional[str]) -> str:
    if not val:
        return ""
    try:
        # Recover raw bytes if already decoded as string with incorrect encoding
        if isinstance(val, str):
            try:
                # Try to recover bytes using latin-1 encoding
                raw_bytes = val.encode('latin-1', errors='strict')
            except Exception:
                try:
                    raw_bytes = val.encode('utf-8', errors='surrogateescape')
                except Exception:
                    raw_bytes = val.encode('utf-8', errors='replace')
        else:
            raw_bytes = val

        from email.header import decode_header
        decoded_parts = decode_header(raw_bytes)
        header_parts = []
        for text, charset in decoded_parts:
            if isinstance(text, bytes):
                # Try decoding with different charsets in sequence
                decoded = None
                for enc in (charset, 'utf-8', 'cp1252', 'latin-1'):
                    if not enc:
                        continue
                    try:
                        decoded = text.decode(enc, errors='strict')
                        break
                    except Exception:
                        continue
                if decoded is None:
                    decoded = text.decode('utf-8', errors='replace')
                header_parts.append(decoded)
            else:
                header_parts.append(text)
        return "".join(header_parts)
    except Exception:
        return str(val)


def parse_email_message(msg: Message) -> dict[str, Any]:
    """Traverses MIME message and parses headers, authentication, hops, body, links, and attachments."""
    # Basic envelope headers
    subject = decode_mime_header(msg.get("Subject") or "(No Subject)")
    from_header = decode_mime_header(msg.get("From") or "(No From)")
    to_header = decode_mime_header(msg.get("To") or "(No To)")
    reply_to = decode_mime_header(msg.get("Reply-To") or "")
    return_path = decode_mime_header(msg.get("Return-Path") or "")
    date_header = decode_mime_header(msg.get("Date") or "")
    msg_id = decode_mime_header(msg.get("Message-ID") or "")
    
    # Extract email addresses from From/Return-Path to check for spoofing anomalies
    from_email = ""
    from_match = re.search(r"<([^>]+)>", from_header)
    if from_match:
        from_email = from_match.group(1).strip()
    else:
        from_email = from_header.strip()
        
    return_path_email = ""
    if return_path:
        rp_match = re.search(r"<([^>]+)>", return_path)
        return_path_email = rp_match.group(1).strip() if rp_match else return_path.strip()

    # Domain mismatch check (Return-Path domain vs From header domain)
    domain_anomaly = False
    if from_email and return_path_email:
        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        rp_domain = return_path_email.split("@")[-1].lower() if "@" in return_path_email else ""
        if from_domain and rp_domain and from_domain != rp_domain:
            domain_anomaly = True

    # Parse headers and hops
    auth_results = parse_authentication_results(msg)
    hops = extract_received_hops(msg)
    
    # Isolate ingress IP (oldest hop IP or sender IP in auth results)
    ingress_ip = "unknown"
    if hops:
        # Check oldest hop for external IPs
        for hop in hops:
            if hop["external_ips"]:
                ingress_ip = hop["external_ips"][0]
                break
    # Fallback to any IP in the raw Auth Results header if hops didn't yield an external IP
    if ingress_ip == "unknown" and auth_results["raw"]:
        auth_ips = get_external_ips(extract_ips(auth_results["raw"]))
        if auth_ips:
            ingress_ip = auth_ips[0]

    # Content extraction variables
    bodies = []
    urls = set()
    attachments = []

    # Traverse MIME parts
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()
        filename = part.get_filename()

        # Attachment Check
        if content_disposition == "attachment" or filename:
            filename = filename or "unnamed_attachment"
            
            # Size check to prevent memory exhaustion (max 50MB limit)
            content_length = part.get("Content-Length")
            raw_payload = part.get_payload()
            if (content_length and int(content_length) > 50 * 1024 * 1024) or \
               (isinstance(raw_payload, str) and len(raw_payload) > 70 * 1024 * 1024):
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": int(content_length) if content_length else len(raw_payload),
                    "md5": "skipped_due_to_size",
                    "sha1": "skipped_due_to_size",
                    "sha256": "skipped_due_to_size"
                })
                continue
                
            payload = part.get_payload(decode=True)
            if payload is not None:
                size_bytes = len(payload)
                md5_hash = hashlib.md5(payload).hexdigest()
                sha1_hash = hashlib.sha1(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "md5": md5_hash,
                    "sha1": sha1_hash,
                    "sha256": sha256_hash
                })
        # Text/HTML/Plain Body Check
        elif content_type in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if payload is not None:
                charset = part.get_content_charset() or "utf-8"
                try:
                    body_text = payload.decode(charset, errors="replace")
                except Exception:
                    body_text = payload.decode("latin-1", errors="replace")
                
                # Unescape HTML entities
                body_clean = html.unescape(body_text)
                bodies.append({
                    "content_type": content_type,
                    "content": body_clean
                })
                
                # Extract URLs from HTML href attributes
                if content_type == "text/html":
                    hrefs = re.findall(r'href=["\'](https?://[^"\']+)["\']', body_clean, re.IGNORECASE)
                    urls.update(hrefs)
                
                # Extract any other URLs matching standard patterns
                raw_urls = URL_RE.findall(body_clean)
                urls.update(raw_urls)

    return {
        "subject": subject,
        "from": from_header,
        "from_email": from_email,
        "to": to_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "return_path_email": return_path_email,
        "domain_anomaly": domain_anomaly,
        "date": date_header,
        "message_id": msg_id,
        "ingress_ip": ingress_ip,
        "authentication": auth_results,
        "hops": hops,
        "attachments": attachments,
        "urls": sorted(list(urls)),
        "bodies_count": len(bodies),
        "bodies": bodies
    }


def generate_markdown_report(data: dict[str, Any]) -> str:
    """Formats parsed email data into a structured Tier 1 Triage Report."""
    auth = data["authentication"]
    
    # Check authentication alignment
    spf_status = auth["spf"].upper()
    dkim_status = auth["dkim"].upper()
    dmarc_status = auth["dmarc"].upper()
    
    spf_alert = "FAIL" if "fail" in auth["spf"] else "PASS" if "pass" in auth["spf"] else "UNKNOWN/NONE"
    dkim_alert = "FAIL" if "fail" in auth["dkim"] else "PASS" if "pass" in auth["dkim"] else "UNKNOWN/NONE"
    dmarc_alert = "FAIL" if "fail" in auth["dmarc"] else "PASS" if "pass" in auth["dmarc"] else "UNKNOWN/NONE"

    # Evaluate Spoofing / Anomalies
    anomalies = []
    if data["domain_anomaly"]:
        anomalies.append(f"**Domain Mismatch**: From header domain (`{data['from_email'].split('@')[-1]}`) does not match Return-Path (`{data['return_path_email'].split('@')[-1]}`).")
    if data["reply_to"] and data["from_email"] not in data["reply_to"]:
        anomalies.append(f"**Reply-To Mismatch**: Reply-To header is set to `{data['reply_to']}`, pointing to a different address than From.")

    anomaly_text = "\n".join([f"- {a}" for a in anomalies]) if anomalies else "None detected"

    # Defang URLs
    defanged_urls = [defang_url(u) for u in data["urls"]]
    urls_text = "\n".join([f"- `{u}`" for u in defanged_urls]) if defanged_urls else "None detected"

    # Formatting attachments
    attachments_text = ""
    if data["attachments"]:
        for att in data["attachments"]:
            attachments_text += f"""#### Attachment: {att['filename']}
- **Content-Type**: `{att['content_type']}`
- **Size**: {att['size_bytes']} bytes
- **MD5**: `{att['md5']}`
- **SHA256**: `{att['sha256']}`
"""
    else:
        attachments_text = "None detected"

    # Hops timeline
    hops_text = "| Hop | From | By | Hops IPs | External ingress? |\n|---|---|---|---|---|\n"
    if data["hops"]:
        for hop in data["hops"]:
            ips = ", ".join(hop["ips"]) if hop["ips"] else "none"
            ext_ips = ", ".join(hop["external_ips"]) if hop["external_ips"] else "none"
            is_ingress = "YES" if ext_ips else "No"
            hops_text += f"| {hop['hop']} | {hop['from']} | {hop['by']} | {ips} | {is_ingress} |\n"
    else:
        hops_text += "| - | - | - | - | - |\n"

    report = f"""# Phishing Email Header Analysis & Triage Report

## Email Information
| Header | Value |
|---|---|
| **Subject** | {data['subject']} |
| **From** | `{data['from']}` |
| **To** | `{data['to']}` |
| **Date** | {data['date']} |
| **Message-ID** | `{data['message_id']}` |
| **Return-Path**| `{data['return_path']}` |
| **Reply-To** | `{data['reply_to']}` |
| **Ingress IP** | `{data['ingress_ip']}` |

## Authentication Triad
| Protocol | Result | Assessment |
|---|---|---|
| **SPF** | `{spf_status}` | {spf_alert} |
| **DKIM** | `{dkim_status}` | {dkim_alert} |
| **DMARC** | `{dmarc_status}` | {dmarc_alert} |

## Security Anomalies
{anomaly_text}

## Extracted URLs (Defanged)
{urls_text}

## Attachments
{attachments_text}

## Mail Routing Hops (Oldest to Newest)
{hops_text}
"""
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated Phishing Email Header Parser for SOC L1")
    parser.add_argument("--input", "-i", required=True, help="Path to raw .eml file to parse")
    parser.add_argument("--output", "-o", help="Path to write the report file (formats based on extension: .md or .json)")
    parser.add_argument("--json", action="store_true", help="Print output in JSON format to stdout")
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            msg = email.message_from_binary_file(f)
    except FileNotFoundError:
        print(f"[Error] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[Error] Failed to read email file: {exc}", file=sys.stderr)
        sys.exit(1)

    # Parse raw message
    parsed_data = parse_email_message(msg)

    # Export formats
    if args.json:
        # Remove raw body content for concise JSON stdout display
        clean_json_data = parsed_data.copy()
        if "bodies" in clean_json_data:
            del clean_json_data["bodies"]
        output_str = json.dumps(clean_json_data, indent=2)
        print(output_str)
    else:
        output_str = generate_markdown_report(parsed_data)
        print(output_str)

    if args.output:
        try:
            if args.output.endswith(".json"):
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(parsed_data, f, indent=2)
            else:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_str)
            print(f"\n[+] Report successfully saved to: {args.output}")
        except Exception as exc:
            print(f"[Error] Failed to write output file: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
