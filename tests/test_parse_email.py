import os
import email
from email.message import Message
import pytest
from scripts.parse_email import (
    defang_url,
    extract_ips,
    get_external_ips,
    parse_authentication_results,
    extract_received_hops,
    parse_email_message,
    generate_markdown_report,
)

# Define path to the sample EML file in the workspace
SAMPLE_EML_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "artifacts", "phishing-invoice.eml")


def test_defang_url():
    assert defang_url("http://google.com") == "hxxp://google[.]com"
    assert defang_url("https://sub.domain.co.uk/path?query=1") == "hxxps://sub[.]domain[.]co[.]uk/path?query=1"
    assert defang_url("ftp://legit-site.com") == "ftp://legit-site[.]com"  # Only http/https are changed to hxxp/hxxps, but host is defanged
    assert defang_url("http://malicious.com:8080/beacon") == "hxxp://malicious[.]com:8080/beacon"
    assert defang_url("invalid-url") == "invalid-url"


def test_extract_ips():
    text = "Received from 192.168.1.10 and relayed to 10.10.10.50 via 203.0.113.88"
    ips = extract_ips(text)
    assert ips == ["10.10.10.50", "192.168.1.10", "203.0.113.88"]


def test_get_external_ips():
    ips = [
        "10.0.0.1",       # RFC 1918 Private
        "127.0.0.1",      # Loopback
        "192.0.2.5",       # RFC 5737 Test Net 1
        "203.0.113.88",   # RFC 5737 Test Net 3
        "8.8.8.8",        # Public DNS (External)
        "198.51.100.10",  # RFC 5737 Test Net 2
        "8.8.4.4",        # Public DNS (External)
    ]
    external = get_external_ips(ips)
    assert external == ["192.0.2.5", "203.0.113.88", "8.8.8.8", "198.51.100.10", "8.8.4.4"]


def test_parse_authentication_results():
    msg = Message()
    msg["Authentication-Results"] = (
        "mx.corp.lab;\r\n"
        "\tspf=fail (sender IP 203.0.113.88) smtp.mailfrom=vendor-secure.com;\r\n"
        "\tdkim=none;\r\n"
        "\tdmarc=fail action=none header.from=vendor-secure.com"
    )
    results = parse_authentication_results(msg)
    assert results["spf"] == "fail"
    assert results["dkim"] == "none"
    assert results["dmarc"] == "fail"


def test_extract_received_hops():
    msg = Message()
    # Adding two Received headers
    msg.add_header(
        "Received",
        "from internal-relay.corp.lab.local (10.10.20.50) by mail-destination.corp.lab; Wed, 17 Jun 2026 13:55:04 +0000"
    )
    msg.add_header(
        "Received",
        "from mail-sender-unknown (8.8.8.8) by mx.corp.lab; Wed, 17 Jun 2026 13:55:02 +0000"
    )
    hops = extract_received_hops(msg)
    assert len(hops) == 2
    # Chronological verification (oldest is bottom-most in email headers, which means last added/lowest)
    # The last header added is index 1, which should be Hop 1 (oldest)
    assert hops[0]["hop"] == 1
    assert hops[0]["from"] == "mail-sender-unknown"
    assert "8.8.8.8" in hops[0]["ips"]
    assert hops[0]["external_ips"] == ["8.8.8.8"]

    assert hops[1]["hop"] == 2
    assert hops[1]["from"] == "internal-relay.corp.lab.local"
    assert "10.10.20.50" in hops[1]["ips"]
    assert hops[1]["external_ips"] == []


def test_parse_sample_eml():
    # Make sure sample EML exists
    assert os.path.exists(SAMPLE_EML_PATH), f"Sample email artifact not found at {SAMPLE_EML_PATH}"

    with open(SAMPLE_EML_PATH, "rb") as f:
        msg = email.message_from_binary_file(f)

    data = parse_email_message(msg)

    # Envelope Header checks
    assert "Invoice #88421" in data["subject"]
    assert "payable@vendor-secure.com" in data["from"]
    assert data["from_email"] == "payable@vendor-secure.com"
    assert data["return_path_email"] == "bounce+xyz@mail.vendor-secure.com"
    assert data["domain_anomaly"] is True  # vendor-secure.com vs mail.vendor-secure.com
    assert data["reply_to"] == "attacker-drop@protonmail.com"

    # Authentication Checks
    assert data["authentication"]["spf"] == "fail"
    assert data["authentication"]["dkim"] == "none"
    assert data["authentication"]["dmarc"] == "fail"

    # Hops Check (The oldest hop has IP 203.0.113.88)
    assert data["ingress_ip"] == "203.0.113.88"

    # Attachment checks
    assert len(data["attachments"]) == 1
    attachment = data["attachments"][0]
    assert attachment["filename"] == "Invoice_June2026.zip"
    assert attachment["content_type"] == "application/zip"
    # Content has redacted notes, size should be greater than 0
    assert attachment["size_bytes"] > 0
    # MD5 & SHA256 hashes must be generated
    assert len(attachment["md5"]) == 32
    assert len(attachment["sha256"]) == 64

    # URL Check
    # The body has hxxps://vendor-secure.com.login-update.tk/invoice?id=88421
    assert any("login-update.tk" in url for url in data["urls"])


def test_generate_markdown_report():
    # Verify that the report generator compiles and doesn't crash on standard schema
    data = {
        "subject": "Test Alert",
        "from": "Sender <sender@test.com>",
        "from_email": "sender@test.com",
        "to": "Recipient <recipient@test.com>",
        "date": "Wed, 17 Jun 2026 13:55:00 +0000",
        "message_id": "<test-id@domain>",
        "return_path": "<sender@test.com>",
        "return_path_email": "sender@test.com",
        "reply_to": "",
        "domain_anomaly": False,
        "ingress_ip": "8.8.8.8",
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "raw": "spf=pass dkim=pass dmarc=pass"
        },
        "hops": [
            {
                "hop": 1,
                "from": "sender.com",
                "by": "mx.test.com",
                "ips": ["8.8.8.8"],
                "external_ips": ["8.8.8.8"]
            }
        ],
        "attachments": [
            {
                "filename": "malware.exe",
                "content_type": "application/octet-stream",
                "size_bytes": 1024,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        ],
        "urls": ["http://phish-link.tk/login"]
    }
    
    report = generate_markdown_report(data)
    
    assert "Test Alert" in report
    assert "sender@test.com" in report
    assert "8.8.8.8" in report
    assert "PASS" in report
    assert "hxxp://phish-link[.]tk/login" in report
    assert "malware.exe" in report
    assert "d41d8cd98f00b204e9800998ecf8427e" in report
