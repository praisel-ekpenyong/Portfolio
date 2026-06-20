import json
import socket
import time
from unittest.mock import MagicMock, patch
import pytest
import requests

from scripts.ioc_enrichment import (
    EnrichmentResult,
    classify_ioc,
    enrich_ip,
    enrich_domain,
    enrich_url,
    enrich_hash,
    enrich_one,
    load_iocs,
    main,
)

# 1. Test classify_ioc
@pytest.mark.parametrize(
    "ioc,expected_type",
    [
        ("http://malicious.com/phish", "url"),
        ("https://secure.site.com", "url"),
        ("8.8.8.8", "ip"),
        ("192.168.1.1", "ip"),
        ("44d88612fea8a8f36de82e1278abb02f", "hash"),  # MD5
        ("44d88612fea8a8f36de82e1278abb02f44d88612", "hash"),  # SHA1
        ("8f434346648f6b96df89ec901460c4061c20e290db5d43efca5580a97682f42a", "hash"),  # SHA256
        ("google.com", "domain"),
        ("sub.domain.co.uk", "domain"),
        ("not_a_valid_ioc!!!", "unknown"),
    ],
)
def test_classify_ioc(ioc, expected_type):
    assert classify_ioc(ioc) == expected_type


# 2. Test enrich_ip
def test_enrich_ip_documentation():
    session = MagicMock()
    # RFC 5737 test IP
    res = enrich_ip("192.0.2.1", session)
    assert res.verdict == "sanitized_documentation_ip"
    assert res.source == "local_classification"
    session.get.assert_not_called()


def test_enrich_ip_private():
    session = MagicMock()
    # RFC 1918 test IP
    res = enrich_ip("10.0.0.15", session)
    assert res.verdict == "internal_lab_ip"
    assert res.source == "local_classification"
    session.get.assert_not_called()


def test_enrich_ip_public_success_consumer():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Canada",
        "isp": "Shaw Communications",
        "org": "Shaw Cablesystems",
        "as": "AS6327 Shaw Cablesystems G.P.",
    }
    session.get.return_value = mock_resp

    res = enrich_ip("8.8.8.8", session)
    assert res.verdict == "informational"
    assert res.source == "ip-api"
    assert res.details["country"] == "Canada"
    session.get.assert_called_once_with(
        "https://ip-api.com/json/8.8.8.8?fields=status,message,country,isp,org,as,query",
        timeout=10,
    )


def test_enrich_ip_public_success_hosting():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "isp": "Amazon Technologies Inc. Hosting",
        "org": "Amazon Data Services",
        "as": "AS16509",
    }
    session.get.return_value = mock_resp

    res = enrich_ip("54.239.28.85", session)
    assert res.verdict == "investigate"  # Verdict should flag hosting provider
    assert res.source == "ip-api"


def test_enrich_ip_public_fail():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": "fail",
        "message": "invalid query",
    }
    session.get.return_value = mock_resp

    res = enrich_ip("8.8.4.4", session)  # Handled as string query by API when status is fail
    assert res.verdict == "error"
    assert res.details["message"] == "invalid query"


def test_enrich_ip_public_exception():
    session = MagicMock()
    session.get.side_effect = requests.RequestException("Timeout")

    res = enrich_ip("8.8.8.8", session)
    assert res.verdict == "error"
    assert res.source == "ip-api"
    assert "Timeout" in res.error


# 3. Test enrich_domain
def test_enrich_domain_internal():
    session = MagicMock()
    res = enrich_domain("ad.corp.lab", session, vt_key="somekey")
    assert res.verdict == "internal_lab_domain"
    assert res.source == "local_classification"
    session.get.assert_not_called()


def test_enrich_domain_vt_clean():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5,
                }
            }
        }
    }
    session.get.return_value = mock_resp

    res = enrich_domain("clean.com", session, vt_key="my_key")
    assert res.verdict == "clean"
    assert res.source == "virustotal"
    session.get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/domains/clean.com",
        headers={"x-apikey": "my_key"},
        timeout=15,
    )


def test_enrich_domain_vt_suspicious():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 1,
                }
            }
        }
    }
    session.get.return_value = mock_resp

    res = enrich_domain("sus.com", session, vt_key="my_key")
    assert res.verdict == "suspicious"


def test_enrich_domain_vt_malicious():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                }
            }
        }
    }
    session.get.return_value = mock_resp

    res = enrich_domain("bad.com", session, vt_key="my_key")
    assert res.verdict == "malicious"


def test_enrich_domain_vt_error():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    session.get.return_value = mock_resp

    res = enrich_domain("bad.com", session, vt_key="my_key")
    assert res.verdict == "error"
    assert res.details["status_code"] == 403


def test_enrich_domain_vt_exception():
    session = MagicMock()
    session.get.side_effect = requests.RequestException("Connection aborted")

    res = enrich_domain("error.com", session, vt_key="my_key")
    assert res.verdict == "error"
    assert "Connection aborted" in res.error


@patch("socket.gethostbyname")
def test_enrich_domain_no_key_resolves(mock_gethostbyname):
    # Mocking socket resolution to prevent real network calls
    mock_gethostbyname.return_value = "1.2.3.4"
    session = MagicMock()

    res = enrich_domain("resolves-locally.com", session, vt_key=None)
    assert res.verdict == "resolves"
    assert res.source == "dns"
    mock_gethostbyname.assert_called_once_with("resolves-locally.com")
    session.get.assert_not_called()


@patch("socket.gethostbyname")
def test_enrich_domain_no_key_nxdomain(mock_gethostbyname):
    mock_gethostbyname.side_effect = socket.gaierror("Name or service not known")
    session = MagicMock()

    res = enrich_domain("does-not-exist.com", session, vt_key=None)
    assert res.verdict == "nxdomain"
    assert res.source == "dns"
    mock_gethostbyname.assert_called_once_with("does-not-exist.com")
    session.get.assert_not_called()


# 4. Test enrich_url
def test_enrich_url_suspicious_tld():
    session = MagicMock()
    res = enrich_url("http://phish-site.tk/login", session)
    assert res.verdict == "suspicious"
    assert res.details["host"] == "phish-site.tk"


def test_enrich_url_lab_c2_keyword():
    session = MagicMock()
    res = enrich_url("https://normaldomain.com:8888/payload", session)
    assert res.verdict == "suspicious"
    assert "C2" in res.details["note"]

    res2 = enrich_url("http://legit.org/beaconing/active", session)
    assert res2.verdict == "suspicious"
    assert "C2" in res2.details["note"]


def test_enrich_url_normal():
    session = MagicMock()
    res = enrich_url("https://github.com/praisel-ekpenyong", session)
    assert res.verdict == "investigate"
    assert res.details["host"] == "github.com"


# 5. Test enrich_hash
def test_enrich_hash_no_key():
    session = MagicMock()
    res = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key=None)
    assert res.verdict == "unknown"
    assert "VT_API_KEY" in res.details["note"]
    session.get.assert_not_called()


def test_enrich_hash_vt_clean():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                "meaningful_name": "clean_app.exe",
            }
        }
    }
    session.get.return_value = mock_resp

    res = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res.verdict == "clean"
    assert res.details["meaningful_name"] == "clean_app.exe"
    session.get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f",
        headers={"x-apikey": "my_key"},
        timeout=15,
    )


def test_enrich_hash_vt_suspicious():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "suspicious": 0},
                "meaningful_name": "sus_file.exe",
            }
        }
    }
    session.get.return_value = mock_resp

    res = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res.verdict == "suspicious"


def test_enrich_hash_vt_malicious():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 1},
                "meaningful_name": "malware.exe",
            }
        }
    }
    session.get.return_value = mock_resp

    res = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res.verdict == "malicious"


def test_enrich_hash_vt_not_found():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    session.get.return_value = mock_resp

    res = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res.verdict == "unknown"
    assert "Not in VT" in res.details["note"]


def test_enrich_hash_vt_api_failures():
    session = MagicMock()
    
    # 429 Rate Limit
    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429
    session.get.return_value = mock_resp_429
    res_429 = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res_429.verdict == "error"
    assert res_429.details["status_code"] == 429

    # 403 Forbidden
    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403
    session.get.return_value = mock_resp_403
    res_403 = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res_403.verdict == "error"
    assert res_403.details["status_code"] == 403

    # 500 Server Error
    mock_resp_500 = MagicMock()
    mock_resp_500.status_code = 500
    session.get.return_value = mock_resp_500
    res_500 = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res_500.verdict == "error"
    assert res_500.details["status_code"] == 500


def test_enrich_hash_vt_exception():
    session = MagicMock()
    session.get.side_effect = requests.RequestException("Connection refused")

    res = enrich_hash("44d88612fea8a8f36de82e1278abb02f", session, vt_key="my_key")
    assert res.verdict == "error"
    assert "Connection refused" in res.error


# 6. Test load_iocs with malformed inputs/comments
def test_load_iocs(tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    content = """# This is a comment line
1.1.1.1
  # Another indented comment
  google.com  
  
http://attacker.tk
"""
    ioc_file.write_text(content, encoding="utf-8")
    
    loaded = load_iocs(str(ioc_file))
    # Check trailing/leading spaces are removed and empty/comment lines skipped
    assert loaded == ["1.1.1.1", "google.com", "http://attacker.tk"]


# 7. Test CLI integration (main)
@patch("scripts.ioc_enrichment.time.sleep") # mock time.sleep to bypass CLI delay
@patch("socket.gethostbyname")
def test_main_cli(mock_gethostbyname, mock_sleep, tmp_path):
    mock_gethostbyname.return_value = "1.2.3.4"
    
    ioc_file = tmp_path / "iocs.txt"
    output_file = tmp_path / "report.json"
    
    # Writing test IOCs
    content = """192.168.1.1
google.com
http://phish.tk
"""
    ioc_file.write_text(content, encoding="utf-8")
    
    with patch("sys.argv", ["ioc_enrichment.py", "--input", str(ioc_file), "--output", str(output_file), "--delay", "5.0"]):
        # Pass a large delay to verify our mock sleep completely bypasses it
        main()
        
    assert output_file.exists()
    mock_sleep.assert_called()  # ensure delay loop was executed
    # Ensure delay was bypassed in tests (should execute instantly)
    
    with open(output_file, encoding="utf-8") as f:
        report = json.load(f)
        assert "generated_at" in report
        assert report["ioc_count"] == 3
        
        results = report["results"]
        assert results[0]["ioc"] == "192.168.1.1"
        assert results[0]["verdict"] == "internal_lab_ip"
        
        assert results[1]["ioc"] == "google.com"
        assert results[1]["verdict"] == "resolves"
        
        assert results[2]["ioc"] == "http://phish.tk"
        assert results[2]["verdict"] == "suspicious"
