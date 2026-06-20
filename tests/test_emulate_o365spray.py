import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import requests

from scripts.emulate_o365spray import load_userlist, check_user_realm, spray_oauth2_token, main


def test_load_userlist_success(tmp_path):
    user_file = tmp_path / "users.txt"
    user_file.write_text("user1@corp.lab\n# this is a comment\n\nuser2@corp.lab\n", encoding="utf-8")
    
    users = load_userlist(str(user_file))
    assert len(users) == 2
    assert users[0] == "user1@corp.lab"
    assert users[1] == "user2@corp.lab"


def test_load_userlist_failure():
    # Non-existent file path should return empty list gracefully
    users = load_userlist("non_existent_file_path_12345.txt")
    assert users == []


@patch("requests.Session.get")
def test_check_user_realm_managed(mock_get):
    # Setup mock response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_name = "json"
    mock_resp.json.return_value = {"NameSpaceType": "Managed"}
    mock_get.return_value = mock_resp
    
    session = requests.Session()
    res = check_user_realm("test@domain.com", session)
    
    assert res["username"] == "test@domain.com"
    assert res["exists"] is True
    assert res["type"] == "Managed"
    assert res["domain"] == "domain.com"


@patch("requests.Session.get")
def test_check_user_realm_unknown(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"NameSpaceType": "Unknown"}
    mock_get.return_value = mock_resp
    
    session = requests.Session()
    res = check_user_realm("invalid@domain.com", session)
    
    assert res["exists"] is False
    assert res["type"] == "Unknown"


@patch("requests.Session.post")
def test_spray_oauth2_token_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "mock_token"}
    mock_post.return_value = mock_resp
    
    session = requests.Session()
    res = spray_oauth2_token("test@domain.com", "password123", session)
    
    assert res["status"] == "SUCCESS"
    assert res["code"] == "0"


@patch("requests.Session.post")
def test_spray_oauth2_token_invalid_password(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"error_codes": [50126], "error_description": "Invalid credentials"}
    mock_post.return_value = mock_resp
    
    session = requests.Session()
    res = spray_oauth2_token("test@domain.com", "wrong_password", session)
    
    assert res["status"] == "FAILURE"
    assert res["code"] == "50126"


@patch("requests.Session.post")
def test_spray_oauth2_token_mfa_required(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    # 50076 or 50079 represents MFA required
    mock_resp.json.return_value = {"error_codes": [50076], "error_description": "MFA required"}
    mock_post.return_value = mock_resp
    
    session = requests.Session()
    res = spray_oauth2_token("test@domain.com", "correct_password_but_mfa", session)
    
    assert res["status"] == "SUCCESS_MFA"
    assert res["code"] == "50076"


def test_main_mock_spray(tmp_path):
    user_file = tmp_path / "users.txt"
    user_file.write_text("jsmith@corp.lab\nuser2@corp.lab", encoding="utf-8")
    output_file = tmp_path / "spray_report.json"
    
    # Mock CLI arguments for mock run
    cli_args = [
        "emulate_o365spray.py",
        "-u", str(user_file),
        "-p", "Winter2026",
        "--mock",
        "--success-user", "jsmith@corp.lab",
        "--validate",
        "-o", str(output_file)
    ]
    
    with patch("sys.argv", cli_args):
        main()
        
    assert output_file.exists()
    
    with open(output_file, encoding="utf-8") as f:
        report = json.load(f)
        assert report["mode"] == "mock"
        assert report["summary"]["total"] == 2
        assert report["summary"]["success"] == 1
        assert report["summary"]["failure"] == 1
        
        # Verify success on jsmith
        jsmith_res = [r for r in report["results"] if r["username"] == "jsmith@corp.lab"][0]
        assert jsmith_res["status"] == "SUCCESS"
        
        # Verify failure on user2
        user2_res = [r for r in report["results"] if r["username"] == "user2@corp.lab"][0]
        assert user2_res["status"] == "FAILURE"
        assert user2_res["code"] == "50126"
