import csv
import json
import sys
from pathlib import Path
from unittest.mock import patch
import pytest

from scripts.caldera_log_parser import _extract_technique, parse_operation, main

def test_extract_technique_flat_technique_id():
    entry = {"technique_id": "T1059.001"}
    ability = {}
    assert _extract_technique(ability, entry) == "T1059.001"

def test_extract_technique_flat_technique_string():
    entry = {"technique": "T1059"}
    ability = {}
    assert _extract_technique(ability, entry) == "T1059"

def test_extract_technique_nested_dict():
    entry = {}
    ability = {"technique": {"attack_id": "T1082"}}
    assert _extract_technique(ability, entry) == "T1082"

def test_extract_technique_nested_list():
    entry = {}
    ability = {"technique": [{"attack_id": "T1033"}]}
    assert _extract_technique(ability, entry) == "T1033"

def test_extract_technique_ability_technique_id():
    entry = {}
    ability = {"technique_id": "T1016"}
    assert _extract_technique(ability, entry) == "T1016"

def test_extract_technique_empty():
    assert _extract_technique({}, {}) == ""

def test_parse_operation_success(tmp_path):
    report_file = tmp_path / "caldera_report.json"
    output_file = tmp_path / "timeline.csv"

    mock_report = {
        "chain": [
            {
                "finish": "2026-06-19T04:00:00Z",
                "ability": {"name": "Discovery", "ability_id": "ab-1"},
                "technique_id": "T1082",
                "host": "wkstn-01",
                "status": "0",
                "output": "A" * 300  # Longer than 200 chars
            },
            {
                "finish": "2026-06-19T03:00:00Z",  # Earlier timestamp to test sorting
                "ability": {"name": "Recon", "ability_id": "ab-2"},
                "technique_id": "T1595",
                "host": "wkstn-02",
                "status": "1",
                "output": "short output"
            }
        ]
    }

    report_file.write_text(json.dumps(mock_report), encoding="utf-8")
    
    parse_operation(str(report_file), str(output_file))
    
    assert output_file.exists()
    
    with open(output_file, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        
        # Verify count
        assert len(rows) == 2
        
        # Verify sorting (earlier timestamp should be first)
        assert rows[0]["finished_utc"] == "2026-06-19T03:00:00Z"
        assert rows[0]["ability_name"] == "Recon"
        
        assert rows[1]["finished_utc"] == "2026-06-19T04:00:00Z"
        assert rows[1]["ability_name"] == "Discovery"
        
        # Verify output snippet truncation (200 characters maximum)
        assert len(rows[1]["output_snippet"]) == 200
        assert rows[1]["output_snippet"] == "A" * 200

def test_parse_operation_missing_chain_and_steps(tmp_path):
    report_file = tmp_path / "empty_keys.json"
    output_file = tmp_path / "empty_timeline.csv"
    
    # Valid JSON, but missing chain/steps
    report_file.write_text(json.dumps({"operation_id": "123"}), encoding="utf-8")
    
    parse_operation(str(report_file), str(output_file))
    assert output_file.exists()
    
    with open(output_file, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 0

def test_parse_operation_malformed_json(tmp_path):
    report_file = tmp_path / "malformed.json"
    output_file = tmp_path / "timeline.csv"
    
    # Writing malformed JSON content
    report_file.write_text("{invalid json", encoding="utf-8")
    
    with pytest.raises(json.JSONDecodeError):
        parse_operation(str(report_file), str(output_file))

def test_main_cli(tmp_path):
    report_file = tmp_path / "report.json"
    output_file = tmp_path / "cli_timeline.csv"
    
    mock_report = {
        "steps": [  # Test steps key as well
            {
                "finished_timestamp": "2026-06-19T05:00:00Z",
                "ability_name": "Execution",
                "ability_id": "ab-3",
                "technique": "T1059",
                "paw": "wkstn-03",
                "status": "0",
                "output": "execution ok"
            }
        ]
    }
    report_file.write_text(json.dumps(mock_report), encoding="utf-8")
    
    with patch("sys.argv", ["caldera_log_parser.py", "--report", str(report_file), "--output", str(output_file)]):
        main()
        
    assert output_file.exists()
    with open(output_file, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["ability_name"] == "Execution"
        assert rows[0]["technique"] == "T1059"
