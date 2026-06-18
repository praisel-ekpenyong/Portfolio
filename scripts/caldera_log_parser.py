#!/usr/bin/env python3
"""Parse Caldera operation JSON export into SIEM-correlation timeline CSV."""

import argparse
import csv
import json
import sys
from datetime import datetime


def parse_operation(report_path: str, output_path: str) -> None:
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    chain = data.get("chain", []) or data.get("steps", [])
    rows = []

    for entry in chain:
        ability = entry.get("ability", {}) or {}
        rows.append({
            "finished_utc": entry.get("finish", entry.get("finished_timestamp", "")),
            "ability_name": ability.get("name", entry.get("ability_name", "unknown")),
            "ability_id": ability.get("ability_id", entry.get("ability_id", "")),
            "technique": _extract_technique(ability, entry),
            "host": entry.get("host", entry.get("paw", "")),
            "status": entry.get("status", ""),
            "output_snippet": (entry.get("output", "") or "")[:200],
        })

    rows.sort(key=lambda r: r["finished_utc"] or "")

    fieldnames = list(rows[0].keys()) if rows else [
        "finished_utc", "ability_name", "ability_id", "technique", "host", "status", "output_snippet"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Parsed {len(rows)} abilities -> {output_path}")


def _extract_technique(ability: dict, entry: dict = None) -> str:
    # Check entry-level technique_id first (flat JSON exports)
    if entry and entry.get("technique_id"):
        return entry["technique_id"]
    # Check entry-level technique as bare string
    if entry and isinstance(entry.get("technique"), str) and entry.get("technique"):
        return entry["technique"]
    # Nested ability dict formats
    technique = ability.get("technique", {})
    if isinstance(technique, dict):
        return technique.get("attack_id", "")
    if isinstance(technique, list) and technique:
        return technique[0].get("attack_id", "")
    return ability.get("technique_id", "")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, help="Caldera operation JSON export")
    parser.add_argument("--output", default="caldera_timeline.csv")
    args = parser.parse_args()
    parse_operation(args.report, args.output)


if __name__ == "__main__":
    main()