# Scenario 01 — Windows BITS Download (Caldera)

**Incident Record:** [`INC-2026-001`](../../incidents/INC-2026-001-bits-job-download.md)

## Objective

Demonstrate Tier 1 triage of LOLBin abuse on Windows using Wazuh, Splunk, Sentinel, and MDE.

## Caldera Setup

| Setting | Value |
|---------|-------|
| Adversary | `T1-Windows-Download-Exec` |
| Agent | WKSTN-042 (sandcat, group `blue-team-lab`) |
| Planner | atomic |

## Run Operation

1. Start operation in Caldera UI
2. Note UTC timestamp
3. Wait for abilities: BITS download → save → execute

## Expected Alerts

| Source | Identifier |
|--------|------------|
| Wazuh | Rule 180001 |
| Sysmon | Event ID 1, 11 |
| Defender | Suspicious process chain |

## Lab Replay Checklist

- [ ] Acknowledge ticket < 15 min
- [ ] Run Splunk query in `detections/splunk/T1197_bits_download.spl`
- [ ] Enrich IOCs with `scripts/ioc_enrichment.py`
- [ ] Isolate host via MDE
- [ ] Complete `incidents/INC-2026-001-bits-job-download.md`
- [ ] Stop Caldera operation and verify cleanup

## MITRE Mapping

| Technique | Name |
|-----------|------|
| T1197 | BITS Jobs |
| T1105 | Ingress Tool Transfer |
| T1059.003 | Windows Command Shell |

## Skills Practiced

SIEM correlation, Windows event analysis, containment authorization, escalation to T2, IOC enrichment.