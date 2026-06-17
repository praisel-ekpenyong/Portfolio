# Supplemental Case: RDP Port Change & Network Sniffing (Not Core Portfolio)

> **Portfolio status:** Stretch module for PCAP/network correlation practice. Replaced in the core five-case set by [INC-2026-003 — Scheduled task persistence](../incidents/INC-2026-003-scheduled-task-persistence.md).

**Original incident ID:** INC-2026-003-RDP (archived)  
**Caldera profile:** `T1-Windows-Lateral`  
**MITRE:** T1040, T1021.001  
**Host:** WKSTN-099 (finance segment)

## Summary

Wazuh alerted on `tshark.exe` execution and RDP registry port change. Analyst correlated pfSense logs and PCAP — no credential exfil; IR engaged per finance-segment policy.

## Walkthrough

Full PCAP methodology: [`pcap-analysis-guide.md`](pcap-analysis-guide.md)

## Why supplemental

Valuable for Tier 2/IR depth, but heavier than the scheduled-task persistence case for entry-level portfolio interviews.