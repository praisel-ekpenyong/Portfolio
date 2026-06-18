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

## Production Transfer

In a production environment, this same investigation pattern applies to any unauthorized RDP activity:

1. **Correlate** — Match RDP logon events (4624 Type 10) with PCAP/network flow to confirm source host.
2. **Scope** — Query Splunk/Sentinel for the same source IP across all hosts in the last 24 hours.
3. **Contain** — Isolate destination host if credential dumping or file staging is observed.
4. **Escalate** — Finance-segment policy requires Tier 2 engagement for any confirmed lateral movement attempt, even if data exfiltration is not confirmed.

**Key Takeaway:** Tier 1 does not need to decode every PCAP frame — the job is to correlate network evidence with endpoint alerts and escalate with a clear timeline.