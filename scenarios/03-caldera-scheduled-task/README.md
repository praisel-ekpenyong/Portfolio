# Scenario 03 — Scheduled Task Persistence (Caldera)

**Portfolio case #4** — [`INC-2026-003`](../../incidents/INC-2026-003-scheduled-task-persistence.md)

## Objective

Demonstrate persistence triage: plausible task name (`ChromeUpdate`) with suspicious action path, baseline comparison against SCCM, temporal correlation with prior PowerShell.

## Caldera Profile

| Setting | Value |
|---------|-------|
| Adversary | `T1-Scheduled-Task` |
| Agent | WKSTN-042 |
| MITRE | T1053.005 |

## Tier 1 Checklist

- [ ] Who created the task? Which process?
- [ ] Compare to legitimate SCCM/Chrome GPO tasks
- [ ] Check if task executed (Task Scheduler operational log)
- [ ] Scope org-wide with Splunk/Sentinel
- [ ] Document benign comparator (see INC-003 baseline table)
- [ ] Complete incident report and osTicket #48318

## Supplemental

RDP/PCAP lateral case moved to [`network/supplemental-rdp-lateral-case.md`](../../network/supplemental-rdp-lateral-case.md).