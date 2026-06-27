# Part 6 of 8: INC-2026-003 (Scheduled Task Persistence)

**Scope:** [`incidents/INC-2026-003-scheduled-task-persistence.md`](../../incidents/INC-2026-003-scheduled-task-persistence.md), Wazuh 180002, logtest validation.

---

## Verdict: Strong persistence case with scope-check depth

Best persistence write-up in the portfolio. Domain-scope validation, multi-mechanism sweep, and logtest proof pair with INC-001’s baseline-comparison pattern.

**Overall case grade: A**

---

## What works exceptionally well

1. **Masquerade analysis** — `ChromeUpdate` name vs Temp path / ONLOGON trigger
2. **Baseline comparison** — SCCM on WKSTN-099 vs attacker task on WKSTN-042
3. **Domain-scope check** — DC Event 4698 + fleet Sysmon → local only, no GPO push
4. **Post-containment persistence sweep** — Run keys, WMI, startup folder
5. **Task XML inspection** — Hidden PowerShell arguments documented
6. **Detection + validation** — Wazuh 180002, Splunk, Sentinel KQL, logtest Tests 3/4
7. **Registry bypass recommendation** — TaskCache writes evading Sysmon EID 11

### Caldera alignment

Sysmon EID 1 at `16:04:16.842Z` → Wazuh at `16:04:18Z` (2s lag, consistent with INC-001).

---

## Issues & gaps

| Severity | Issue | Status |
|----------|-------|--------|
| Medium | “Creator” terminology ambiguous | **Fixed** — see below |
| Low | Incident KQL uses `DeviceEvents`; shipped rule uses `DeviceProcessEvents` | Align or document both |
| Low | Section 9 structure differs from other incidents | Optional renumber |
| Low | No `osticket-48318.png` | Uses `sample-tickets.md` link |
| Low | SHA256 truncated | Expand from artifacts |
| Low | `update.ps1` reused in INC-005 | Optional cross-reference |
| Low | Sentinel KQL not in Artifacts table | Add path |

---

## Fix applied during review

**Problem:** Docs mixed “creator” (`powershell.exe`), Sysmon parent (`cmd.exe`), and task action.

**Resolution (2026-06):**

- **Initiating process chain:** `cmd.exe` → `schtasks.exe`
- **Task action:** `powershell.exe -File ...\update.ps1`

Updated files:

- `incidents/INC-2026-003-scheduled-task-persistence.md`
- `tickets/sample-tickets.md` (Ticket #48318)
- `tickets/high-volume-shift-example.md`

---

## Interview talking points

1. Scheduled task triage workflow
2. Ruling out SCCM (creator, path, change ticket, DC scope)
3. Persistence sweep beyond the primary alert
4. Wazuh logtest Tests 3/4 for tuning
5. TaskCache registry evasion (Recommendation #6)

---

## Scorecard

| Criterion | Score |
|-----------|-------|
| Persistence triage | 10/10 |
| Scope / lateral check | 10/10 |
| Detection engineering | 9/10 |
| IR process | 9/10 |
| Documentation consistency | 9/10 (post-fix) |

---

[Previous: Part 5](05-inc-2026-001-bits-lolbin.md) · [Next: Part 7](07-inc-2026-004-vpn-false-positive.md) · [Index](README.md)