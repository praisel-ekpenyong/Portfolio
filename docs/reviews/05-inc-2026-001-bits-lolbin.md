# Part 5 of 8: INC-2026-001 (LOLBin / BITS Download)

**Scope:** [`incidents/INC-2026-001-bits-job-download.md`](../../incidents/INC-2026-001-bits-job-download.md), Wazuh 180001, Splunk T1197 detection.

---

## Verdict: Strong endpoint case with detection engineering

Demonstrates contextual LOLBin validation — not every `bitsadmin` alert is malware. Malicious-vs-benign comparison table is one of the clearest artifacts in the portfolio.

**Overall case grade: A-**

---

## What works exceptionally well

1. **Malicious vs benign comparator** — Parent, destination, change ticket, user context
2. **Multi-tool detection cascade** — Wazuh → Suricata → Defender within 33 seconds
3. **Caldera provenance** — Ability finish 14:22:06Z, Wazuh 14:22:08Z (2s lag)
4. **Shipped detections** — Wazuh 180001 + `T1197_bits_download.spl` with parent exclusions
5. **Richest screenshot set** — Six captures (Wazuh, Defender, Sentinel, osTicket, Sysmon, IOC enrichment)
6. **T2 pivot note** — `Start-BitsTransfer` PowerShell bypass awareness
7. **Eradication completeness** — BITS job cleanup, Caldera agent kill, MDE quarantine

---

## Issues & gaps

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Medium | Timeline: Section 1 assigns 14:22:15 to Suricata; Section 8 assigns it to Sysmon | Split or align timestamps |
| Low | Defender alert text `bitsadmin.exe → cmd.exe` reverses parent chain | Use `cmd.exe → bitsadmin.exe` |
| Low | Caldera JSON includes execute step; narrative light on execution | Add execution phase to timeline |
| Low | SHA256 truncated | Link full hash from `sysmon-INC001.json` |
| Low | `caldera-operation-INC001.json` omits Suricata in `siem_alerts` | Add entry |
| Low | Shift row implies phishing link; INC-001 predates INC-005 | Footnote compressed shift narrative |
| Low | Raw JSON logs not in Evidence table | Add `wazuh-alert-INC001.json`, `sysmon-INC001.json` |

---

## Cross-case positioning

- First chronological incident (2026-06-13); establishes `WKSTN-042` / `jsmith` baseline
- INC-2026-004 contrast table slots this as “TP endpoint”
- Referenced in shift triage and high-volume shift examples

---

## Interview talking points

1. LOLBin triage workflow (baseline table)
2. Why not a false positive
3. Detection rules: Wazuh 180001 or Splunk T1197
4. Attacker next steps (Caldera execute ability)
5. `Start-BitsTransfer` evasion

---

## Scorecard

| Criterion | Score |
|-----------|-------|
| LOLBin triage methodology | 10/10 |
| Multi-tool correlation | 9/10 |
| Detection engineering | 9/10 |
| IR process | 9/10 |
| Evidence depth | 9/10 |

---

## Highest-impact fix

Correct **14:22:15** timestamp labels so Suricata and Sysmon each have distinct, consistent times.

---

[Previous: Part 4](04-inc-2026-002-entra-spray.md) · [Next: Part 6](06-inc-2026-003-scheduled-task.md) · [Index](README.md)