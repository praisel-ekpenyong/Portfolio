# Part 8 of 8: INC-2026-006 + Portfolio Wrap-Up

**Scope:** [`incidents/INC-2026-006-rdp-lateral-movement.md`](../../incidents/INC-2026-006-rdp-lateral-movement.md), scripts, detections, tests, overall scorecard.

---

## INC-2026-006 — RDP Lateral Movement & Network Sniffing

### Verdict: Strong network forensics capstone

Lateral movement, registry evasion, and command-line `tshark` PCAP analysis. Closes the `WKSTN-042` / `jsmith` thread from earlier incidents.

**Overall case grade: A**

### What works exceptionally well

1. **Baseline comparison** — IT jumpbox + admin vs user workstation + `jsmith` + port 8443
2. **Multi-layer detection** — Wazuh 180003 → Suricata (port 8443) → Wazuh 180004 (tcpdump) in 13 seconds
3. **PCAP forensics** — DNS volume, HTTP POST, TLS SNI checks with commands, output, and conclusions
4. **Dual-host containment** — WKSTN-099 + WKSTN-042 isolated; domain-wide `jsmith` disable
5. **Caldera alignment** — Ability timestamps match alerts to the second
6. **Network module** — `network/pcap-analysis-guide.md` extends incident into reusable workflow

### Issues & gaps (INC-006)

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Low | Splunk query uses port 3389; attack moved to 8443 | Add 8443 query or note sequence |
| Low | Suricata absent from `caldera-operation-INC006.json` | Add to `siem_alerts` |
| Low | `tcpdump.exe` on Windows — unusual in production | Optional lab note |
| Low | Wazuh XML excerpt differs slightly from `local_rules.xml` | Align excerpts |

### Scorecard (INC-006)

| Criterion | Score |
|-----------|-------|
| Lateral movement triage | 9/10 |
| Network forensics | 10/10 |
| Detection engineering | 9/10 |
| IR process | 9/10 |
| Portfolio integration | 10/10 |

---

## Cross-cutting: Scripts

| Script | Purpose | Tests |
|--------|---------|-------|
| `parse_email.py` | Phishing header/IOC → markdown | 7 |
| `ioc_enrichment.py` | IP/domain/URL/hash enrichment | 27 |
| `emulate_o365spray.py` | Entra spray emulator (`--mock`) | 8 |
| `caldera_log_parser.py` | Caldera JSON → timeline CSV | 10 |
| `triage_alert.ps1` | Tier 1 host context + optional isolation | — |
| `build.ps1` | IOC report + Caldera timelines | — |

**Gap:** No Pester tests for `triage_alert.ps1`.

---

## Cross-cutting: Detections

| Platform | Files | Incidents |
|----------|-------|-----------|
| Wazuh | `local_rules.xml` (180001–180004, 180020) | 001, 003, 006 |
| Splunk | 4 `.spl` | 001, 003, 005, DNS supplemental |
| Sentinel | 4 `.kql` + 2 `.yaml` | 002, 003, 004, 005 |

**Strength:** Original + tuned VPN rules with documented validation and production tuning comments in rule files.

---

## Cross-cutting: Tests

```
python -m pytest tests/
============================= 61 passed =============================
```

| Module | Tests | Focus |
|--------|-------|-------|
| `test_ioc_enrichment.py` | 27 | Classification, VT mocks, CLI |
| `test_caldera_log_parser.py` | 10 | Technique extraction, malformed JSON |
| `test_emulate_o365spray.py` | 8 | Mock spray, OAuth responses |
| `test_parse_email.py` | 7 | SPF/DKIM/DMARC, full `.eml` parse |

---

## Full portfolio scorecard

| Case / Area | Grade | Standout skill |
|-------------|-------|----------------|
| Overview & structure | A | Hiring-manager paths, honest lab framing |
| Website | A- | Visual polish; lab depth not on site |
| INC-2026-005 Phishing | A | Staged conclusions, multi-layer correlation |
| INC-2026-002 Entra spray | A- | Post-auth sweep, CA policy thinking |
| INC-2026-001 BITS | A- | LOLBin benign vs malicious comparator |
| INC-2026-003 Schtask | A | Domain scope + persistence sweep |
| INC-2026-004 VPN FP | A | Close noise + tune rules |
| INC-2026-006 RDP lateral | A | tshark PCAP forensics |
| Scripts & tests | A | 61 passing tests, `build.ps1` |

### **Portfolio overall: A / A-**

---

## What makes this portfolio hireable

1. **Consistent methodology** — Baselines, change tickets, staged conclusions, escalation judgment
2. **Breadth** — Email, identity, endpoint, persistence, FP tuning, network forensics
3. **Depth** — Artifacts, detections, scripts, tickets, screenshots — not narratives alone
4. **Integrity** — Lab disclaimers, sanitized IPs, Caldera provenance, tuning residual risk
5. **Verifier-friendly** — pytest, build.ps1, logtest results, raw JSON logs

---

## Top remaining improvements (portfolio-wide)

| Priority | Item |
|----------|------|
| 1 | Align truncated hashes/timestamps across incidents and script output |
| 2 | Add direct cert verification URLs on website |
| 3 | CI badge or GitHub Actions running `pytest` on push |
| 4 | Skip welcome screen on repeat website visits |
| 5 | Rename local folder to `Portfolio` to match public repository name |

---

## Suggested interview walk-through (15 minutes)

| Step | Topic | Time |
|------|-------|------|
| 1 | INC-2026-005 — staged conclusions + correlation | 3 min |
| 2 | INC-2026-004 vs INC-2026-002 — FP vs TP identity | 2 min |
| 3 | INC-2026-001 or INC-2026-003 — baseline comparison | 2 min |
| 4 | `parse_email.py` or `pytest` — reproducibility | 2 min |
| 5 | INC-2026-006 — tshark PCAP conclusions | 3 min |
| 6 | Shift triage doc — prioritization under volume | 3 min |

---

## Review changelog

| Date | Change |
|------|--------|
| 2026-06-26 | Initial 8-part review documents created |
| 2026-06-26 | INC-2026-003 terminology fix applied (initiating chain vs task action) |

---

[Previous: Part 7](07-inc-2026-004-vpn-false-positive.md) · [Index](README.md)