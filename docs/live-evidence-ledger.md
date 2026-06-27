# Live Evidence Ledger

Ground-truth record for portfolio incidents. Every case listed here was driven by **live activity in the lab** (real Caldera operations, real Entra authentication attempts, or real VPN auth failures forwarded from pfSense). Evidence was **exported at run time** — not reconstructed via log replay or mock modes.

> **Test-only exception:** `emulate_o365spray.py --mock` and pytest VT mocks are for CI only. They are **not** incident evidence.

---

## Evidence chain (required for each case)

```text
Live action → Source log (host/VPN/Entra) → Forwarder/connector → SIEM alert → Exported artifact → Incident write-up
```

---

## INC-2026-001 — BITS LOLBin

| Field | Value |
|-------|-------|
| **Run window (UTC)** | 2026-06-13 14:20 – 16:00 |
| **Method** | LIVE — Caldera operation `2026-06-13-INC001-BITS-LAB` · adversary `T1-Windows-Download-Exec` |
| **Target** | WKSTN-042 · agent group `blue-team-lab` |
| **Primary alerts** | Wazuh 180001 (14:22:08) · Suricata BITS/EXE download · Defender process chain (14:22:41) |
| **Exported artifacts** | `artifacts/caldera-operation-INC001.json` · `artifacts/logs/sysmon-INC001.json` · `artifacts/logs/wazuh-alert-INC001.json` · screenshots `wazuh-inc001.png`, `defender-inc001.png`, `sentinel-inc001.png`, `sysmon-inc001.png`, `osticket-48291.png` |
| **Ticket** | #48291 |

---

## INC-2026-002 — Entra password spray

| Field | Value |
|-------|-------|
| **Run window (UTC)** | 2026-06-14 11:02 – 12:15 |
| **Method** | LIVE — `scripts/emulate_o365spray.py` against `pe-soc-lab` tenant (**no `--mock`**) from lab red-team host `203.0.113.55` |
| **Target** | `jsmith@corp.lab` · 18 failed sign-ins + 1 success |
| **Primary alerts** | Sentinel `password_spray_entra` (incident #2863) · Entra ID Protection risky sign-in |
| **Exported artifacts** | `artifacts/screenshots/sentinel-inc002.png` · `osticket-48305.png` · Sentinel/Entra queries in incident Section 9 |
| **Ticket** | #48305 |

---

## INC-2026-003 — Scheduled task persistence

| Field | Value |
|-------|-------|
| **Run window (UTC)** | 2026-06-15 16:02 – 17:15 |
| **Method** | LIVE — Caldera operation `2026-06-15-SCHTASK-LAB` · adversary `T1-Scheduled-Task` |
| **Target** | WKSTN-042 |
| **Primary alerts** | Wazuh 180002 (16:04:18) · Defender persistence (16:04:52) |
| **Exported artifacts** | `artifacts/caldera-operation-INC003.json` · `artifacts/logs/sysmon-INC003-schtask.json` · `artifacts/tuning/wazuh-logtest-results.txt` (Tests 3–4) · screenshots `wazuh-inc003.png`, `defender-inc003.png`, `sysmon-inc003.png` |
| **Ticket** | #48318 |

---

## INC-2026-004 — VPN false positive

| Field | Value |
|-------|-------|
| **Run window (UTC)** | 2026-06-16 03:02 – 03:45 |
| **Method** | LIVE — external scanner traffic against pfSense OpenVPN during **CHG-8821** geo-block cutover; failures forwarded via syslog to Sentinel `VPNLogs` |
| **Target** | `vpn.corp.lab` · source `203.0.113.45` · invalid usernames · **0 successes** |
| **Primary alerts** | Sentinel `Multiple failed VPN logins` |
| **Exported artifacts** | Firewall log sample in incident Section 3 · `artifacts/screenshots/sentinel-inc004.png` · `osticket-48322.png` · tuned rule `detections/sentinel/vpn_failed_logins_tuned.kql` |
| **Ticket** | #48322 · tuning #48355 |

---

## INC-2026-005 — Phishing chain

| Field | Value |
|-------|-------|
| **Run window (UTC)** | 2026-06-17 13:55 – 16:30 |
| **Method** | LIVE — Phase A: preserved phishing email `artifacts/phishing-invoice.eml` + user report. Phase B: Caldera `2026-06-17-PHISH-LAB` · `T1-Phish-to-Host` post-click on WKSTN-042 |
| **Target** | `jsmith@corp.lab` · WKSTN-042 |
| **Primary alerts** | User report · Suricata C2/beacon · Sentinel PowerShell-from-Outlook rule |
| **Exported artifacts** | `artifacts/caldera-operation-INC005.json` · `artifacts/phishing-invoice.eml` · `artifacts/phishing_analysis.md` (from `parse_email.py`) · `phishing/email-header-analysis.md` · screenshots `sentinel-inc005.png`, `defender-inc005.png`, `osticket-48340.png` |
| **Ticket** | #48340 |

---

## INC-2026-006 — RDP lateral + sniffing

| Field | Value |
|-------|-------|
| **Run window (UTC)** | 2026-06-18 10:10 – 14:00 |
| **Method** | LIVE — Caldera operation `2026-06-18-LATERAL-RDP-LAB` · adversary `T1-Windows-Lateral` |
| **Target** | WKSTN-099 (destination) · lateral source WKSTN-042 · `CORP\jsmith` |
| **Primary alerts** | Wazuh 180003 (registry port 8443) · Suricata non-standard RDP · Wazuh 180004 (`tcpdump.exe`) |
| **Exported artifacts** | `artifacts/caldera-operation-INC006.json` · `artifacts/logs/sysmon-INC006-rdp.json` · `artifacts/logs/wazuh-alert-INC006.json` · PCAP analyzed with `tshark` · screenshots `wazuh-inc006.png`, `sysmon-inc006.png`, `osticket-48370.png` |
| **Ticket** | #48370 |

---

**Step-by-step execution:** [`attack-simulations/`](attack-simulations/) — per-case guides in [`attack-simulations/README.md`](attack-simulations/README.md)

---

## Post-run export checklist

After each live run, capture before cleanup:

- [ ] Caldera operation report → `artifacts/caldera-operation-INC###.json`
- [ ] Representative Wazuh / Sysmon / Sentinel export → `artifacts/logs/`
- [ ] Screenshot with UTC visible
- [ ] osTicket internal note with operation or script start time
- [ ] Update this ledger row

```powershell
.\build.ps1
python -m pytest tests/
```